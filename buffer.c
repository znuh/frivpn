/*
 *
 * Copyright (C) 2017 Benedikt Heinz <Zn000h AT gmail.com>
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This code is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this code.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "chains.h"
#include <assert.h>

#include <inttypes.h>
#include <stdio.h>

static inline void *buf_update(buf_t *b) {
	b->maxlen = b->bufsize - b->ofs;
	b->ptr = b->d + b->ofs;
	return b->ptr;
}

void *buf_reset(buf_t *b, size_t ofs) {
	//printf("buf_reset %zd %zd\n",ofs,b->bufsize);
	assert(ofs >= 0);
	assert(ofs < b->bufsize);
	b->ofs = ofs;
	b->len = 0;
	return buf_update(b);
}

void *buf_prepend(buf_t *b, size_t sz) {
	//printf("prepend %zd %zd\n",b->len,sz);
	assert(sz <= b->ofs);
	b->ofs -= sz;
	b->len += sz;
	return buf_update(b);
}

void *buf_consume(buf_t *b, size_t sz) {
	//printf("buf_consume %zd\n",sz);
	assert(sz <= b->len);
	b->ofs += sz;
	b->len -= sz;
	return buf_update(b);
}

bufstore_t *bufstore_create(size_t bufsize, uint32_t n_bufs) {
	bufstore_t *bs = calloc(1,sizeof(bufstore_t));
	bufmgmt_simple_t *bm = &bs->bm.simple;
	uint8_t *p = malloc(n_bufs * (sizeof(buf_t) + bufsize));
	int i;

	bs->type = BS_SIMPLE;
	bs->bm.simple.bufs = p;

	pthread_mutex_init(&bs->mtx, NULL);
	pthread_cond_init(&bs->cond, NULL);

	bm->stack = malloc(n_bufs * sizeof(buf_t*));

	for(i=0;i<n_bufs;i++, p+=sizeof(buf_t)+bufsize) {
		buf_t *buf = (buf_t *) p;
		memset(buf, 0, sizeof(buf_t));
		buf->d = p + sizeof(buf_t);
		buf->bufsize = bufsize;
		buf->owner = bs;
		bm->stack[bm->idx++] = buf;
	}

	return bs;
}

int bufstore_exhausted(bufstore_t *bs) {
	bufmgmt_simple_t *bm;
	int res;
	assert(bs->type == BS_SIMPLE);
	bm = &bs->bm.simple;
	pthread_mutex_lock(&bs->mtx);
	res = !bm->idx;
	pthread_mutex_unlock(&bs->mtx);
	return res;
}

buf_t *bufstore_getbuf(bufstore_t *bs, size_t len, int nonblock) {
	bufmgmt_simple_t *bm = &bs->bm.simple;
	buf_t *buf = NULL;

	pthread_mutex_lock(&bs->mtx);

	if((!bm->idx) && nonblock) {
		pthread_mutex_unlock(&bs->mtx);
		return NULL;
	}

	bs->blocked++;
	while(!bm->idx)
		pthread_cond_wait(&bs->cond, &bs->mtx);
	bs->blocked--;

	buf = bm->stack[--bm->idx];
	buf->flags = BUF_INUSE;

	pthread_mutex_unlock(&bs->mtx);

	buf->last_node = NULL;
	buf_reset(buf, 0);
	buf_assertspace(buf, len);

	return buf;
}

void streamstore_reset(bufstore_t *bs) {
	bufmgmt_stream_t *stream = &(bs->bm.stream);
	assert(bs->type == BS_STREAM);
	stream->put = stream->get;
	stream->fill = 0;
}

/*
static inline void bs_sanitycheck(bufmgmt_stream_t *stream) {
	return;
	size_t sum=0;
	int i;
	for(i=0;i<=stream->n_bufs;i++) {
		buf_t *buf = stream->bufs + i;
		sum+= buf->bufsize;
	}
	if(sum != stream->bufsz) {
		printf("lost buffer space: %ld %ld\n",stream->bufsz,sum);
		assert(sum == stream->bufsz);
	}
}
*/

bufstore_t *streamstore_create(size_t bufsize, uint32_t n_bufs) {
	bufstore_t *bs = calloc(1,sizeof(bufstore_t));
	bufmgmt_stream_t *stream = &(bs->bm.stream);
	buf_t *buf;
	int i;

	assert(is_power_of_two(bufsize));
	assert(is_power_of_two(n_bufs));

	bs->type = BS_STREAM;

	pthread_mutex_init(&bs->mtx, NULL);
	pthread_cond_init(&bs->cond, NULL);

	stream->bufsz = bufsize;
	stream->rbuf = malloc(stream->bufsz);

	stream->n_bufs = n_bufs;
	stream->bufs = calloc(stream->n_bufs+2, sizeof(buf_t));

	/* init first buffer
	 * first buf always points to start of rbuf */
	stream->bufs->flags = BUF_SETUP;
	stream->bufs->d = stream->rbuf;
	stream->bufs->bufsize = stream->bufsz;

	for(i=0;i<stream->n_bufs+2;i++) {
		buf = stream->bufs + i;
		buf->bi.si.free_start = buf->bi.si.free_end = buf;
		buf->owner = bs;
	}
	buf = stream->bufs + n_bufs;
	buf++;
	buf->flags = BUF_INUSE; /* guard buffer */

	stream->put = stream->get = stream->bufs->d;

	return bs;
}

#define buf_idle(buf) (!((buf)->flags))
#define buf_inuse(buf) ((buf)->flags & BUF_INUSE)

/* streamstore discard
 *
 * this can be invoked by any thread
 * therefore we need a mutex for everything we read/write here
 *
 * mutex MUST BE HELD */
void streamstore_discard(bufmgmt_stream_t *stream, buf_t *buf) {
	buf_t *free_start=buf, *free_end=buf;
	int buf_id = buf - stream->bufs;

	assert(buf_id <= stream->n_bufs);

	/* merge right block to this buf if possible
	 * don't do this if right block is in use or being setup
	 *
	 * note: there's one extra buf (n_bufs+1) for keeping unused space
	 * therefore no buf_id-checking here (assert is done above) */
	if(buf_idle(buf+1)) {
		buf_t *right = buf+1;
		free_end = right->bi.si.free_end;
		buf->bufsize += right->bufsize;
		right->bufsize = 0;
	}
	assert(free_end);

	/* merge this block left if possible
	 *
	 * merging current buf to left block while left
	 * block ist being setup does no harm
	 * b/c we simply enlarge the buffer being setup
	 */
	if((buf_id) && (!buf_inuse(buf-1))) {
		buf_t *left = buf-1;
		free_start = left->bi.si.free_start;
		free_start->bufsize += buf->bufsize;
		buf->bufsize = 0;
	}
	assert(free_start);

	/* update limits of block */
	free_start->bi.si.free_end = free_end;
	free_end->bi.si.free_start = free_start;

	buf->flags = 0;
}

/* mutex MUST BE HELD */
static buf_t *rollover(bufmgmt_stream_t *stream, buf_t *buf) {

	//printf("rollover fill %d\n",stream->fill);

	assert(buf_idle(stream->bufs));
	if(stream->fill) {
		assert(stream->fill <= stream->bufs->bufsize);
		memmove(stream->bufs->d, stream->get, stream->fill);
	}
	stream->get_idx = 0;
	stream->get = stream->bufs->d;
	stream->put = stream->bufs->d + stream->fill;
	streamstore_discard(stream, buf);	/* release old buffer */
	stream->bufs->flags = BUF_SETUP;
	return stream->bufs;
}

/* streamstore request
 *
 * buffer has already been reserved in getspace
 * data pointer has been set
 * we now just have to set the buffer length
 *
 * TODO: best rollover strategy?
 * */
buf_t *streamstore_getbuf(bufstore_t *bs, size_t len) {
	bufmgmt_stream_t *stream = &(bs->bm.stream);
	buf_t *buf = stream->bufs + stream->get_idx;
	buf_t *next_buf = buf+1;

	if(!len)
		return NULL;

	if(*bs->debug > 5)
		printf("buf %p (%d) (stream) get / sz %zd\n",buf,stream->get_idx, len);

	assert(len <= stream->fill);

	assert(buf->flags == BUF_SETUP);

	/* we set the bufsize to the actual needed length
	 * and move the leftover space to the next buf
	 *
	 * there is one extra buf (n_bufs+1) which will
	 * never be assigned just to hold unused memory
	 * from the last 'normal' buf.
	 * otherwise we would lose leftover memory of the
	 * last 'normal' buf
	 *
	 * if next buf is a 'normal' buf it might be in use
	 * in this case we need to wait
	 * */

	pthread_mutex_lock(&bs->mtx);

	/* update get ptr & fill info for stream */
	stream->get += len;
	stream->fill -= len;

	/* wait for buf if not ready */
	bs->blocked = 1;
	while(next_buf->flags)
		pthread_cond_wait(&bs->cond, &bs->mtx);
	bs->blocked = 0;

	stream->get_idx++; /* next buffer */
	stream->get_idx &= (stream->n_bufs-1);

	/* move unused space to next buf
	 *
	 * this might be the 'special' n_bufs+1 spare buffer
	 * if we hit the spare buffer, we'll fix this with rollover() */
	next_buf->d = stream->get;
	next_buf->bufsize += buf->bufsize - len;

	if(!stream->get_idx) {	/* get_idx did a rollover -> fix things */
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec +=5;
		/* wait for buf if not ready */
		bs->blocked = 1;
		while( (stream->bufs->flags) || (stream->fill > stream->bufs->bufsize) ) {
			int res = pthread_cond_timedwait(&bs->cond, &bs->mtx, &ts);
			assert(!res);
		}
		bs->blocked = 0;
		next_buf = rollover(stream, next_buf);
	}

	next_buf->flags = BUF_SETUP;

	buf->flags = BUF_INUSE;
	buf->bufsize = len;

	pthread_mutex_unlock(&bs->mtx);

	buf_reset(buf, 0);	/* will update maxlen as well */
	buf->len = len;

	return buf;
}

/* mutex MUST BE HELD */
static buf_t *consider_rollover(bufmgmt_stream_t *stream) {
	buf_t *buf = stream->bufs + stream->get_idx;
	buf_t *buf1 = stream->bufs;
	size_t put_pos = stream->put - stream->rbuf;
	size_t remaining = buf->bufsize - stream->fill;

	/* we cannot rollover if 1st buf in use or not sufficient free space */
	if(!buf_idle(buf1)) {
		//puts("n_rollover: !idle(0)");
		return buf;
	}
	if(stream->fill > buf1->bufsize) {
		//puts("n_rollover: fill>size");
		return buf;
	}

	if((remaining < 2048) && (buf1->bufsize > remaining))
		goto rollover;
	else
		return buf;

#if 0
	/* never do a rollover if <= 1/2 of rbuf used */
	if((remaining >= 128) && (put_pos <= (stream->bufsz/2))) {
		//puts("n_rollover: <1/2");
		return buf;
	}
#endif
	/*
	 * relevant factors for rollover decision:
	 * - free space as start
	 * - free space at current get
	 * - fill == 0 ?
	 *
	 * if there's no free buffer left we would have to enforce
	 * the rollover as well
	 * BUT: acquiring buffers is done with getbuf()
	 * we handle this rollover case there
	 */

	/* we try to avoid rollovers while there's still
	 * data stored in the rbuf because we need to memmove
	 * this data on a rollover
	 * once we run out of space we have to face the inevitable */
	//printf("rollover?: buf %d putpos %d fill %d bs %d\n",bs->get_idx, put_pos,stream->fill,buf->bufsize);
	if( (put_pos < ((stream->bufsz*3)/4)) && (stream->fill) ) {
		return buf;
	}
rollover:
	/* do rollover */
	rollover(stream, buf);
	buf1->flags = BUF_SETUP;
	return buf1;
}

/*
void dump_bufs(bufmgmt_stream_t *stream) {
	int i=0,n=stream->n_bufs+1;
	//n=100;
	for(i=0;i<n;i++) {
		buf_t *buf = stream->bufs+i;
		uint32_t x = buf->d-stream->rbuf;
		printf("%4d: %"PRIu32" %zd %"PRIu32"\n",i,x,buf->bufsize,buf->flags);
	}
	fflush(stdout);
}
*/

void *streamstore_getspace(bufstore_t *bs, size_t *sz) {
	bufmgmt_stream_t *stream = &(bs->bm.stream);
	buf_t *buf;

	assert(sz);

	pthread_mutex_lock(&bs->mtx);

	/* gather free space from current block */

	bs->blocked = 1;

	do {

		buf = consider_rollover(stream);

		stream->free = buf->bufsize - stream->fill;

		if(!stream->free) {
			//puts("blocked");
			//dump_bufs(stream);
			pthread_cond_wait(&bs->cond, &bs->mtx);
			//puts("unblocked");
		}

	} while(!stream->free);

	bs->blocked = 0;

	pthread_mutex_unlock(&bs->mtx);

//	printf("bufsize %d fill %d\n",buf->bufsize, stream->fill);

	if(*bs->debug > 5) {
		uint32_t buf_id = buf - stream->bufs;
		printf("buf %p (%"PRIu32") getspace free %zd\n",buf,buf_id, stream->free);
	}

	*sz = stream->free;

	return stream->put;
}

inline int streamstore_put(bufstore_t *bs, size_t len) {
	bufmgmt_stream_t *stream = &(bs->bm.stream);
	if(*bs->debug > 5)
		printf("buf put stream %zd\n",len);
	assert(len <= stream->free);	/* check is too late here, but still better than no check */
	stream->fill += len;
	stream->put += len;
	stream->free -= len;
	return len;
}

void buf_discard(buf_t *buf, const char *last_node) {
	bufstore_t *bs;

	assert(buf);
	bs = buf->owner;
	assert(bs);

	if(*bs->debug > 5)
		printf("buf %p (type %d) discard after %s owner %p\n", buf, bs->type, last_node, bs);

	pthread_mutex_lock(&bs->mtx);

	if(buf->flags != BUF_INUSE) {
		const char *n1 = buf->last_node ? buf->last_node : "???";
		const char *n2 = last_node ? last_node : "???";
		fprintf(stderr,"buf %p: double discard: 1st %s 2nd %s\n",buf,n1,n2);
		fflush(stdout);
		assert(buf->flags == BUF_INUSE);
	}
	buf->last_node = last_node;

	if(bs->type == BS_STREAM)
		streamstore_discard(&(bs->bm.stream), buf);
	else {
		bufmgmt_simple_t *bm = &bs->bm.simple;
		buf->flags = 0;
		bm->stack[bm->idx++] = buf;
	}

	if(bs->blocked)
		pthread_cond_signal(&bs->cond);

	pthread_mutex_unlock(&bs->mtx);
}
