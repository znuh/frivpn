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
	bufmgmt_simple_t *bm = &bs->bm;
	uint8_t *p = malloc(n_bufs * (sizeof(buf_t) + bufsize));
	int i;

	bs->bm.bufs = p;

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
	bufmgmt_simple_t *bm = &bs->bm;
	int res;
	pthread_mutex_lock(&bs->mtx);
	res = !bm->idx;
	pthread_mutex_unlock(&bs->mtx);
	return res;
}

buf_t *bufstore_getbuf(bufstore_t *bs, size_t len, int nonblock) {
	bufmgmt_simple_t *bm = &bs->bm;
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

void buf_discard(buf_t *buf, const char *last_node) {
	bufstore_t *bs;
	bufmgmt_simple_t *bm;

	assert(buf);
	bs = buf->owner;
	assert(bs);

	if(*bs->debug > 5)
		printf("buf %p discard after %s owner %p\n", buf, last_node, bs);

	pthread_mutex_lock(&bs->mtx);

	if(buf->flags != BUF_INUSE) {
		const char *n1 = buf->last_node ? buf->last_node : "???";
		const char *n2 = last_node ? last_node : "???";
		fprintf(stderr,"buf %p: double discard: 1st %s 2nd %s\n",buf,n1,n2);
		fflush(stdout);
		assert(buf->flags == BUF_INUSE);
	}
	buf->last_node = last_node;

	bm = &bs->bm;
	buf->flags = 0;
	bm->stack[bm->idx++] = buf;

	if(bs->blocked)
		pthread_cond_signal(&bs->cond);

	pthread_mutex_unlock(&bs->mtx);
}
