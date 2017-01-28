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
#include <poll.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "chains.h"
#include <assert.h>
#include <sys/uio.h>

struct iov_s {
	buf_t **bufs;
	struct iovec *iovs;
	uint32_t n_bufs;
	uint32_t full_bufs;
	uint32_t put_idx;
	uint32_t get_idx;
	int opportunistic_write;
};

#define N_BUFS	256

/* needed for reconnect */
static void reset_iovec(node_t *n) {
	struct iov_s *iov = n->priv;
	
	/* discard all queued buffers */
	for(;iov->full_bufs;iov->full_bufs--) {
		buf_t *buf = iov->bufs[iov->get_idx];
		buf_discard(buf, n->name);
		iov->get_idx++;
		iov->get_idx &= (iov->n_bufs-1);
	}
	n->flags = 0;
}

static int init_iovec(chains_t *chains, node_t *n) {
	struct iov_s *iov = calloc(1,sizeof(struct iov_s));
	n->priv = iov;
	
	iov->n_bufs = N_BUFS;
	assert(is_power_of_two(iov->n_bufs));
	
	iov->bufs = malloc(iov->n_bufs * sizeof(buf_t *));
	iov->iovs = malloc(iov->n_bufs * sizeof(struct iovec));
	
	return 0;
}

static int write_vectors(int fd, struct iov_s *iov, const char *nname) {
	struct iovec *iovec = iov->iovs + iov->get_idx;
	int max_vectors = iov->n_bufs - iov->get_idx; /* stop at end of vectors */
	int iocnt = MIN(max_vectors, iov->full_bufs);
	size_t remaining, res = writev(fd, iovec, iocnt);
	//printf("sz %zd\n",res);
	
	/* process completely written iovecs */
	for(remaining=res; iov->full_bufs && (remaining>=iovec->iov_len); 
			iovec++, iov->get_idx++, iov->full_bufs--) {
		buf_t *buf = iov->bufs[iov->get_idx];
		//printf("write_iovec discard %d %d\n",iov->get_idx,iovec->iov_len);
		buf_discard(buf, nname);
		remaining -= iovec->iov_len;
	}
	
	iov->get_idx &= (iov->n_bufs-1);
	
	/* last iovec incomplete */
	if(remaining > 0) {
		/* update iovec for next writev */
		iovec->iov_base += remaining;
		iovec->iov_len -= remaining;
	}
	/* if we hit the end of the vectors and there's still
	 * more vectors at the start, try to write them as well */
	else if((res>0) && (!iov->get_idx) && iov->n_bufs) {
		size_t res2 = write_vectors(fd, iov, nname);
		if(res2 > 0)
			res += res2;
	}
	
	return res;
}

static int work_iovec(chains_t *chains, node_t *n) {
	buf_t *b = n->inbuf;
	struct iov_s *iov = n->priv;
	
	if(b) {
		struct iovec *iovec = iov->iovs + iov->put_idx;
		
		assert(iov->full_bufs < iov->n_bufs);
		
		iovec->iov_base = b->ptr;
		iovec->iov_len = b->len;
		
		//printf("write_iovec enqueue %d\n",iov->put_idx);
		
		iov->bufs[iov->put_idx++] = b;
		iov->put_idx &= (iov->n_bufs-1);
		iov->full_bufs++;
		
		if(!iov->opportunistic_write)
			goto out;
	}
	
	write_vectors(n->fd, iov, n->name);

out:
	n->flags = iov->full_bufs ? NF_SINK_RESIDUE : 0;
	return 1; /* prevent discard */
}

static int work_poll(chains_t *chains, node_t *n) {
	buf_t *b = n->inbuf;
	int res, remain=b->len;
	uint8_t *p=b->ptr;

	while(remain) {
		struct pollfd pfd = {.fd=n->fd, .events=POLLOUT};
		poll(&pfd, 1, -1);
		
		if(pfd.revents != POLLOUT)
			return -1;
			
		//assert(pfd.revents == POLLOUT);
		res = write(n->fd, p, remain);
		if(res <= 0)
			return -1;
		remain-=res;
		p+=res;
	}

	return 0;
}

static int work_single(chains_t *chains, node_t *n) {
	buf_t *b = n->inbuf;
	int res = write(n->fd, b->ptr, b->len);
	assert(res == b->len);
	return 0;
}

const node_info_t writev_sink = {
	.name = "writev_sink",
	.desc = "write file/sock sink (iovec)",
	.init = init_iovec,
	.reset = reset_iovec,
	.work = work_iovec,
	.flags = NI_SINK | NI_USE_POLLOUT,
};

const node_info_t write_sink = {
	.name = "write_sink",
	.desc = "write file/sock sink",
	.work = work_poll,
	.flags = NI_SINK,
};

const node_info_t write_single = {
	.name = "write_single",
	.desc = "write sink w/o remainder",
	.work = work_single,
	.flags = NI_SINK,
};
