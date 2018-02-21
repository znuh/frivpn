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

typedef struct ctx_s {
	uint8_t *rbuf;
	uint8_t *get;
	uint8_t *put;
	size_t bufsz;
	size_t fill;
	uint32_t last_fsize;
	//buf_t obuf;
} ctx_t;

/* needed for reconnect */
static void reset(node_t *n) {
	ctx_t *c = n->priv;
	c->get = c->rbuf;
	c->put = c->rbuf;
	c->fill = 0;
	c->last_fsize = 0;
}

/* TODO: init, config, release */
static int init(chains_t *chains, node_t *n) {
	ctx_t *c;
	n->priv = malloc(sizeof(ctx_t));
	c = n->priv;

	memset(c, 0, sizeof(ctx_t));
	c->bufsz = 256*1024;
	c->rbuf = malloc(c->bufsz);
	c->get = c->rbuf;
	c->put = c->rbuf;

	//n->outbuf = &c->obuf;

	return 0;
}

static inline int frame_size(const uint8_t *d) {
	return ((d[0]<<8)|(d[1]))+2;
}

static inline int sock_read(int fd, ctx_t *c) {
	int res = read(fd, c->put, c->bufsz - (c->put - c->rbuf));
	//printf("sock_read %d %d\n",fd,c->bufsz - (c->put - c->rbuf));
	if(res > 0) {
		c->fill += res;
		c->put += res;
	}
	else
		res = -1;
	return res;
}

static inline uint32_t check_residue(ctx_t *c, uint32_t fsize) {
	uint32_t fill = c->fill - fsize;
	uint8_t *get = c->get + fsize;
	if(fill < 3)
		return 0;
	fsize = frame_size(get);
	if(fill >= fsize)
		return NF_SOURCE_RESIDUE;
	return 0;
}

static int work(chains_t *chains, node_t *n) {
	ctx_t *c = n->priv;
	buf_t *obuf = n->outbuf;
	uint32_t fsize;
	int res=0;

	/* release last frame */
	if(c->last_fsize) {
		c->fill -= c->last_fsize;
		c->get += c->last_fsize;
		c->last_fsize = 0;

		/* reset buffer pointers if trivial or if not much space left */
		if(!c->fill)
			c->get = c->put = c->rbuf;
		else if((c->bufsz - (c->put - c->rbuf)) < 2048) {
			memmove(c->rbuf, c->get, c->fill);
			c->get = c->rbuf;
			c->put = c->rbuf + c->fill;
		}
	}

	/* new read necessary or still sufficient old data available? */
	if((c->fill < 3) || ((fsize = frame_size(c->get)) > c->fill)) {
		res = sock_read(n->fd, c);
		//assert(res>0);
		if(res <= 0)
			return res;
	}

	/* still insufficient data? */
	if(c->fill < (fsize = frame_size(c->get)))
		return 0;

	/* release frame upon next call */
	c->last_fsize = fsize;

	//buf_reset(obuf, 0);
	memcpy(obuf->d, c->get, fsize);
//	obuf->d = obuf->ptr = c->get;
	obuf->ofs=0;
	obuf->len = obuf->maxlen = fsize;

	/* is there another complete frame in the buffer? */
	n->flags = check_residue(c, fsize);

	return fsize;
}

const node_info_t ovpn_tcp_src = {
	.name = "ovpn_tcp_src",
	.desc = "OVPN TCP source",
	.init = init,
	.reset = reset,
	.work = work,
	.flags = NI_SOURCE | NI_OBUF,
};
