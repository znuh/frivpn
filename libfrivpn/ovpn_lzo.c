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
#include <lzo/lzo1x.h>
#include "chains.h"
#include <assert.h>

struct ctx_s {
	int compress;
	uint8_t workmem[LZO1X_MEM_COMPRESS];
};

static void lzo_init_once(void) {
	static int init_done = 0;
	if (init_done)
		return;
	assert(lzo_init() == LZO_E_OK);
	init_done = 1;
}

static int init(chains_t *chains, node_t *n) {
	struct ctx_s *c = calloc(1,sizeof(struct ctx_s));
	n->priv = c;
	c->compress = 0;
	lzo_init_once();
	return 0;
}

#define MAGIC_COMPRESSED	0x66
#define MAGIC_UNCOMPRESSED	0xFA

#define LZO_THRESHOLD	100

static int compress(chains_t *chains, node_t *n) {
	buf_t *ib = n->inbuf;
	buf_t *ob = n->outbuf;
	struct ctx_s *c = n->priv;
	int compress = c->compress && (ib->len >= LZO_THRESHOLD);

	if(compress) {
		lzo_uint clen=0;
		buf_reset(ob, 64);
		lzo1x_1_15_compress(ib->ptr, ib->len, ob->ptr, &clen, c->workmem);
		ob->len = clen;
	}
	else
		ob = n->outbuf = ib;
	buf_prepend(ob, 1);
	*ob->ptr = compress ? MAGIC_COMPRESSED : MAGIC_UNCOMPRESSED;

	return ob->len;
}

static int decompress(chains_t *chains, node_t *n) {
	buf_t *ib = n->inbuf;
	buf_t *ob = n->outbuf;
	uint8_t cid = ib->ptr[0];

	buf_consume(ib, 1);

	if(cid == MAGIC_COMPRESSED) {
		lzo_uint uclen=0;
		int res;
		buf_reset(ob, 0);
		uclen = ob->maxlen;
		res = lzo1x_decompress_safe (ib->ptr, ib->len, ob->ptr, &uclen, NULL);
		assert(res == LZO_E_OK);
		ob->len = uclen;
	}
	else if (cid == MAGIC_UNCOMPRESSED)
		ob = n->outbuf = ib;
	else
		assert(0);

	return ob->len;
}

const node_info_t lzo_comp = {
	.init = init,
	.name = "ovpn_lzo_comp",
	.desc = "OVPN LZO compress",
	.work = compress,
	.flags = NI_OBUF,
};

const node_info_t lzo_decomp = {
	.name = "ovpn_lzo_decomp",
	.desc = "OVPN LZO decompress",
	.work = decompress,
	.flags = NI_OBUF,
};
