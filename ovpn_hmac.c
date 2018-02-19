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
#include "ovpn.h"
#include <assert.h>
#include <stdio.h>

static inline int hmac(HMAC_CTX *ctx, const uint8_t *src, int src_len, uint8_t *dst) {
	unsigned int in_hmac_len = 0;
	HMAC_Init_ex (ctx, NULL, 0, NULL, NULL);
	HMAC_Update (ctx, src, src_len);
	return HMAC_Final (ctx, dst, &in_hmac_len);
}

static int work_hash(chains_t *chains, node_t *n) {
	struct crypto_s *crypto = n->ctx;
	buf_t *ib = n->inbuf;
	uint8_t key_id = ib->ptr[0]&7;
	const uint8_t *src = ib->ptr+1;
	int res, src_len = ib->len-1;
	struct key_s *key = request_key(crypto, key_id);

	if(!key) {
		printf("TX key %d invalid - dropping packet\n",key_id);
		ib->len = 0;
		goto done;
	}

	buf_prepend(ib, 20);
	res = hmac(key->hmac_tx, src, src_len, ib->ptr+1);

	pthread_rwlock_unlock(&key->lock);

	assert(res == 1);
	ib->ptr[0] = key_id | (DATA<<3); /* DATA_V1 */
done:
	return ib->len;
}

static int work_verify(chains_t *chains, node_t *n) {
	struct crypto_s *crypto = n->ctx;
	buf_t *ib = n->inbuf;
	uint8_t hmac_buf[20];
	int res, key_id = ib->ptr[0]&7;
	struct key_s *key;
	const uint8_t *rcvd_hash = ib->ptr+1;

	if(ib->len < 20)
		goto drop;

	buf_consume(ib, 20);

	if(crypto->flags & OVPN_IGNORE_HMAC)
		goto done;

	key = request_key(crypto, key_id);
	if(!key) {
		printf("RX key %d invalid - dropping packet\n",key_id);
		goto drop;
	}

	res = hmac(key->hmac_rx, ib->ptr+1, ib->len-1, hmac_buf);

	pthread_rwlock_unlock(&key->lock);

	assert(res == 1);
	res = compare_hmac(rcvd_hash,hmac_buf,20);
	if(res) {
		puts("HMAC mismatch - dropping buffer");
		goto drop;
	}

done:
	ib->ptr[0] = key_id;
	return ib->len;
drop:
	ib->len=0;
	return 0;
}

const node_info_t ovpn_hmac_hash = {
	.name = "ovpn_hmac_hash",
	.desc = "OVPN HMAC hash",
	.work = work_hash,
};

const node_info_t ovpn_hmac_verify = {
	.name = "ovpn_hmac_verify",
	.desc = "OVPN HMAC verify",
	.work = work_verify,
};
