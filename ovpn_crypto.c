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
#include <arpa/inet.h>
#include "chains.h"
#include "ovpn.h"
#include <inttypes.h>
#include <stdio.h>

#define IV_SIZE		16

/* note regarding out-of-order PID-check
 * use 2x 64 bit bitmaps
 * plus a pid reference for the bitmaps
 * set seen pids in the bitmap
 * increase reference & update bitmaps as necessary */

static inline void update_stats(struct crypto_stats_s *cs, uint32_t bytes) {
	cs->bytes += bytes;
	cs->packets++;
}

static int encrypt(chains_t *chains, node_t *n) {
	struct crypto_s *crypto = n->ctx;
	buf_t *ib = n->inbuf;
	buf_t *ob = n->outbuf;
	int res, key_id, c_len=0, f_len;
	uint8_t *iv_ptr, *od_ptr;
	uint32_t pid;
	struct key_s *key;

	/* output buffer */
	buf_reset(ob, 64-(IV_SIZE+1));
	buf_assertspace(ob, IV_SIZE + 1 + ib->len + 16); /* honor potential padding to AES blocksize */

	/* prepend packet-ID to input */
	buf_prepend(ib, sizeof(uint32_t));

	iv_ptr = ob->ptr+1; /* IV ptr */
	od_ptr = iv_ptr + IV_SIZE; /* output data ptr */

	prng(&crypto->prng, iv_ptr, IV_SIZE); /* generate IV */

	/* drop if key invalid, use tx_key */
	key = request_key(crypto, -1);
	if(!key) {
		puts("TX key invalid - dropping buffer");
		ob->len=0;
		goto done;
	}

	pid = ++key->tx_pid; /* packet ID */
	*((uint32_t *)ib->ptr) = htonl(pid);

	res=EVP_EncryptInit_ex(key->evp_enc, NULL, NULL, NULL, iv_ptr);
	EVP_EncryptUpdate(key->evp_enc, od_ptr, &c_len, ib->ptr, ib->len);
	EVP_EncryptFinal_ex(key->evp_enc, od_ptr+c_len, &f_len);

	pthread_rwlock_unlock(&key->lock);

	update_stats(&crypto->enc_stats, c_len + f_len);

	assert(res == 1);

	ob->len = IV_SIZE + 1 + c_len + f_len;
	assert(ob->len <= ob->maxlen);

	key_id = key - crypto->key;
	ob->ptr[0] = key_id;

done:
	return ob->len;
}

static int decrypt(chains_t *chains, node_t *n) {
	struct crypto_s *crypto = n->ctx;
	buf_t *ib = n->inbuf;
	buf_t *ob = n->outbuf;
	uint8_t key_id = ib->ptr[0]&7;
	struct key_s *key;
	uint8_t *iv = ib->ptr+1;
	int c_len=0, f_len, pid_valid;
	uint32_t pid;

	if(ib->len <= (1+IV_SIZE)) {
		ob->len=0;
		return 0;
	}

	buf_consume(ib, 1+IV_SIZE);

	buf_reset(ob, 0);
	buf_assertspace(ob, ib->len);

	/* drop if key invalid */
	key = request_key(crypto, key_id);
	if(!key) {
		puts("RX key invalid - dropping buffer");
		ob->len=0;
		return 0;
	}

	EVP_DecryptInit_ex(key->evp_dec, NULL, NULL, NULL, iv);
	EVP_DecryptUpdate(key->evp_dec, ob->ptr, &c_len, ib->ptr, ib->len);
	EVP_DecryptFinal_ex(key->evp_dec, ob->ptr + c_len, &f_len);

	update_stats(&crypto->dec_stats, c_len + f_len);

	ob->len = c_len + f_len;

	if(ob->len < 4)
		goto drop;

	/*
	hexdump(id,ib->len);
	hexdump(ob->ptr,ob->len);
	*/
	//printf("decrypt %d %d\n", ib->len,c_len+f_len);

	pid = ntohl(*((uint32_t*)ob->ptr));
	buf_consume(ob, sizeof(uint32_t));

	if(!key->rx_pid)
		key->rx_pid=1;

	pid_valid = (pid == key->rx_pid);
	//if(!pid_valid)
		//fprintf(stderr,"PID %"PRIu32" REPLAY (last: %"PRIu32")\n",pid,key->rx_pid);

	//if(pid_valid)
		key->rx_pid++;

	/* replay check */
	if(pid_valid)
		goto done;
	else
		fprintf(stderr,"PID %"PRIu32" REPLAY (last: %"PRIu32")\n",pid,key->rx_pid);

drop:
	ob->len = 0;
done:
	pthread_rwlock_unlock(&key->lock);
	return ob->len;
}

const node_info_t ovpn_encrypt = {
	.name = "ovpn_encrypt",
	.desc = "OVPN encrypt",
	.work = encrypt,
	.flags = NI_OBUF,
};

const node_info_t ovpn_decrypt = {
	.name = "ovpn_decrypt",
	.desc = "OVPN decrypt",
	.work = decrypt,
	.flags = NI_OBUF,
};
