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
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "ovpn.h"
#include "chains.h"
#include <assert.h>

/* use key_id = -1 for txkey
 * checks if key is valid and locks key for reading
 * caller must unlock rwlock after crypto */
struct key_s *request_key(struct crypto_s *crypto, int key_id) {
	struct key_s *key = NULL;
	pthread_rwlock_rdlock(&crypto->lock);
	key_id = (key_id < 0) ? crypto->tx_key : key_id;
	if(KEY_VALID(crypto, key_id)) {
		key = crypto->key + key_id;
		pthread_rwlock_rdlock(&key->lock);
	}
	pthread_rwlock_unlock(&crypto->lock);
	return key;
}

int ovpn_ctl_getsock(ovpn_t *ovpn) {
	return ovpn->ctl.ctl_sock[1];
}

void ovpn_ctl_config(ovpn_t *ovpn, const uint8_t *hmac_txkey, const uint8_t *hmac_rxkey) {
	struct ctl_s *ctl = &ovpn->ctl;
	int res = HMAC_Init_ex(ctl->hmac_tx, hmac_txkey, 20, EVP_sha1(), NULL);
	assert(res == 1);
	res = HMAC_Init_ex(ctl->hmac_rx, hmac_rxkey, 20, EVP_sha1(), NULL);
	assert(res == 1);
}

void lua_notify(struct ctl_s *ctl, const char *msg) {
	int res = write(ctl->ctl_sock[0], msg, strlen(msg));
	//printf("2LUA: %s\n",msg);
	assert(res > 0);
}

static const uint8_t ping_msg[] = {
	0x2a, 0x18, 0x7b, 0xf3, 0x64, 0x1e, 0xb4, 0xcb,
	0x07, 0xed, 0x2d, 0x0a, 0x98, 0x1f, 0xc7, 0x48
};

int ovpn_sendping(chains_t *chains, ctimer_t *ct, void *priv) {
	struct ctl_s *ctl = priv;
	node_t *lzo = ctl->lzo_comp;
	chain_t *chain = lzo->chain;
	buf_t *b = bufstore_getbuf(chain->bs, chain->bufsize, 0);
	assert(b);
	buf_reset(b, 64);
	buf_assertspace(b, sizeof(ping_msg));
	memcpy(b->ptr, ping_msg, sizeof(ping_msg));
	b->len = sizeof(ping_msg);
	run_chain(chains, lzo, b, 1);
	return CTIMER_ENABLED;
}

void ovpn_rx(chains_t *chains, struct ctl_s *ctl) {
	ctl->last_rx = chains_gettime(chains, 0);
}

inline uint32_t compare_hmac(const uint8_t *a, const uint8_t *b, size_t len) {
	const uint32_t *s1 = (const uint32_t *)a;
	const uint32_t *s2 = (const uint32_t *)b;
	uint32_t diff=0;
	assert(!(len&3));
	len>>=2;
	for(;len;len--,s1++,s2++)
		diff |= (*s1) ^ (*s2);
	return diff;
}

struct ovpn_hdr_s {
	uint8_t opcode;
	uint64_t session_id;
	uint8_t hmac[20];
	uint32_t packet_id;
	uint32_t timestamp;
	uint8_t ack_len;

	/* followed by:
	 *
	 * if ack_len > 0:
	 * 	ack_len * uint32_t msg_pkt_ids
	 *  remote session id
	 *
	 * if op != ACK:
	 *  uint32_t packet_id
	 *  data payload
	 */
} __attribute__((packed));

static int ctl_hmac(HMAC_CTX *hmac, struct ovpn_hdr_s *hdr, uint32_t len, int verify) {
	unsigned int in_hmac_len = 0;
	int res;
	HMAC_Init_ex (hmac, NULL, 0, NULL, NULL);
	/* HMAC: pkt.pkt_id .. pkt.tstamp .. pkt.op .. pkt.sid .. pkt.ack_len .. pkt.msg_pktid */
	HMAC_Update (hmac, (uint8_t*)&hdr->packet_id, 4+4);
	HMAC_Update (hmac, &hdr->opcode, 1+8);
	HMAC_Update (hmac, &hdr->ack_len, len-(sizeof(struct ovpn_hdr_s)-1));
	if(!verify) {
		res = HMAC_Final (hmac, hdr->hmac, &in_hmac_len);
		assert(res);
	}
	else {
		uint8_t buf[20];
		res = HMAC_Final (hmac, buf, &in_hmac_len);
		assert(res);
		return compare_hmac(buf, hdr->hmac, 20);
	}
	return 1;
}

static int ctl_putheader(struct ctl_s *ctl, buf_t *ob, uint8_t op) {
	struct ctl_state_s *txc = &ctl->tx_state;
	struct ctl_state_s *rxc = &ctl->rx_state;
	struct ovpn_hdr_s *hdr;
	int n_acks;
	int res=0;

	pthread_mutex_lock(&ctl->state_mtx);

	n_acks = rxc->n_acks;

	if(op != ACK) {
		uint32_t *msgid = buf_prepend(ob, 4);
		*msgid = htonl(txc->msg_pkt_id++);
	}
	else if(!n_acks)
		goto done;

	if(n_acks) {
		/* put remote session ID */
		uint64_t *remote_sid = buf_prepend(ob, 8);
		*remote_sid = rxc->session_id;

		/* put ACK-ids */
		memcpy(buf_prepend(ob, 4*n_acks), rxc->ack_ids, n_acks*4);

		rxc->n_acks = 0;
		if(ctl->debug > 5)
			printf("send %d ACKs %"PRIu32"\n",n_acks,ntohl(rxc->ack_ids[0]));
	}

	hdr = buf_prepend(ob, sizeof(struct ovpn_hdr_s));
	hdr->opcode 	= (op<<3) | ctl->key_id;
	hdr->session_id = txc->session_id;
	hdr->timestamp 	= htonl(time(NULL));

	if(hdr->timestamp != txc->last_time)
		txc->packet_id = 0;

	txc->last_time = hdr->timestamp;

	hdr->packet_id 	= htonl(++txc->packet_id);

	hdr->ack_len 	= n_acks;

	ctl_hmac(ctl->hmac_tx, hdr, ob->len, 0);

	res = ob->len;

done:
	pthread_mutex_unlock(&ctl->state_mtx);
	return res;
}

static int ovpn_ctl_send(chains_t *chains, struct ctl_s *ctl, uint8_t op) {
	int res;
	node_t *encap = ctl->encap;
	chain_t *chain = encap->chain;
	buf_t *b = bufstore_getbuf(chain->bs, chain->bufsize, 0);
	assert(b);
	buf_reset(b, 64);
	ctl_putheader(ctl, b, op);
	if(chains->debug)
		printf("ctl_send %p %zd\n",b,b->len);
	/* TODO: proper locking needed to avoid collisions w/ other threads */
	res = run_chain(chains, encap, b, 1);
	return res;
}

int ovpn_ctl_start(chains_t *chains, struct ctl_s *ctl) {
	node_t *encap = ctl->encap;
	stats_outdated(chains, encap->thread_id);
	return ovpn_ctl_send(chains, ctl, CLIENT_RESET_V2);
}

/* invoked from ovpn_decap via ovpn_process_ctl
 * write packet to non-default destination ovpn_encap
 *
 * ctl_send for writing to ovpn_encap
 * w/o using normal output buffer
 * needed for connection start and for sending
 * ACKs while doing a tls_write at the same time */
static int send_acks(chains_t *chains, struct ctl_s *ctl) {
	return ovpn_ctl_send(chains, ctl, ACK);
}

static void enqueue_ack(struct ctl_s *ctl, int msg_pkt_id) {
	struct ctl_state_s *rxc = &ctl->rx_state;
	pthread_mutex_lock(&ctl->state_mtx);
	assert(rxc->n_acks < MAX_PENDING_ACKS);
	rxc->ack_ids[rxc->n_acks++] = msg_pkt_id;
	pthread_mutex_unlock(&ctl->state_mtx);
}

static void ctl_reset(chains_t *chains, struct ctl_s *ctl, int opcode, int key_id) {
	struct ctl_state_s *rxc = &ctl->rx_state;
	struct ctl_state_s *txc = &ctl->tx_state;
	struct crypto_s *crypto = &ctl->crypto;
	struct key_s *key = NULL;
	int last_key, reply;

	//puts("RESET");

	/* reset ctl ctx for new key */
	pthread_mutex_lock(&ctl->state_mtx);
	last_key = ctl->key_id;
	ctl->key_id = key_id;
	rxc->msg_pkt_id = 1; /* next ID */
	pthread_mutex_unlock(&ctl->state_mtx);

	/* invalidate all keys except for the last one
	 * key 0 is only used once during initial handshake */
	pthread_rwlock_wrlock(&crypto->lock);
	if((key_id) || (last_key))
		crypto->valid_keys = (1<<last_key);
	pthread_rwlock_unlock(&crypto->lock);

	//fprintf(stderr,"rst key_id %d valid %x\n",key_id,crypto->valid_keys);

	/* reset data packet id for new key */
	key = crypto->key + key_id;
	pthread_rwlock_wrlock(&key->lock);
	key->rx_pid = 0;
	key->tx_pid = 0;
	pthread_rwlock_unlock(&key->lock);

	if(opcode == SOFT_RESET) {
		reply = SOFT_RESET;
		txc->msg_pkt_id = 0;
	}
	else
		reply = ACK;

	ovpn_ctl_send(chains, ctl, reply);
	//puts("TLS_START");
	lua_notify(ctl, "TLS_START");
}

/* invoked from ovpn_decap */
int ovpn_process_ctl(chains_t *chains, struct ctl_s *ctl, buf_t *ib) {
	struct ctl_state_s *rxc = &ctl->rx_state;
	struct ovpn_hdr_s *hdr = (struct ovpn_hdr_s *)ib->ptr;
	uint32_t orig_len = ib->len;
	uint64_t *our_sid=NULL;
	uint32_t *msg_pkt_id_p=NULL, msg_pkt_id=0;
	int res, opcode, key_id;

	assert(ib->len >= sizeof(struct ovpn_hdr_s));
	opcode = hdr->opcode>>3;
	key_id = hdr->opcode&7;

	buf_consume(ib, sizeof(struct ovpn_hdr_s));

	/* check HMAC */
	res = ctl_hmac(ctl->hmac_rx, hdr, orig_len, 1);
	if(res)
		goto drop;

	pthread_mutex_lock(&ctl->state_mtx);

	/* keep remote session ID if not yet stored */
	if(!rxc->session_id)
		rxc->session_id = hdr->session_id;

	pthread_mutex_unlock(&ctl->state_mtx);

	// TODO: handle ACK-list
	buf_consume(ib, hdr->ack_len*4);

	if(hdr->ack_len) {
		/* find our own session-id at end of ACK-list */
		our_sid = (uint64_t*)ib->ptr;
		(void)our_sid; // suppress not-used warning
		buf_consume(ib, 8);
	}

	if(opcode == ACK) {
		goto drop; // nothing to do
	}

	/* non-ACK packets have a message-ID */
	msg_pkt_id_p = (uint32_t*)ib->ptr;
	msg_pkt_id = ntohl(*msg_pkt_id_p);
	buf_consume(ib, 4);

	/* this needs NETWORK ORDER msg_pkt_ids */
	enqueue_ack(ctl, *msg_pkt_id_p);

	/* remaining buffer content is data payload */

	if(ctl->debug > 1)
		printf("ctl %d %d payload len %zu msg_id %"PRIu32"\n",opcode,key_id,ib->len,msg_pkt_id);

	/* TODO: verify locking */
	switch(opcode) {
		case SERVER_RESET_V2:
		case SOFT_RESET:
			assert(!msg_pkt_id);
			ctl_reset(chains, ctl, opcode, key_id);
			break;

		case CONTROL:
			send_acks(chains, ctl);

			/* preliminary sanity check for duplicate messages */
			if(msg_pkt_id != rxc->msg_pkt_id) {
				fprintf(stderr,"msg_pkt_id != rxc->msg_pkt_id: %d != %d\n",msg_pkt_id,rxc->msg_pkt_id);
			}

			/* our ACK might have arrived too late
			 * so we simply drop duplicate message IDs
			 * this works for TCP only */
			if(msg_pkt_id < rxc->msg_pkt_id)
				goto drop;

			//assert(msg_pkt_id == rxc->msg_pkt_id);

			if(key_id != ctl->key_id) {
				fprintf(stderr,"key_id != ctl->key_id: %d != %d\n",key_id, ctl->key_id);
			}
			assert(key_id == ctl->key_id);

			pthread_mutex_lock(&ctl->state_mtx);
			rxc->msg_pkt_id++;
			pthread_mutex_unlock(&ctl->state_mtx);
			/* send buf to TLS sock, drop buf afterwards */
			run_chain(chains, ctl->tls_write, ib, 0);
			break;

		default:
			fprintf(stderr,"unknown opcode: %d\n",opcode);
			assert(0);
	}

drop:
	ib->len=0;
	return 0;
}

/*
 * - invalid keys must not be used
 * - keys must not be invalidated while in use
 * 	-> invalidation only if key not in use
 *
 * crypto/hmac:
 * - lock general crypto
 * - find key
 * - lock key
 * - unlock general crypto
 * - do stuff
 * - unlock key
 */
void ovpn_ctl_setkeys(ovpn_t *ovpn, const uint8_t *keys) {
	struct ctl_s *ctl = &ovpn->ctl;
	struct crypto_s *crypto = &ctl->crypto;
	struct key_s *key;
	int res, key_id;

	pthread_mutex_lock(&ctl->state_mtx);
	key_id = ctl->key_id;
	pthread_mutex_unlock(&ctl->state_mtx);
	key = crypto->key + key_id;

	/* invalidate key if not yet done */
	pthread_rwlock_wrlock(&crypto->lock);
	crypto->valid_keys &= ~(1<<key_id);
	pthread_rwlock_unlock(&crypto->lock);

	/* update key */
	pthread_rwlock_wrlock(&key->lock);

	res = EVP_EncryptInit_ex(key->evp_enc, EVP_aes_256_cbc(), NULL, keys, NULL);
	assert(res == 1);
	res = HMAC_Init_ex(key->hmac_tx, keys+64, 20, EVP_sha1(), NULL);
	assert(res == 1);

	res = EVP_DecryptInit_ex(key->evp_dec, EVP_aes_256_cbc(), NULL, keys+128, NULL);
	assert(res == 1);
	res = HMAC_Init_ex(key->hmac_rx, keys+192, 20, EVP_sha1(), NULL);
	assert(res == 1);

	pthread_rwlock_unlock(&key->lock);

	/* mark key as valid now, set new key as txkey */
	pthread_rwlock_wrlock(&crypto->lock);
	crypto->valid_keys |= (1<<key_id);
	crypto->tx_key = key_id;
	pthread_rwlock_unlock(&crypto->lock);

	//fprintf(stderr,"setkey %d\n",key_id);

	if(!key_id)
		ctimer_start(ovpn->chains, ovpn->ctl.ping_timer);
}

static int work(chains_t *chains, node_t *n) {
	buf_t *ib = n->inbuf;
	struct ctl_s *ctl = n->ctx;
	n->outbuf = ib;
	/* prepend ctl header, send via default dst (ovpn_encap) */
	return ctl_putheader(ctl, ib, CONTROL);
}

const node_info_t tls_encap = {
	.name = "tls_encap",
	.desc = "OVPN TLS encapsulate",
	.work = work,
};
