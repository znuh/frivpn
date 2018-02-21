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
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <openssl/rand.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>

#include "ovpn.h"
#include "chains.h"
#include "nodes.h"

#define THREADS
#ifndef THREADS
#define SOCK_RX_THREAD		0
#define SOCK_TX_THREAD		0
#define DECRYPT_THREAD		0
#define ENCRYPT_THREAD		0
#define TUNTX_THREAD		0
#define N_THREADS	(TUNTX_THREAD+1)
#else
#define SOCK_RX_THREAD		0
#define DECRYPT_THREAD		1
#define ENCRYPT_THREAD		2
#define SOCK_TX_THREAD		2
#define TUNTX_THREAD		3
#define N_THREADS	(TUNTX_THREAD+1)
#endif

static const chain_template_t from_sock[] = {
	{ "tun_write", 		&write_single,		TUNTX_THREAD 	},	/* 117 us */

	{ "ovpn_filter",	&ovpn_filter,		DECRYPT_THREAD	},
	{ "lzo_decomp", 	&lzo_decomp,		DECRYPT_THREAD	},	/* 13 us */
	{ "decrypt", 		&ovpn_decrypt,		DECRYPT_THREAD	},	/* 104 us */

	{ "hmac_verify", 	&ovpn_hmac_verify,	SOCK_RX_THREAD	},	/* 56 us */
	{ "ovpn_decap", 	&ovpn_decap,		SOCK_RX_THREAD	},
	{ "sock_read",		&ovpn_tcp_src,		SOCK_RX_THREAD	},	/* 72 us */
	{ NULL, 			NULL,				-1	},
};

static const chain_template_t from_tun[] = {
	{ "sock_write",		&write_sink,		SOCK_TX_THREAD	},
	{ "ovpn_encap",		&ovpn_encap,		SOCK_TX_THREAD	},

	{ "hmac_hash",		&ovpn_hmac_hash,	ENCRYPT_THREAD	},	/* 37 us */
	{ "encrypt",		&ovpn_encrypt,		ENCRYPT_THREAD	},	/* 39 us */
	{ "lzo_comp",		&lzo_comp,			ENCRYPT_THREAD	},
	{ "tun_read",		&read_src,			ENCRYPT_THREAD	},	/* 43 us */
	{ NULL,				NULL,				-1	},
};

static const chain_template_t from_tls[] = {
	{ "ovpn_encap",		&ovpn_encap,		SOCK_TX_THREAD	},
	{ "tls_encap",		&tls_encap,			SOCK_TX_THREAD	},
	{ "tls_read",		&read_src,			SOCK_TX_THREAD	},
	{ NULL,				NULL,				-1	},
};

static const chain_template_t to_tls[] = {
	{ "tls_write",		&write_sink,		SOCK_RX_THREAD	},
	{ NULL,				NULL,				-1	},
};

/* reset needs to be sent to server upon connection start
 * -> possibility to send buf to any node from outside of chain needed */
static chains_t *mkchains(void) {
	chains_t *chains = chains_create(N_THREADS);
	chain_create(chains, from_sock, 2048, 128+8);
	chain_create(chains, from_tun, 2048, 128+8);
	chain_create(chains, from_tls, 1564, 16);	/* limit due to MTU */
	chain_create(chains, to_tls, 2048, 16);
	// ovpn_decap needs tls_write and ovpn_encap
	return chains;
}

int ovpn_sendping(chains_t *chains, ctimer_t *ct, void *priv);

static void ctl_init(ovpn_t *ovpn) {
	struct ctl_s *ctl = &ovpn->ctl;
	struct crypto_s *crypto = &ctl->crypto;
	int i, res;

	pthread_mutex_init(&ctl->state_mtx, NULL);

	ctl->hmac_tx = HMAC_CTX_new();
	ctl->hmac_rx = HMAC_CTX_new();

	/* initialize key contexts */

	pthread_rwlock_init(&crypto->lock, NULL);

	for(i=0;i<8;i++) {
		struct key_s *key = crypto->key+i;

		pthread_rwlock_init(&key->lock, NULL);

		key->hmac_rx = HMAC_CTX_new();
		key->hmac_tx = HMAC_CTX_new();
		key->evp_dec = EVP_CIPHER_CTX_new();
		key->evp_enc = EVP_CIPHER_CTX_new();

		EVP_CIPHER_CTX_init(key->evp_dec);
		EVP_CIPHER_CTX_init(key->evp_enc);
	}

	/* socketpair for notifying Lua about state changes
	 * Lua -> C direction isn't used */
	res = socketpair(AF_UNIX, SOCK_STREAM, 0, ctl->ctl_sock);
	assert(!res);
	//fd_nonblock(ovpn->ctl.ctl_sock[0]);

	ctl->ping_timer = ctimer_create(ovpn->chains, ENCRYPT_THREAD, ovpn_sendping, ctl, 10000);
}

static int open_client(const char *srv, int port) {
	struct sockaddr_in sin;
	int sfd, res;
	memset(&sin, 0, sizeof(sin));
	sfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(sfd>=0);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(srv);
	sin.sin_port = htons(port);
	res = connect(sfd,(struct sockaddr *) &sin, sizeof(sin));
	if(res) {
		close(sfd);
		return res;
	}
	fd_nonblock(sfd);
	return sfd;
}

int ovpn_connect(ovpn_t *ovpn, const char *srv, int port) {
	struct ctl_s *ctl = &ovpn->ctl;
	struct crypto_s *crypto = &ctl->crypto;
	int sock = open_client(srv, port);

	node_setfd(ovpn->chains, ovpn->sock_read, sock);
	node_setfd(ovpn->chains, ovpn->sock_write, dup(sock));

	//printf("connect fds %d %d\n",sock, ovpn->sock_write->fd);

	// reset ctl
	pthread_mutex_lock(&ctl->state_mtx);
	ctl->key_id = 0;
	memset(&ctl->tx_state, 0, sizeof(struct ctl_state_s));
	memset(&ctl->rx_state, 0, sizeof(struct ctl_state_s));
	pthread_mutex_unlock(&ctl->state_mtx);

	if(sock < 0)
		return sock;

	/* local session-id */
	prng(&crypto->prng, (uint8_t*) &ctl->tx_state.session_id, sizeof(&ctl->tx_state.session_id));

	// start chains and send 1st ctl packet
	return ovpn_ctl_start(ovpn->chains, ctl);
}

static void shutdown_cb(chains_t *chains, node_t *node, int res) {
	ovpn_t *ovpn = chains->priv;
	//printf("shutdown_cb node %s fd %d res %d\n",node->name,fd,res);

	if((node == ovpn->sock_read) || (node == ovpn->sock_write)) {
		struct crypto_s *crypto = &ovpn->ctl.crypto;
		int res = pthread_mutex_trylock(&ovpn->mtx);	/* prevent infinite recursion */
		if(res)
			return;

		ctimer_stop(chains, ovpn->ctl.ping_timer);
		crypto->valid_keys = 0;
		/* shutdown other part of socket as well */
		shutdown_node(chains, (node == ovpn->sock_read) ? ovpn->sock_write : ovpn->sock_read, 0);
		lua_notify(&ovpn->ctl, "DISCONNECT");
		pthread_mutex_unlock(&ovpn->mtx);
	}
}

static void prng_init(struct prng_s *prng) {
	uint8_t buf[16];
	int res = RAND_bytes(buf, 16);
	assert(res == 1);
	res = RAND_bytes(prng->buf, 16);
	assert(res == 1);
	AES_set_encrypt_key(buf, 128, &prng->aes);
	AES_encrypt(prng->buf, prng->buf, &prng->aes);
	pthread_mutex_init(&prng->mtx, NULL);
}

void prng(struct prng_s *prng, uint8_t *dst, uint32_t len) {
	int chunksize=0;
	pthread_mutex_lock(&prng->mtx);
	for(;len;len-=chunksize,dst+=chunksize) {
		AES_encrypt(prng->buf, prng->buf, &prng->aes);
		chunksize = len <= 16 ? len : 16;
		memcpy(dst, prng->buf, chunksize);
	}
	pthread_mutex_unlock(&prng->mtx);
}

ovpn_t *ovpn_init(int tun_fd, uint32_t flags) {
	ovpn_t *ovpn = calloc(1,sizeof(ovpn_t));
	struct ctl_s *ctl = &ovpn->ctl;
	struct crypto_s *crypto = &ctl->crypto;
	chains_t *chains = mkchains();

	pthread_mutex_init(&ovpn->mtx, NULL);

	ovpn->flags = flags;
	crypto->flags = flags;

	ovpn->chains = chains;
	chains->priv = ovpn;
	chains->shutdown_cb = shutdown_cb;

	node_setctx(chains_findnode(chains, "decrypt"), crypto);
	node_setctx(chains_findnode(chains, "encrypt"), crypto);
	node_setctx(chains_findnode(chains, "hmac_hash"), crypto);
	node_setctx(chains_findnode(chains, "hmac_verify"), crypto);

	node_setctx(chains_findnode(chains, "ovpn_decap"), ctl);
	node_setctx(chains_findnode(chains, "tls_encap"), ctl);

	ctl->encap = chains_findnode(chains, "ovpn_encap");
	ctl->tls_write = chains_findnode(chains, "tls_write");
	ctl->tls_read = chains_findnode(chains, "tls_read");
	ctl->lzo_comp = chains_findnode(chains, "lzo_comp");
	assert(ctl->encap);
	assert(ctl->tls_write);
	assert(ctl->lzo_comp);

	ovpn->sock_read = chains_findnode(chains, "sock_read");
	ovpn->sock_write = chains_findnode(chains, "sock_write");
	assert(ovpn->sock_read);
	assert(ovpn->sock_write);

	ctl_init(ovpn);
	prng_init(&crypto->prng);

	if(tun_fd >= 0) {
		node_setfd(chains, chains_findnode(chains, "tun_read"), tun_fd);
		node_setfd(chains, chains_findnode(chains, "tun_write"), dup(tun_fd));
	}

	chains_info(chains);

	chains_setup(chains);

	return ovpn;
}

/* next:
 *
 * - ctl mutex
 * - verify mutex for node shutdown
 * - stall/drop policy?, nonblocking chains?
 * - optimize TCP sock read?
 *
 * - buf (queue?) stats
 * - graceful shutdown
 *
 * TODO: flush queues on disconnect?
 *
 * - timer from Lua?
 *
 * - mutex for ctl?
 * 		-> otherwise msg if ordering might not be correct?
 *
 * - initiate soft reset before packet ID wraps
 * 	   rollover would need 1193046 pkts/s w/ 1h rekeying interval
 *     -> exotic case
 */

void ovpn_finish(ovpn_t *ovpn) {

	/* all remaining threads need to finish before we return
	 * b/c Lua does a dlclose() on this code and various memory
	 * sections for the threads will disappear */

	/* pthread_cancel isn't available if we chroot()ed
	 * b/c it needs libgcc_s <- DAFUQ?? */
	//pthread_cancel(ovpn->chains->master_pt);

	chains_destroy(ovpn->chains);

	/* TODO: free alloced data */
	puts("finish");

}

void hexdump(const uint8_t *d, int n) {
	for(;n;n--,d++)
		printf("%02x ",*d);
	puts("");
}
