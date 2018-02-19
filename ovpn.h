#ifndef OVPN_H
#define OVPN_H

#include <stdint.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <assert.h>

#include "chains.h"

enum opcode_e {
	CLIENT_RESET 	= 1,
	SERVER_RESET 	= 2,
	SOFT_RESET		= 3,
	CONTROL			= 4,
	ACK				= 5,
	DATA			= 6,
	CLIENT_RESET_V2	= 7,
	SERVER_RESET_V2	= 8,
	DATA_V2			= 9,
};

#define MAX_PENDING_ACKS	32

struct prng_s {
	AES_KEY aes;
	uint8_t buf[16];
	pthread_mutex_t mtx;
};

struct key_s {
	EVP_CIPHER_CTX *evp_dec;
	EVP_CIPHER_CTX *evp_enc;
	HMAC_CTX *hmac_tx;
	HMAC_CTX *hmac_rx;
	uint32_t rx_pid;
	uint32_t tx_pid;
	pthread_rwlock_t lock;
};

struct crypto_stats_s {
	uint64_t bytes;
	uint64_t packets;
};

struct crypto_s {
	struct key_s key[8];
	uint32_t valid_keys;
	int tx_key;
	pthread_rwlock_t lock;

	struct crypto_stats_s enc_stats;
	struct crypto_stats_s dec_stats;

	// TODO: IV, chiper spec, etc.
	struct prng_s prng;
	uint32_t flags;
};

struct ctl_state_s {
	uint64_t session_id;
	uint32_t packet_id; /* also incremented by ACKs */
	uint32_t last_time; /* stored in network endian! */
	uint32_t msg_pkt_id;
	uint8_t n_acks;
	uint32_t ack_ids[MAX_PENDING_ACKS];
};

struct ctl_s {
	uint32_t debug;

	int ctl_sock[2];

	HMAC_CTX *hmac_tx;
	HMAC_CTX *hmac_rx;

	int key_id;
	struct ctl_state_s tx_state;
	struct ctl_state_s rx_state;
	pthread_mutex_t state_mtx;
	node_t *encap;
	node_t *tls_write;
	node_t *tls_read;
	node_t *lzo_comp;

	time64_t last_rx; /* used for timeout detection */
	ctimer_t *ping_timer;

	struct crypto_s crypto;
};

#define KEY_VALID(c,id)	( ((id)>=0) && (((c)->valid_keys>>(id))&1) )

#define OVPN_IGNORE_HMAC	1

typedef struct ovpn_s {

	pthread_mutex_t mtx;

	struct ctl_s ctl;

	chains_t *chains;
	node_t *sock_read;
	node_t *sock_write;

	uint32_t flags;
} ovpn_t;

ovpn_t *ovpn_init(int tun_fd, uint32_t flags);
int ovpn_connect(ovpn_t *ovpn, const char *srv, int port);
int ovpn_loop(ovpn_t *ovpn);
void ovpn_finish(ovpn_t *ovpn);
void ovpn_ctl_config(ovpn_t *ovpn, const uint8_t *hmac_txkey, const uint8_t *hmac_rxkey);
int ovpn_ctl_start(chains_t *chains, struct ctl_s *ctl);
int ovpn_tls_getsock(ovpn_t *ovpn);
int ovpn_ctl_getsock(ovpn_t *ovpn);
void ovpn_ctl_setkeys(ovpn_t *ovpn, const uint8_t *keys);
uint32_t compare_hmac(const uint8_t *a, const uint8_t *b, size_t len);
void hexdump(const uint8_t *d, int n);
void prng(struct prng_s *prng, uint8_t *dst, uint32_t len);
void lua_notify(struct ctl_s *ctl, const char *msg);
struct key_s *request_key(struct crypto_s *crypto, int key_id);

#endif /* OVPN_H */
