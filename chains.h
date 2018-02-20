#ifndef CHAINS_H
#define CHAINS_H

#include <unistd.h>
#include <stdint.h>
#include <pthread.h>
//#include <poll.h>

typedef struct node_info_s node_info_t;
typedef struct node_s node_t;
typedef struct chains_s chains_t;
typedef struct thread_s thread_t;
typedef struct buf_s buf_t;
typedef struct bufstore_s bufstore_t;
typedef struct ctimer_s ctimer_t;
typedef uint64_t time64_t;

#ifndef MIN
#define MIN(a,b)	((a)<=(b) ? (a) : (b))
#endif

#include "timer.h"

#define CTIMER_ENABLED	1

struct ctimer_s {
	int thread_id;
	time64_t timeout;
	time64_t interval;
	uint32_t flags;
	void *priv;
	int (*work) (chains_t *chains, ctimer_t *ct, void *priv);
	struct list_head list;
};

#define BUF_INUSE	(1<<0)

struct buf_s {
	uint8_t *d;
	size_t bufsize;

	uint8_t *ptr;
	size_t ofs;
	size_t len;
	size_t maxlen;	/* remaining length from ptr to end of buf */

	const char *last_node;

	/* bufstore stuff */
	bufstore_t *owner;
	struct list_head list;
	uint32_t flags;
};

void *buf_reset(buf_t *b, size_t ofs);
#define buf_assertspace(buf,sz)	assert((sz) <= (buf)->maxlen)
void *buf_prepend(buf_t *b, size_t sz);
void *buf_consume(buf_t *b, size_t sz);

typedef struct bufqueue_s {
	buf_t **bufs;
	uint32_t n_bufs;
	uint32_t full_bufs;
	uint32_t put_idx;
	uint32_t get_idx;

	pthread_mutex_t mutex;
	pthread_cond_t put_unblock;
	pthread_cond_t get_unblock;
	int put_blocked;
	int get_blocked;

	int quit;
} bufqueue_t;

void bufqueue_quit(bufqueue_t *q);
bufqueue_t *bufqueue_create(uint32_t n_bufs);
void bufqueue_put(bufqueue_t *q, buf_t *ib);
buf_t *bufqueue_get(bufqueue_t *q);

typedef struct bufmgmt_simple_s {
	uint8_t *bufs;
	buf_t **stack;
	uint32_t idx;
} bufmgmt_simple_t;

struct bufstore_s {

	pthread_mutex_t mtx;
	pthread_cond_t cond;
	int blocked;

	uint32_t *debug;

	bufmgmt_simple_t bm;
};

bufstore_t *bufstore_create(size_t bufsize, uint32_t n_bufs);
buf_t *bufstore_getbuf(bufstore_t *bs, size_t len, int nonblock);
int bufstore_exhausted(bufstore_t *bs);
void buf_discard(buf_t *buf, const char *last_node);

#define NI_SOURCE			(1<<0)
#define NI_SINK				(1<<1)
#define NI_TRIVIAL			(1<<2)	/* trivial task - stats disable */
#define NI_OBUF				(1<<3)	/* node needs output buffer != input buffer */
#define NI_USE_POLLOUT		(1<<4)	/* sink needs to be triggered by pollout */

/* RFU: */
//#define NI_ALLOW_MULTI		(1<<2)	/* allow multiple threads for node */

struct node_info_s {
	char *name;
	char *desc;
	int (*init) (chains_t *chains, node_t *n);
	void (*reset) (node_t *n);
	int (*work) (chains_t *chains, node_t *n);
	uint32_t flags;
};

typedef struct chain_s {
	bufstore_t *bs;
	size_t bufsize;
	uint32_t n_bufs;
	node_t *source;
} chain_t;

typedef struct chain_template_s {
	const char *name;
	const node_info_t *ni;
	const int thread_id;
} chain_template_t;

typedef struct node_stats_s {
	time64_t cputime;
	uint32_t invoked;
} node_stats_t;

#define NF_SOURCE_RESIDUE		(1<<0)	/* indicates that source can provide another data chunk w/o doing a new read */
#define NF_SINK_RESIDUE			(1<<1)	/* indicates that the sink wants to write data */
#define NF_BYPASS				(1<<2)  /* TODO: bypass for node (e.g. LZO) */
#define NF_NOSTATS				(1<<3)	/* stats disable */

struct node_s {
	int fd;
	uint32_t epoll_cfg;
	int thread_id;
	char *name;
	void *priv;
	void *ctx;
	const node_info_t *ni;
	chain_t *chain;
	buf_t *inbuf;
	buf_t *outbuf;
	node_t *dst;
	uint32_t flags;
	node_stats_t *stats;
	struct list_head list;
	pthread_mutex_t mtx; /* used for out-of-band processing */
};

#define CHAINS_STATS_EN			(1<<0)

struct thread_s {
	pthread_t thread;
/*
	pthread_mutex_t poll_mtx;
	struct pollfd *pollfds[2];
	int pfd_idx;
	node_t **io_nodes;
*/
	uint32_t n_ionodes;

	int notify_fd;

	int epoll_fd;
	node_t *queue_src;	/* used if we have a single source which is a queue */

	//int poll_active;

	time64_t last_stats;
	time64_t total_cputime;
};

struct chains_s {

	pthread_mutex_t mtx;

	int quit;
	uint32_t debug;

	void (*shutdown_cb) (chains_t *chains, node_t *node, int res);
	void *priv;

	uint32_t n_nodes;
	struct list_head nodes;

	int thread_idx;
	thread_t *threads;
	uint32_t n_threads;

	/***************************/

	/* all timers are handled in thread 0 */
	uint32_t n_timers;
	struct list_head timers;

	/* we build a proxy around the syscall so we can reuse the most recent
	 * timestamp for use-cases with lower precision requirements.
	 * we do this because clock_gettime/gettimeofday is a regular syscall
	 * on some platforms (see vdso(7) for more details) */
	time64_t recently; /* timestamp */
	pthread_mutex_t recently_mtx;

	uint32_t flags; /* stats en-/disable per thread? */
};

int chains_setup(chains_t *chains);
void chains_info(chains_t *chains);
chains_t *chains_create(int threads);
node_t *chains_findnode(chains_t *chains, const char *name);
int chain_create(chains_t *chains, const chain_template_t *t, size_t bufsize, uint32_t n_bufs);
void node_setctx(node_t *node, void *ctx);
void node_setfd(chains_t *chains, node_t *node, int fd);
void chains_destroy(chains_t *chains);
int fd_nonblock(int sfd);
void stats_outdated(chains_t *chains, int thread_id);
int run_chain(chains_t *chains, node_t *node, buf_t *obuf, int discard);
void shutdown_node(chains_t *chains, node_t *node, int res);

#define is_power_of_two(x)	(!((x)&(x-1)))

#endif /* CHAINS_H */
