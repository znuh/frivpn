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
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include "chains.h"
#include <assert.h>

int fd_nonblock(int sfd) {
	int res, flags = fcntl(sfd,F_GETFL,0);
	assert(flags != -1);
	res = fcntl(sfd, F_SETFL, flags | O_NONBLOCK);
	assert(!res);
	return res;
}

static char flagbuf[32];

static const char *flag_names[] = {
	"SOURCE ", "SINK ", "TRIVIAL", "OBUF", "USE_POLLOUT", NULL
};

static const char *flags2str(uint32_t flags) {
	int i;
	flagbuf[0]=0;
	for(i=0;flag_names[i];i++) {
		if(flags&1)
			strcat(flagbuf,flag_names[i]);
		flags>>=1;
	}
	return flagbuf;
}

#define NODE_FD_VALID(n)		((n)->fd >= 0)
#define NODE_FD_INVALID(n)		((n)->fd < 0)
#define NI_IS_SINK(ni)			((ni)->flags&NI_SINK)
#define NI_IS_SOURCE(ni)		((ni)->flags&NI_SOURCE)

/* invoke this if last timestamp for stats is outdated */
inline void stats_outdated(chains_t *chains, int thread_id) {
	thread_t *thread = chains->threads + thread_id;
	if (chains->flags & CHAINS_STATS_EN)
		thread->last_stats = chains_gettime(chains, 1);
}

static inline void stats_update(chains_t *chains, node_t *node) {
	const node_info_t *ni = node->ni;
	thread_t *thread = chains->threads + node->thread_id;
	node_stats_t *ns = node->stats;
	time64_t now, last;

	/* assume trivial nodes consume 0 cputime */
	if( (!(chains->flags & CHAINS_STATS_EN)) || (ni->flags & NI_TRIVIAL))
		return;

	last = thread->last_stats;

	/* get current time and set last to now */
	now = chains_gettime(chains, 1);
	thread->last_stats = now;

	/* done if no node-stats needed */
	if ((!ns) || (node->flags & NF_NOSTATS))
		return;

	now -= last;
	thread->total_cputime += now;
	ns->cputime += now;
	ns->invoked++;
}

static void print_node_stats(chains_t *chains, node_t *node) {
	node_stats_t *ns = node->stats;
	thread_t *thread = chains->threads + node->thread_id;
	time64_t perc, avg;
	if((!ns) || (!(chains->flags & CHAINS_STATS_EN)))
		return;
	if(!ns->invoked)
		return;
	assert(thread->total_cputime);
	avg = ns->cputime;
	avg /= ns->invoked;
	perc = ns->cputime;
	perc *= 100;
	perc /= thread->total_cputime;
	printf("    invoked: %"PRIu32"x, avg: %"PRIu64" ns, %"PRIu64"%%\n",ns->invoked, avg, perc);
}

void chains_info(chains_t *chains) {
	thread_t *thread;
	int i;
	uint64_t cputime;
	struct list_head *pos;
	list_for_each(pos, &chains->nodes){
		node_t *n= list_entry(pos, node_t, list);
		printf("  %-32s %d %-20s %-20s\n", n->name,n->thread_id,n->ni->name,flags2str(n->ni->flags));
		print_node_stats(chains, n);
	}
	puts("CPU time: ");
	for(i=0;i<chains->n_threads;i++) {
		thread = chains->threads + i;
		cputime = thread->total_cputime;
		cputime /= 1000000; /* msec */
		printf("%"PRIu64" ",cputime);
	}
	puts("");
}

chains_t *chains_create(int threads) {
	chains_t *c = calloc(1,sizeof(chains_t));
	int i;
	c->n_threads = threads;
	c->threads = calloc(threads,sizeof(thread_t));
	INIT_LIST_HEAD(&c->nodes);
	INIT_LIST_HEAD(&c->timers);
	pthread_mutex_init(&c->mtx, NULL);
	pthread_mutex_init(&c->recently_mtx, NULL);
	for(i=0;i<threads;i++) {
		thread_t *thread = c->threads+i;
		thread->notify_fd = -1;
		thread->epoll_fd = -1;
	}
	/* initialize time */
	chains_gettime(c, 1);
	return c;
}

/* this is very SLOW, but it's fine if used rarely (e.g. during init)
 * if node is needed often you should save the node pointer */
node_t *chains_findnode(chains_t *chains, const char *name) {
	struct list_head *pos;

	list_for_each(pos, &chains->nodes){
		node_t *n= list_entry(pos, node_t, list);
		if(!strcmp(n->name, name)) {
			//printf("node %s found\n",name);
			return n;
		}
	}
	return NULL;
}

node_t *chains_mknode(chains_t *chains, const node_info_t *ni, const char *name, int thread_id, node_t *dst_node) {
	node_t *n = chains_findnode(chains, name);
	thread_t *thread = chains->threads + thread_id;

	if(n)
		goto done;

	assert(thread_id < chains->n_threads);

	n = calloc(1,sizeof(node_t));
	n->fd = -1; // important! 0 is a valid fd (stdin)
	n->thread_id = thread_id;
	pthread_mutex_init(&n->mtx, NULL);

	n->name = strdup(name);
	n->ni = ni;
	n->dst = dst_node;

	/* node stats */
	if(!(ni->flags & NI_TRIVIAL))
		n->stats = calloc(1,sizeof(node_stats_t));

	// register node with chains
	list_add_tail(&n->list, &chains->nodes);
	chains->n_nodes++;

	if(ni->flags & (NI_SOURCE|NI_SINK))
		thread->n_ionodes++;

done:
	return n;
}

const node_info_t queue_sink;
const node_info_t queue_source;

int chain_create(chains_t *chains, const chain_template_t *t, size_t bufsize, uint32_t n_bufs) {
	node_t *new = NULL, *dst_node = NULL;
	chain_t *chain = calloc(1, sizeof(chain_t));
	int last_thread = t->thread_id;

	chain->bufsize = bufsize;
	chain->n_bufs = n_bufs;

	chain->bs = bufstore_create(bufsize, n_bufs);
	chain->bs->debug = &chains->debug;

	/* chain is assembled in reverse order (from sink to source) */
	for(;t->name;t++) {
		if(t->thread_id != last_thread) {
			char name[32];
			node_t *q_src, *q_sink;
			assert(dst_node);
			/* insert queue */
			sprintf(name,"%s->%s/sink",t->name,dst_node->name);
			q_sink = chains_mknode(chains, &queue_sink, name, t->thread_id, NULL);
			sprintf(name,"%s->%s/src",t->name,dst_node->name);
			q_src = chains_mknode(chains, &queue_source, name, last_thread, dst_node);
			node_setctx(q_src, q_sink);
			if(chains->debug) {
				printf("inserting queue %s (%d) -> %s (%d)\n",
					t->name, t->thread_id, dst_node->name, last_thread);
			}
			dst_node = q_sink;
			last_thread = t->thread_id;
		}
		new = chains_mknode(chains, t->ni, t->name, t->thread_id, dst_node);
		assert(new);
		new->chain=chain;
		dst_node=new;
	}
	chain->source = new;
	return 0;
}

void node_setctx(node_t *node, void *ctx) {
	assert(node);
	node->ctx = ctx;
}

static inline void wakeup_thread(thread_t *thread) {
	uint64_t v=1;
	int res;
	if(thread->notify_fd >= 0) {
		puts("wakeup");
		res = write(thread->notify_fd, &v, sizeof(v));
		assert(res == 8);
	}
	else { /* wakeup pthread_cond */
		assert(thread->queue_src);
		bufqueue_quit(thread->queue_src->priv);
	}
}

void chains_destroy(chains_t *chains) {
	int i;

	chains->quit = 1;

	for(i=0;i<chains->n_threads;i++) {
		thread_t *thread = chains->threads + i;
		printf("shutdown thread %d\n",i);
		wakeup_thread(thread);
		pthread_join(thread->thread, NULL);
	}
}

/* node mutex must be held */
void node_update_pollout(chains_t *chains, node_t *node) {
	thread_t *thread = chains->threads + node->thread_id;
	struct epoll_event ev;
	int res;
	assert(node);

	assert(NI_IS_SINK(node->ni));

	assert(node->fd >= 0);

	ev.events = (node->flags & NF_SINK_RESIDUE) ? EPOLLOUT : 0;

	if(ev.events == node->epoll_cfg)
		return;

	node->epoll_cfg = ev.events;

	ev.data.ptr = node;
	res = epoll_ctl(thread->epoll_fd, EPOLL_CTL_MOD, node->fd, &ev);
	assert(!res);
}

void node_setfd(chains_t *chains, node_t *node, int fd) {
	thread_t *thread = chains->threads + node->thread_id;
	int res;
	assert(node);

	pthread_mutex_lock(&node->mtx);

	if(thread->epoll_fd < 0) {
		node->fd = fd;
		goto out;
	}

	if(node->fd == fd)
		goto out;

	if(chains->debug)
		printf("node_setfd %s old %d new %d np %p\n",node->name,node->fd,fd,node);

	/* old fd valid? delete if true */
	if(node->fd >= 0) {
		res = epoll_ctl(thread->epoll_fd, EPOLL_CTL_DEL, node->fd, NULL);
		//assert(!res);
		node->fd = -1;
		node->epoll_cfg = 0;
	}

	node->fd = fd;

	if(node->fd >= 0) {
		struct epoll_event ev;
		ev.events = NI_IS_SOURCE(node->ni) ? EPOLLIN : 0;
		ev.events |= (node->flags & NF_SINK_RESIDUE) ? EPOLLOUT : 0;
		node->epoll_cfg = ev.events;
		ev.data.ptr = node;
		res = epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, node->fd, &ev);
		assert(!res);
	}

out:
	pthread_mutex_unlock(&node->mtx);
}

/* TODO: verify node mutex */
void shutdown_node(chains_t *chains, node_t *node, int res) {
	int fd = node->fd;

//	pthread_mutex_lock(&node->mtx);

	/* shutdown already done? */
	if(fd < 0)
		goto out;

	if(chains->debug)
		printf("shutdown node %s (reason: %d) fd %d\n",node->name,res,fd);

	if(chains->shutdown_cb)
		chains->shutdown_cb(chains, node, res);

	node_setfd(chains, node, -1);
	if(node->ni->reset)
		node->ni->reset(node);
	close(fd);

out:
//	pthread_mutex_unlock(&node->mtx);

	/* might have taken a while -> last timestamp might be outdated */
	stats_outdated(chains, node->thread_id);
}

int run_chain(chains_t *chains, node_t *node, buf_t *obuf, int discard) {
	int res=0;
	node_t *last=NULL;
	buf_t *last_discard = NULL;

	if(chains->debug)
		printf("run_chain %s\n",node->name);

	for(;node && (!chains->quit);node=node->dst) {
		const node_info_t *ni = node->ni;
		const chain_t *chain = node->chain;
		buf_t *tmp_obuf = NULL;

		pthread_mutex_lock(&node->mtx);

		/* abort if we stumble upon a sink or source w/o a valid fd */
		if( (NI_IS_SINK(ni) || NI_IS_SOURCE(ni)) && NODE_FD_INVALID(node) &&
			(ni != &queue_source) && (ni != &queue_sink) ) {
			printf("node %s: fd invalid - dropping data\n",node->name);
			res = 0;
			pthread_mutex_unlock(&node->mtx);
			break;
		}

		/* set former output buffer as input buffer
		 * also set input as default output buffer
		 * in case the node doesn't set one */
		node->inbuf = obuf;
		node->outbuf = obuf;

		/* if node needs an output buffer get one
		 * keep reference to this buffer and release if node didn't use it */
		if(ni->flags & NI_OBUF)
			tmp_obuf = node->outbuf = bufstore_getbuf(chain->bs, chain->bufsize, 0);

		last=node;

		res = ni->work(chains, node);

		stats_update(chains, node);

		if(chains->debug > 5)
			printf("node %s: res %d ib %p ob %p\n",node->name,res,node->inbuf,node->outbuf);

		/* keep output buffer for next node */
		obuf = node->outbuf;

		/* discard temporary buffer if unused */
		if(tmp_obuf && (obuf != tmp_obuf))
			buf_discard(tmp_obuf,node->name);

		/* discard inbuf if node didn't forward the input buffer
		 * (no longer needed) */
		if((node->inbuf != node->outbuf) && (node->inbuf) && (discard) ) {
			buf_discard(node->inbuf,node->name);
			last_discard = node->inbuf;
		}

		if (NI_IS_SINK(ni) && (ni->flags & NI_USE_POLLOUT))
			node_update_pollout(chains, node);

		pthread_mutex_unlock(&node->mtx);

		last = node;

		/* abort if output void */
		if((!res) || (!obuf))
			break;

		if(res < 0) {
			/* TODO: mutex? */
			shutdown_node(chains, node, res);
			break;
		}
	}

	/* usually we discard the last output buffer after processed by the sink (res==0)
	 * a special case exists if sink is a queue - then we must not discard obuf
	 * (queue sink returns res > 0) */
	if(obuf && (res <= 0) && (discard)) {
		assert(last_discard != obuf);
		buf_discard(obuf,last->name);
	}

	/* TODO: flow control update */

	return 0;
}

int process_timers(chains_t *chains, int thread_id);

static inline int thread_poll(chains_t *chains, struct epoll_event *events, int n_events, int thread_id) {
	thread_t *thread = chains->threads + thread_id;
	int res, timeout=-1;

	do {
		timeout = process_timers(chains, thread_id);
		res = epoll_wait(thread->epoll_fd, events, n_events, timeout);
	} while(!res);
	assert(res>0);
	return res;
}

static void *chains_thread(void *priv) {
	chains_t *chains = priv;
	thread_t *thread;
	struct epoll_event *ev, *events = NULL;
	int res, n_events = 0;
	int thread_id;

	pthread_mutex_lock(&chains->mtx);
	/* get a unique thread id */
	thread_id = chains->thread_idx++;
	pthread_mutex_unlock(&chains->mtx);

	thread = chains->threads + thread_id;

	/* special treatment for threads waiting on a pthread_cond */
	if(thread->queue_src) {
		while(!chains->quit)
			run_chain(chains, thread->queue_src, NULL, 1);
		goto quit;
	}

	n_events = thread->n_ionodes+1;
	events = alloca(sizeof(struct epoll_event)*n_events);

	/* TODO: mutex */
	while(!chains->quit) {

		res = thread_poll(chains, events, n_events, thread_id);
		assert(res>0);
		stats_outdated(chains, thread_id);

		if(chains->quit)
			break;

		for(ev=events;res;res--,ev++) {
			node_t *n = ev->data.ptr;

			if(!n) {
				uint64_t v;
				int res2 = read(thread->notify_fd, &v, sizeof(v));
				assert(res2 == sizeof(v));
				puts("WAKEUP");
				continue; /* wakeup */
			}

			if(chains->debug > 5)
				printf("(%d) node %s revents %x\n",thread_id, n->name,ev->events);

			/* TODO: verify shutdown <-> OOB shutdown */
			if(ev->events & (EPOLLRDHUP|EPOLLERR|EPOLLHUP)) {
				shutdown_node(chains, n, ev->events);
			}

			else if(ev->events & EPOLLOUT) {
				/* we only invoke the sink, but we use run_chain
				 * b/c it does all the mutex stuff, etc. */
				run_chain(chains, n, NULL, 1);
			}

			else if(ev->events & EPOLLIN) {
				do {
					run_chain(chains, n, NULL, 1);
					/* TODO: stalled chain */
				} while(n->flags & NF_SOURCE_RESIDUE);
			}
		}
	} // main loop

quit:
	printf("thread %d quit\n",thread_id);

	if((!thread_id) && (chains->flags & CHAINS_STATS_EN))
		chains_info(chains);

	return NULL;
}

static int thread_setup(chains_t *chains, int thread_id) {
	thread_t *thread = chains->threads+thread_id;
	struct list_head *pos;
	int res;
	int sources = 0;
	int pthread_queue = 1;
	node_t *queue_src = NULL;
	struct epoll_event ev;

	/* arrays used for poll() */

	thread->epoll_fd = epoll_create1(0);
	assert(thread->epoll_fd >= 0);

	printf("thread %d fds:\n",thread_id);
	list_for_each(pos, &chains->nodes) {
		node_t *n= list_entry(pos, node_t, list);
		const node_info_t *ni = n->ni;

		if(n->thread_id != thread_id)
			continue;

		if(NI_IS_SINK(ni) || NI_IS_SOURCE(ni)) {

			printf("  %s: %d\n",n->name,n->fd);

			if(NODE_FD_VALID(n)) {
				struct epoll_event ev;
				ev.events = NI_IS_SOURCE(ni) ? EPOLLIN : 0;
				ev.data.ptr = n;
				res = epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, n->fd, &ev);
				assert(!res);
			}

			/* determine if we can use pthread_cond instead of eventfd */
			if(NI_IS_SOURCE(ni)) {
				sources++;
				if(ni != &queue_source)
					pthread_queue = 0;
				else
					queue_src = n;
			}
			/* if we need poll for at least one sink then we cannot
			 * use pthread_cond either */
			else if(NI_IS_SINK(ni) && (ni->flags & NI_USE_POLLOUT))
				pthread_queue = 0;

		}
	}

	/* use pthread_cond for queue instead of eventfd? */
	if((sources == 1) && pthread_queue && queue_src) {
		node_t *sink = queue_src->ctx;

		puts("  using pthread_cond instead of eventfd");

		/* eventfd to the ground */
		node_setfd(chains, sink, -1);
		node_setfd(chains, queue_src, -1);
		close(sink->fd);

		/* single source: queue */
		thread->queue_src = queue_src;

		close(thread->epoll_fd);
		thread->epoll_fd = -1;

		return 0;
	}

	/* notify fd */
	res = eventfd(0, EFD_NONBLOCK);
	assert(res>=0);
	thread->notify_fd = res;

	/* add to epoll */
	ev.events = EPOLLIN;
	ev.data.ptr = NULL;
	res = epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, thread->notify_fd, &ev);
	assert(!res);

	return 0;
}

int chains_setup(chains_t *chains) {
	int res, i;
	struct list_head *pos;

	/* init all nodes */
	list_for_each(pos, &chains->nodes) {
		node_t *n= list_entry(pos, node_t, list);
		const node_info_t *ni = n->ni;

		if(ni->init) {
			printf("calling init for %s\n",n->name);
			ni->init(chains,n);
		}

		if(ni->reset)
			ni->reset(n);
	}

	/* setup threads */
	for(i=0;i<chains->n_threads;i++) {
		res = thread_setup(chains, i);
		assert(!res);
	}

	/* start threads */
	for(i=0;i<chains->n_threads;i++) {
		thread_t *thread = chains->threads+i;
		res = pthread_create(&thread->thread, NULL, chains_thread, chains);
		assert(!res);
	}
	return res;
}
