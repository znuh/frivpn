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
#include <sys/eventfd.h>
#include "chains.h"
#include <assert.h>
#include <inttypes.h>

void bufqueue_quit(bufqueue_t *q) {
	q->quit=1;
	pthread_mutex_lock(&q->mutex);
	pthread_cond_signal(&q->get_unblock);
	pthread_mutex_unlock(&q->mutex);
}

bufqueue_t *bufqueue_create(uint32_t n_bufs) {
	bufqueue_t *q = calloc(1,sizeof(bufqueue_t));
	q->n_bufs = n_bufs;
	assert(is_power_of_two(q->n_bufs));

	q->bufs = malloc(sizeof(buf_t *) * q->n_bufs);

	pthread_mutex_init(&q->mutex, NULL);
	pthread_cond_init(&q->put_unblock, NULL);
	pthread_cond_init(&q->get_unblock, NULL);
	return q;
}

void bufqueue_put(bufqueue_t *q, buf_t *ib) {
	pthread_mutex_lock(&q->mutex);

	q->put_blocked++;
	while(q->full_bufs == q->n_bufs)
		pthread_cond_wait(&q->put_unblock, &q->mutex);
	q->put_blocked--;

	q->bufs[q->put_idx++] = ib;
	q->put_idx &= (q->n_bufs-1);
	q->full_bufs++;

	if(q->get_blocked)
		pthread_cond_signal(&q->get_unblock);

	pthread_mutex_unlock(&q->mutex);
}

buf_t *bufqueue_get(bufqueue_t *q) {
	buf_t *ob=NULL;

	pthread_mutex_lock(&q->mutex);

	q->get_blocked++;
	while((!q->full_bufs) && (!q->quit))
		pthread_cond_wait(&q->get_unblock, &q->mutex);
	q->get_blocked--;

	if(q->quit)
		goto out;

	ob = q->bufs[q->get_idx++];
	q->get_idx &= (q->n_bufs-1);
	q->full_bufs--;

	if(q->put_blocked)
		pthread_cond_signal(&q->put_unblock);

out:
	pthread_mutex_unlock(&q->mutex);

	return ob;
}

#define QUEUE_NODE_BUFS			128

static int sink_init(chains_t *chains, node_t *n) {
	n->priv = bufqueue_create(QUEUE_NODE_BUFS);
	n->fd = eventfd(0, EFD_NONBLOCK|EFD_SEMAPHORE);
	return 0;
}

/* context for source must be the sink node
 * source then grabs the shared queue struct from sink node priv */
static int source_init(chains_t *chains, node_t *n) {
	node_t *sink = n->ctx;
	bufqueue_t *q;
	assert(sink);
	q=sink->priv;
	assert(q);
	n->priv = q;
	n->fd = dup(sink->fd);
	return 0;
}

static int sink_put(chains_t *chains, node_t *n) {
	bufqueue_t *q = n->priv;
	bufqueue_put(q, n->inbuf);

	if(n->fd >= 0) {
		uint64_t v=1;
		int res = write(n->fd, &v, sizeof(v));
		assert(res == sizeof(v));
	}

	/* don't return 0 or the buf will be released
	 *
	 * after the mutex_unlock other threads can modify ib->len
	 * therefor we need to return something else (>0)
	 * otherwise we might discard the buf multiple times */
	return 1;
}

static int source_get(chains_t *chains, node_t *n) {
	bufqueue_t *q = n->priv;
	buf_t *ob;

	if(n->fd >= 0) {
		uint64_t v;
		int res = read(n->fd, &v, sizeof(v));
		assert(res == sizeof(v));
	}

	ob = bufqueue_get(q);

	if(!ob)
		return 0;

	stats_outdated(chains, n->thread_id);

	n->outbuf = ob;
	return ob->len;
}

const node_info_t queue_sink = {
	.name = "queue_sink",
	.desc = "queue sink",
	.init = sink_init,
	.work = sink_put,
	.flags = NI_SINK,
};

const node_info_t queue_source = {
	.name = "queue_source",
	.desc = "queue source",
	.init = source_init,
	.work = source_get,
	.flags = NI_SOURCE,
};
