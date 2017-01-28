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
#include "chains.h"
#include <assert.h>

static void *write_thread(void *priv) {
	node_t *n = priv;
	bufqueue_t *q = n->priv;
	
	while(1) {
		buf_t *b = bufqueue_get(q);
		if(!b)
			break;
		int res = write(n->fd, b->ptr, b->len);
		assert(res == b->len);
		buf_discard(b, NULL);
	}
	return NULL;
}

static int init(chains_t *chains, node_t *n) {
	bufqueue_t *q = bufqueue_create(128);
	pthread_t pt1, pt2;
	int res;
	n->priv = q;
	res = pthread_create(&pt1, NULL, write_thread, n);
	assert(!res);
	res = pthread_create(&pt2, NULL, write_thread, n);
	assert(!res);
	return 0;
}

static int putbuf(chains_t *chains, node_t *n) {
	bufqueue_t *q = n->priv;
	bufqueue_put(q, n->inbuf);
	return 1;
}

const node_info_t mt_write_single = {
	.name = "mt_write_single",
	.desc = "multithreaded write sink w/o remainder",
	.init = init,
	.work = putbuf,
	.flags = NI_SINK,
};
