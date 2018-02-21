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
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "timer.h"
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

time64_t chains_gettime(chains_t *chains, int precision) {
	time64_t res;
	pthread_mutex_lock(&chains->recently_mtx);
	if(precision) {
		struct timespec ts;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		res = ts.tv_sec;
		res *= 1000000000;
		res += ts.tv_nsec;
		chains->recently = res;
	}
	res = chains->recently;
	pthread_mutex_unlock(&chains->recently_mtx);
	return res;
}

void ctimer_start(chains_t *chains, ctimer_t *ct) {
	ct->timeout = chains_gettime(chains, 0) + ct->interval;
	ct->flags |= CTIMER_ENABLED;
}

void ctimer_stop(chains_t *chains, ctimer_t *ct) {
	ct->flags &= ~CTIMER_ENABLED;
}

ctimer_t *ctimer_create(chains_t *chains, int thread_id,
	int (*work) (chains_t *chains, ctimer_t *ct, void *priv), void *priv, time64_t interval) {
	ctimer_t *ct = calloc(1,sizeof(ctimer_t));

	ct->thread_id = thread_id;

	// register node with chains
	list_add_tail(&ct->list, &chains->timers);
	chains->n_timers++;

	ct->work = work;
	ct->priv = priv;
	ct->interval = interval*1000000; /* convert from msec to nsec */
	return ct;
}

/* this timer implementation is horribly inefficient
 * but then again we only have 1 timer at the moment */
int process_timers(chains_t *chains, int thread_id) {
	struct list_head *pos;
	time64_t now = chains_gettime(chains, 1); /* get latest time */
	uint64_t naptime=0;
	uint64_t tmp;

	/* walk through active timers until tval > current time */
	list_for_each(pos, &chains->timers) {
		ctimer_t *ct= list_entry(pos, ctimer_t, list);

		if(ct->thread_id != thread_id)
			continue;

		if(!(ct->flags & CTIMER_ENABLED))
			continue;

		if(now >= ct->timeout) {
			int res = ct->work(chains, ct, ct->priv);
			ct->flags = res;
			if(!res)
				continue;
			ct->timeout = now + ct->interval;
		}

		tmp = ct->timeout - now;
		if((!naptime) || (tmp < naptime))
			naptime = tmp;
	}
	naptime /= 1000000; /* nsec -> msec */

	if(chains->debug > 1)
		printf("naptime: %"PRIu64"\n",naptime);

	return naptime ? naptime : -1;
}
