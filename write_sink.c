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
#include <sys/uio.h>

static int work_poll(chains_t *chains, node_t *n) {
	buf_t *b = n->inbuf;
	int res, remain=b->len;
	uint8_t *p=b->ptr;

	while(remain) {
		struct pollfd pfd = {.fd=n->fd, .events=POLLOUT};
		poll(&pfd, 1, -1);

		if(pfd.revents != POLLOUT)
			return -1;

		//assert(pfd.revents == POLLOUT);
		res = write(n->fd, p, remain);
		if(res <= 0)
			return -1;
		remain-=res;
		p+=res;
	}

	return 0;
}

static int work_single(chains_t *chains, node_t *n) {
	buf_t *b = n->inbuf;
	int res = write(n->fd, b->ptr, b->len);
	assert(res == b->len);
	return 0;
}

const node_info_t write_sink = {
	.name = "write_sink",
	.desc = "write file/sock sink",
	.work = work_poll,
	.flags = NI_SINK,
};

const node_info_t write_single = {
	.name = "write_single",
	.desc = "write sink w/o remainder",
	.work = work_single,
	.flags = NI_SINK,
};
