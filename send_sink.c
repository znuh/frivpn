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
#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include "chains.h"
#include "assert.h"

static int work(chains_t *chains, node_t *n) {
	buf_t *b = n->inbuf;
	int res = send(n->fd, b->ptr, b->len, 0);
	//if(res != b->len)
		//fprintf(stderr,"len %d res %d\n",b->len,res);
	assert(res == b->len);
	return 0;
}

const node_info_t send_sink = {
	.name = "send_sink",
	.desc = "send file/sock sink",
	.work = work,
	.flags = NI_SINK,
};
