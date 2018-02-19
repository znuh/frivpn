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
#include <stdlib.h>
#include <unistd.h>
#include "chains.h"
#include <assert.h>
#include <stdio.h>

static int work(chains_t *chains, node_t *n) {
	buf_t *b = n->outbuf;
	int res;
	buf_reset(b, 64);
	res = read(n->fd, b->ptr, b->maxlen);
	if(b>0)
		b->len = res;
//	if(res<0)
//		return res;
//	assert(res >= 0);
	/*
	if(res<=0) {
		printf("node %s read %d!\n",n->name,res);
		res=0;
	}
	*/
	return res;
}

const node_info_t read_src = {
	.name = "read_src",
	.desc = "read source",
	.work = work,
	.flags = NI_SOURCE | NI_OBUF,
};
