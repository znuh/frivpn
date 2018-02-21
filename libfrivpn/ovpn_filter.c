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
#include "ovpn.h"
#include <assert.h>

static int work(chains_t *chains, node_t *n) {
	buf_t *ib = n->inbuf;
	uint8_t ipv;

	/* sanity-check for IPv4/6 packets
	 * drops OpenVPN PING packets */
	if(ib->len < 20)
		goto drop;

	ipv = *((const uint8_t *)ib->ptr)>>4;
	//printf("IPv%d\n",ipv);
	if((ipv == 4) || ((ipv == 6) && (ib->len >= 40)))
		goto done;

drop:
	ib->len = 0;
done:
	return ib->len;
}

const node_info_t ovpn_filter = {
	.name = "ovpn_filter",
	.desc = "OVPN data filter",
	.work = work,
	.flags = NI_TRIVIAL,
};
