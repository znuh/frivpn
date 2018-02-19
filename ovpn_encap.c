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

/* opcode is already in the buffer
 * just prepend length */
static int encap(chains_t *chains, node_t *n) {
	buf_t *ib = n->inbuf;
	size_t payload_len = ib->len;
	buf_prepend(ib, 2);
	ib->ptr[0] = payload_len>>8;
	ib->ptr[1] = payload_len&0xff;
	/* TODO: reset PING timer? */
	return ib->len;
}

const node_info_t ovpn_encap = {
	.name = "ovpn_encap",
	.desc = "OVPN encapsulate",
	.work = encap,
	.flags = NI_TRIVIAL,
};

int ovpn_process_ctl(chains_t *chains, struct ctl_s *ctl, buf_t *ib);
void ovpn_rx(chains_t *chains, struct ctl_s *ctl);

static int decap(chains_t *chains, node_t *n) {
	buf_t *ib = n->inbuf;

	/* remove length but leave opcode intact
	 * as it contains the key-id  */
	buf_consume(ib, 2);

	assert(ib->len > 1);

	// needs mutex or disable NI_ALLOW_MULTI
	//ovpn_rx(chains, (struct ctl_s *)n->ctx);

	/* handle control/ack packets */
	if((ib->ptr[0]>>3) != 6) { /* DATA_V1 */
		ovpn_process_ctl(chains, (struct ctl_s *)n->ctx, ib);
		/* non-trivial node if ctl processing done */
		stats_outdated(chains, n->thread_id);
		//return 0; /* prevent double discard */
	}

	return ib->len;
}

const node_info_t ovpn_decap = {
	.name = "ovpn_decap",
	.desc = "OVPN decapsulate",
	.work = decap,
	.flags = NI_TRIVIAL,
};
