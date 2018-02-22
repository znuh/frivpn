/*
 * Copyright (C) 2017-2018 Benedikt Heinz <Zn000h AT gmail.com>
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

#ifndef NODES_H
#define NODES_H

#include "chains.h"

const node_info_t ovpn_decrypt;
const node_info_t ovpn_encrypt;
const node_info_t ovpn_tcp_src;
const node_info_t write_sink;
const node_info_t write_single;
const node_info_t read_src;
const node_info_t ovpn_hmac_hash;
const node_info_t ovpn_hmac_verify;
const node_info_t ovpn_encap;
const node_info_t tls_encap;
const node_info_t ovpn_decap;
const node_info_t lzo_comp;
const node_info_t lzo_decomp;
const node_info_t ovpn_filter;

#endif /* NODES_H */
