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
