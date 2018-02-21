return {
	tlskeys = "/etc/vpn/ipredator/ta.key",
	tlskeys_ids = { 1, 1 },
	cafile = "/etc/vpn/ipredator/ca.pem",
	auth = "/etc/vpn/ipredator/ipredator.auth",
	netmask = 24,
	host = "46.246.36.130",
	on_connected = "/etc/vpn/onconnect.sh",
	--stats = true,
	--debug = 0xffff,
}
