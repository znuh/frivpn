
return {
	tlskeys = "ipredator/ta.key",
	tlskeys_ids = { 1, 1 },
	cafile = "ipredator/ca.pem",
	auth = "IPredator.auth",
	netmask = 24,
	host = "46.246.36.130",
	on_connected = "/etc/scripts/inet-se.sh",
	--debug = 0xffff,
	--stats = true,
}
