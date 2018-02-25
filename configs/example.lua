return {
	tlskeys = "ta.key",
	tlskeys_ids = { 1, 1 },
	cafile = "ca.pem",
	auth = "vpn.auth",
	netmask = 24,
	host = "1.2.3.4",
	port = 1195,
	on_connected = "onconnect.sh",
	-- stats: to-be-documented
	stats = true,
	-- debug: to-be-documented
	debug = 0xffff,
	-- ignore_hmac: to-be-documented
	ignore_hmac = false,
	-- key: to-be-documented
	key = "",
	-- certificate: to-be-documented
	certificate = "",
}
