return {
	tlskeys = "/etc/vpn/nordvpn/ta.key",
	tlskeys_ids = { 1, 1 },
	cafile = "/etc/vpn/nordvpn/ca.pem",
	auth = "/etc/vpn/nordvpn/nordvpn.auth",
	netmask = 24,
	--NordVPN Germany, please change as you like
	host = "89.249.64.230",
	port = 443,
	on_connected = "/etc/vpn/onconnect.sh",
	--stats = true,
	--debug = 0xffff,
}
