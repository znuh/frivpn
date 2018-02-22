return {
	tlskeys = "/etc/vpn/nordvpn/ta.key",
	tlskeys_ids = { 1, 1 },
	cafile = "/etc/vpn/nordvpn/ca.pem",
	auth = "/etc/vpn/nordvpn/nordvpn.auth",
	netmask = 24,
	--NordVPN Germany, please change as you like
	host = "5.254.89.173",
	on_connected = "/etc/vpn/onconnect.sh",
	--stats = true,
	--debug = 0xffff,
}
