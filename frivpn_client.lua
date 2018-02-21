#!/usr/bin/env lua

-- Make sure we can load libfrivpn when being executed from the src dir
package.cpath = package.cpath .. ';./build/libfrivpn/?.so'

local cqueues = require "cqueues"
local csock = require "cqueues.socket"
local hmac = require "openssl.hmac"
local rand = require "openssl.rand"
local ssl = require "openssl.ssl.context"
local x509 = require "openssl.x509"
local castore = require "openssl.x509.store"
local pkey = require "openssl.pkey"
local posix = require "posix"

require "libfrivpn"
require "utils"
require "seccomp_filter"

local syscalls = {
	"futex",
	"read",
	"epoll_wait",
	"poll",
	"write",
	"writev",
	"clock_gettime",
	"gettimeofday",
	"epoll_ctl",
	"select",
	"_newselect",
	"brk",
	"close",
	"dup",
	"connect",
	"fcntl",
	"fcntl64",
	"fstat",
	"fstat64",
	"getsockopt",
	"rt_sigpending",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigreturn",
	"sigreturn",
	"sendto",
	"send",
	"set_robust_list",
	"setsockopt",
	"socket",
	"socketpair",
	"open",
	"lseek",
	"_llseek", -- ARM
	"getrandom", -- not used by ossl yet??
	"_sysctl", -- TODO: more specific: CTL_KERN, KERN_RANDOM
	"exit_group",
	"exit",
	"munmap",
	"mmap2",
	"eventfd2",
	-- AF_ALG
	--"bind",
	--"accept",

}

function lookup_ip(host)
	local res = posix.getaddrinfo(host, 1195)
	return res[1].addr
end

function tun_update(tun_dev, ip, mask)
	os.execute("/sbin/ip addr flush dev "..tun_dev)
	if ip and mask then
		os.execute("/sbin/ip addr add "..ip.."/"..mask.." dev "..tun_dev)
	end
end

function tun_fork(tun_dev, netmask, on_connected)
	local r,w = posix.pipe()
	local cpid = posix.fork()
	
	if cpid ~= 0 then	-- parent
		posix.close(r)
		return w, cpid
	end
	
	-- child
	posix.close(w)
	
	os.execute("/sbin/ip link set dev "..tun_dev.." up")
	
	while true do
		local res = posix.read(r, 100)
		if #res < 1 then break end
		local ip = res:match("(%d+%.%d+%.%d+%.%d+)")
		--print(ip,mask)
		tun_update(tun_dev, ip, netmask)
		if on_connected then
			os.execute(on_connected)
		end
	end
	posix.close(r)
	posix._exit(0)	
end

local cq = cqueues.new()

function load_auth(fn)
	local fh = io.open(fn,"r")
	local user = fh:read("*line")
	local pass = fh:read("*line")
	fh:close()
	return user, pass
end

function load_tlskeys(fn, key_ids)
	local function subkey(keys,id)
		local res = keys:sub(64*id+1,64*(id+1))
		return res:sub(1,20)
	end
	local fh = io.open(fn, "r")
	local go = false
	local buf = ""
	for line in fh:lines() do
		if line:find("-----BEGIN OpenVPN Static key V1-----") then
			go = true
		elseif line:find("-----") then
			break
		elseif go then
			buf = buf .. line
		end
	end
    fh:close()
    local keys = fromhex(buf)
    --print(#keys)
    assert(#keys == 256)
    local tx_idx, rx_idx = 3, 1
    if key_ids then
		tx_idx = key_ids[1], key_ids[2]
	end
    local txkey, rxkey = subkey(keys, tx_idx), subkey(keys, rx_idx)
    --print(tohex(txkey),"//",tohex(rxkey))
    return txkey, rxkey
end

--[[
data structures:

vpn: ovpn object
	- contains ctl socket, TLS params, TUN name

session: ovpn session
	- contains session IDs, TLS socket, key data
]]--

vpn = {}

function vpn:new(cfg, tun)
	local res = {}
	setmetatable(res, self)
	self.__index = self
	
	local tun_fd
	local txkey, rxkey = load_tlskeys(cfg.tlskeys, cfg.tlskeys_ids)

	res.ssl_params = {
		ca = readfile(cfg.cafile),
		txkey = txkey,
		rxkey = rxkey,
	}

	if cfg.key then
		res.ssl_params.key = readfile(cfg.key)
	end
	
	if cfg.certificate then
		res.ssl_params.certificate = readfile(cfg.certificate)
	end
	
	if cfg.auth then
		res.ssl_params.user, res.ssl_params.pass = load_auth(cfg.auth)
	end
	
	local drop_privs = true
	
	if posix.getuid == nil then
		local ph = io.popen("id","r")
		local myid = ph:read("*a")
		ph:close()
		drop_privs = myid:find("^uid=0") ~= nil
	else 	-- this needs a recent version of luaposix (>= 34.x)
		drop_privs = posix.getuid() == 0
	end

	if drop_privs then
		local chroot_en = false 	-- disable chroot for now - non-trivial to set up
		assert(drop_privileges(chroot_en)==chroot_en)
	end
	
	if tun then tun_fd = tun.fd end
	
	res.my_version = "V4,dev-type tun,link-mtu 1560,tun-mtu 1500,proto TCPv4_CLIENT,comp-lzo,keydir 1,cipher AES-256-CBC,auth SHA1,keysize 256,tls-auth,key-method 2,tls-client" .. string.char(0)
	
	local ovpn, ctl_fd = ovpn{tun_fd = tun_fd, tls_txkey = txkey, tls_rxkey = rxkey, ignore_hmac = cfg.ignore_hmac}
	
	res.ovpn = ovpn
	res.ctl_fd = ctl_fd
	res.ctl_csock = csock.fdopen(ctl_fd)
	
	if cfg.debug then
		ovpn:set_debug(cfg.debug)
	end
	
	if cfg.stats then
		ovpn:stats_enable(cfg.stats)
	end
	
	res.tun = tun
	if tun then
		print("TUN device:", res.tun.dev)
	end
	
	res.ca = x509.new(res.ssl_params.ca)
	res.castore = castore.new()
	res.castore:add(res.ca)
	
	res.ssl = ssl.new("TLSv1_2")
	res.ssl:setVerify(ssl.VERIFY_NONE)
	
	if cfg.certificate and cfg.key then
		res.ssl:setCertificate(x509.new(res.ssl_params.certificate))
		res.ssl:setPrivateKey(pkey.new(res.ssl_params.key))
	end

	-- also disable seccomp filters for now since the list of syscalls
	-- changes depending on library versions
	--seccomp_filter_syscalls(syscalls,SC_RET.ALLOW,SC_RET.TRAP)
	
	return res
end

function vpn:tls_start(line)
	local session = self.session
		
	local tls_local, tls_chains = csock.pair(csock.SOCK_STREAM)
	self.ovpn:set_tlssock(tls_chains:pollfd())
	if self.tls_sock then
		self.tls_sock:close()
		self.tls_chains:close()
	end
	self.tls_sock = tls_local
	self.tls_chains = tls_chains
	session.tls_sock = tls_local
	
	local succ, err = session.tls_sock:starttls(self.ssl)
	--print("cq handshake",succ, err)
	assert(succ)
	
	--dump_table(session.tls_sock)
	local ssl_ctx = session.tls_sock:checktls()
	assert(ssl_ctx)
	local peer_cert = ssl_ctx:getPeerCertificate()
	assert(peer_cert)
	local verified, err = self.castore:verify(peer_cert)
	assert(verified,err)
	
	session.my_sid, session.peer_sid = self.ovpn:get_sessionids()
	
	local my_prfd = {
		pre_master = rand.bytes(48),
		random1 = rand.bytes(32),
		random2 = rand.bytes(32),
	}
	
	session.my_prfd = my_prfd
	session.peer_prfd = nil
	
	local str = packint(0,4) .. string.char(2) .. my_prfd.pre_master .. my_prfd.random1 .. my_prfd.random2
	str = str .. packint(#self.my_version, 2) .. self.my_version
	
	-- for password authentication
	local ssl_params = self.ssl_params
	if ssl_params.user then
		local len = #ssl_params.user + 1
		str = str .. packint(len,2) .. ssl_params.user .. string.char(0)
		len = #ssl_params.pass + 1
		str = str .. packint(len,2) .. ssl_params.pass .. string.char(0)
	end
	--if self.debug then print("init: ", tohex(str)) end
	--session.tls_sock:send(str)
	session.tls_sock:setmode("bn","bn")
	session.tls_sock:send(str,1,#str)
	--session.tls_sock:settimeout(0)
	--print("tls_start")
end

local function tls1_P_hash(dn, secret, seed, olen)
	local A1 = seed
	local res = ""
	while #res < olen do
		A1 = hmac.new(secret, dn):final(A1)
		res = res .. hmac.new(secret, dn):final(A1..seed)
	end
	return res:sub(1,olen)
end

local function tls1_PRF(seed, secret, olen)
	local hlen = math.floor(#secret/2)
	local sh1 = secret:sub(1,hlen)
	local sh2 = secret:sub(hlen+1)
	--print("sec",tohex(secret,4))
	--print("seed",tohex(seed,4))
	local buf1 = tls1_P_hash("md5", sh1, seed, olen)
	local buf2 = tls1_P_hash("sha1", sh2, seed, olen)
	--print("PRF1",tohex(buf1,4))
	--print("PRF2",tohex(buf2,4))
	local obuf = ""
	for i=1,#buf1 do
		obuf = obuf .. string.char(bit32.bxor(buf1:byte(i), buf2:byte(i)))
	end
	return obuf
end

local function PRF(args)
	local client_sid = args.client_sid or ""
	local server_sid = args.server_sid or ""
	local buf = args.label .. args.client_seed .. args.server_seed .. client_sid .. server_sid
	return tls1_PRF(buf, args.secret, args.olen)
end

function vpn:keygen()
	local session = self.session
	local my_prfd = session.my_prfd
	local peer_prfd = session.peer_prfd
	local my_sid, peer_sid = session.my_sid, session.peer_sid
	local master_secret = PRF{
		secret = my_prfd.pre_master,
		label = "OpenVPN master secret",
		client_seed = my_prfd.random1,
		server_seed = peer_prfd.random1,
		olen = 48,
	}
	local keys = PRF{
		secret = master_secret,
		label = "OpenVPN key expansion",
		client_seed = my_prfd.random2,
		server_seed = peer_prfd.random2,
		client_sid = my_sid,
		server_sid = peer_sid,
		olen = 2*(64+64)
	}
	-- debug
	local buf = databuf:new(keys)
	--[[
	print("Master Encrypt (cipher)",tohex(buf:consume(64),4))
	print("Master Encrypt (hmac)",tohex(buf:consume(64),4))
	print("Master Decrypt (cipher)",tohex(buf:consume(64),4))
	print("Master Decrypt (hmac)",tohex(buf:consume(64),4))
	]]--
	return keys
end

local function read_key(data)
	local prfd = {}
	local buf = databuf:new(data)
	--print(tohex(buf:get()))
	local literal = unpackint(buf:consume(4))
	local key_version = unpackint(buf:consume(1))
	assert(literal == 0)
	assert(key_version == 2)
	prfd.random1 = buf:consume(32)
	prfd.random2 = buf:consume(32)
	local opts_len = unpackint(buf:consume(2))
	local opts = buf:consume(opts_len)
	--print("options",opts_len,#opts,opts)
	local user_len = unpackint(buf:consume(2))
	local user = buf:consume(user_len)
	local pass_len = unpackint(buf:consume(2))
	local pass = buf:consume(pass_len)
	local remaining = buf:consume()
	--print("remaining",#remaining,tohex(remaining))
	return prfd
end

function vpn:handle_tls()
	local session = self.session
	local part = session.tls_sock:read(-100000)
	if not part then return end
	--print("handle_tls")
	if not session.peer_prfd then
		session.peer_prfd = read_key(part)
		local keys = self:keygen()
		self.ovpn:set_keys(keys)
		if not session.tun_configured then
			local preq = "PUSH_REQUEST"..string.char(0)
			session.tls_sock:send(preq,1,#preq)
		else
			--print("cq cancel")
			session.tls_complete = true
			cqueues.cancel(session.tls_sock)
		end
	elseif part:find("PUSH_REPLY") and not session.tun_configured then
		print(printable(part))
		local ip = part:match("ifconfig (%d+%.%d+%.%d+%.%d+)")
		if self.tun then
			posix.write(self.tun.pipe,ip.."\n")
		end
		session.tun_configured = true
		session.tls_complete = true
		cqueues.cancel(session.tls_sock)
	end
end

function vpn:show_stats()
	local eb, ep, db, dp = self.ovpn:get_stats()
	eb = prettynum(eb, "B")
	ep = prettynum(ep, "pkts")
	db = prettynum(db, "B")
	dp = prettynum(dp, "pkts")
	print("encrypt",eb,ep,"decrypt",db,dp)
end

function vpn:handle_ctl()
	local line = self.ctl_csock:read(-10000)
	print(os.date("%c"),"CTL:",line)
	if line:find("TLS_START") then
		self:tls_start(line)
		self.session.tls_complete = false

		cq:wrap(function()
				while self.session and (not self.session.tls_complete) do
					self:handle_tls()
				end
			end)

	elseif line:find("DISCONNECT") then
		self.connected = false
		-- TODO: handle TLS socket close in C code
		self.session = nil
	end
	self:show_stats()
end

function vpn:handler()
	cq:wrap(function()
			while self.session do
				self:handle_ctl()
			end
		end)
	while not cq:empty() do
		local ok, err = cq:step()
		--print("STEP",ok,err);
		if not ok then error("cqueue: " .. err) end
	end
end

function vpn:connect(host, port)
	self.session = {}
	self.connected = self.ovpn:connect(host, port)
	if(self.connected) then
		self:handler()
	end
end

function ssl_preload()
	local a, b = csock.pair()
	-- do a dummy checktls so cqueues socket loads & keeps the ossl module
	-- otherwise first checktls fails after chroot
	a:checktls()
	a:close()
	b:close()
end

ssl_preload()

-- load config
local config = require(arg[1])
config.port = config.port or 1195

local tun = nil

if arg[2] ~= "notun" then
	local status, tun_fd, tun_dev = pcall(tun_create)
	if status then
		local tun_pipe, tun_pid = tun_fork(tun_dev, config.netmask, config.on_connected)
		tun = {
			fd = tun_fd,
			dev = tun_dev,
			pipe = tun_pipe,
			pid = tun_pid
		}
	end
end

local ip = lookup_ip(config.host)
local client = vpn:new(config, tun)

while true do
	print("connect...")
	client:connect(ip, config.port)
	sleep(1)
end
print("lua_finish")

if tun then
	posix.close(tun.pipe)
	posix.wait(tun.pid)
end
