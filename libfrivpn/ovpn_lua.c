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

#define _GNU_SOURCE
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>
#include <grp.h>
#include "ovpn.h"

static int tun_open(char *dev) {
  struct ifreq ifr;
  int fd, err, flags = IFF_TUN | IFF_NO_PI;

   /* open the clone device */
   if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
	 return fd;
   }

   /* preparation of the struct ifr, of type "struct ifreq" */
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = flags;   /* IFF_TUN or IFF_TAP, plus maybe IFF_NO_PI */

   if (dev && dev[0]) {
	 /* if a device name was specified, put it in the structure; otherwise,
	  * the kernel will try to allocate the "next" device of the
	  * specified type */
	 strncpy(ifr.ifr_name, dev, IFNAMSIZ);
   }

   /* try to create the device */
   if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ) {
	 close(fd);
	 return err;
   }

   fd_nonblock(fd);

   if (dev)
	strcpy(dev, ifr.ifr_name);

  return fd;
}

static int drop_privileges(lua_State *L) {
	int res, jailed = 0;

	/* getaddrinfo needs resolv access, so we make chroot optional */
	if(lua_toboolean(L, 1)) {
		res = chdir("/var/jail");
		if(!res) {
			res = chroot(".");
			if(!res)
				jailed = 1;
		}
	}

	if(!jailed) {
		res = chdir("/");
		if(res)
			luaL_error(L, "chdir / failed");
	}

	res = setgroups(0, NULL);
	if(res)
		luaL_error(L, "drop groups failed");
	res = setresgid(65534, 65534, 65534);
	if(res)
		luaL_error(L, "drop gids failed");
	res = setresuid(65534, 65534, 65534);
	if(res)
		luaL_error(L, "drop uids failed");
	lua_pushboolean(L, jailed);
	return 1;
}

static int maketun(lua_State *L) {
	char tundev[IFNAMSIZ] = "";
	int fd = tun_open(tundev);

	if(fd < 0)
		luaL_error(L, "TUN create failed");
	lua_pushnumber(L, fd);
	lua_pushstring(L, tundev);
	return 2;
}

static ovpn_t *gethandle(lua_State *L)
{
	return *((ovpn_t**)luaL_checkudata(L,1,"ovpn"));
}

static int delete(lua_State *L)
{
	ovpn_t *ctx = gethandle(L);
	ovpn_finish(ctx);
	lua_pushnil(L);
	lua_setmetatable(L,1);
	return 0;
}

static coremap_t *get_cpucores(lua_State *L, int index, cpu_set_t *mask)
{
	coremap_t *coremap = NULL;
	
	if(!mask) {
		coremap = calloc(1,sizeof(coremap_t));
		coremap->n_entries = lua_rawlen(L, index);
		coremap->masks = calloc(coremap->n_entries, sizeof(cpu_set_t));
		coremap->cpusetsize = CPU_SETSIZE;
		// printf("%d entries\n",coremap->n_entries);
	}
	else {
		CPU_ZERO(mask);
	}

	/* about 80% of the following code has been stolen from https://stackoverflow.com/a/6142700 */

    lua_pushvalue(L, index);
    // stack now contains: -1 => table
    lua_pushnil(L);
    // stack now contains: -1 => nil; -2 => table
    while (lua_next(L, -2)) {
        // stack now contains: -1 => value; -2 => key; -3 => table
        // copy the key so that lua_tostring does not modify the original
        lua_pushvalue(L, -2);
        // stack now contains: -1 => key; -2 => value; -3 => key; -4 => table
        //const char *key = lua_tostring(L, -1);
        int key = lua_tonumber(L, -1);
        // printf("key: %d\n",key);
        if((!mask) && (lua_istable(L, -2)) && (key > 0) && (key <= coremap->n_entries))
			get_cpucores(L, -2, &coremap->masks[key-1]);
		else if ((mask) && lua_isnumber(L, -2)) {
			int core_id = lua_tonumber(L, -2);
			if(core_id < CPU_SETSIZE)
				CPU_SET(core_id, mask);
		}
        // pop value + copy of key, leaving original key
        lua_pop(L, 2);
        // stack now contains: -1 => key; -2 => table
    }
    // stack now contains: -1 => table (when lua_next returns 0 it pops the key
    // but does not push anything.)
    // Pop table
    lua_pop(L, 1);
	 
	return coremap;
}

static int ovpn_create(lua_State *L)
{
	ovpn_t *ctx = NULL;
	int tun_fd = -1;
	coremap_t *cpu_cores = NULL;
	const char *tls_txkey = NULL, *tls_rxkey = NULL;
	size_t keysize;
	uint32_t flags=0;

	lua_settop(L, 1);
	luaL_checktype(L, 1, LUA_TTABLE);

	lua_getfield(L, 1, "tun_fd");
	lua_getfield(L, 1, "tls_txkey");
	lua_getfield(L, 1, "tls_rxkey");
	lua_getfield(L, 1, "ignore_hmac");
	lua_getfield(L, 1, "cpu_affinity");

	if(lua_isnumber(L, -5))
		tun_fd = lua_tonumber(L, -5);

	tls_txkey = luaL_checklstring(L, -4, &keysize);
	if(keysize != 20) {
		luaL_error(L, "invalid TLS keysize");
	}

	tls_rxkey = luaL_checklstring(L, -3, &keysize);
	if(keysize != 20) {
		luaL_error(L, "invalid TLS keysize");
	}

	if(lua_isboolean(L, -2))
		flags |= lua_toboolean(L, -2) ? OVPN_IGNORE_HMAC : 0;

	if(lua_istable(L, -1))
		cpu_cores = get_cpucores(L, -1, NULL);

	ctx = ovpn_init(tun_fd, flags, cpu_cores);
	if(!ctx) {
		luaL_error(L, "cannot create ovpn ctx");
	}
	else {
		ovpn_t **p;
		ovpn_ctl_config(ctx, (const uint8_t *)tls_txkey, (const uint8_t *)tls_rxkey);
		lua_pop(L, 5);
		p=lua_newuserdata(L,sizeof(ovpn_t*));
		*p=ctx;
		lua_pushvalue(L, lua_upvalueindex(1));
		lua_setmetatable(L, -2);
		lua_pushnumber(L, ovpn_ctl_getsock(ctx));
		return 2;
	}

	return 0;
}

static int get_sessionids(lua_State *L) {
	ovpn_t *ovpn = gethandle(L);
	struct ctl_s *ctl = &ovpn->ctl;
	pthread_mutex_lock(&ctl->state_mtx);
	lua_pushlstring(L, (const char*) &ctl->tx_state.session_id, sizeof(uint64_t));
	lua_pushlstring(L, (const char*) &ctl->rx_state.session_id, sizeof(uint64_t));
	pthread_mutex_unlock(&ctl->state_mtx);
	return 2;
}

static int get_stats(lua_State *L) {
	ovpn_t *ovpn = gethandle(L);
	struct crypto_s *crypto = &ovpn->ctl.crypto;
	struct crypto_stats_s enc_stats, dec_stats;

	//pthread_mutex_lock(&crypto->mtx);

	enc_stats = crypto->enc_stats;
	dec_stats = crypto->dec_stats;

	//pthread_mutex_unlock(&crypto->mtx);

	lua_pushnumber(L, enc_stats.bytes);
	lua_pushnumber(L, enc_stats.packets);

	lua_pushnumber(L, dec_stats.bytes);
	lua_pushnumber(L, dec_stats.packets);

	return 4;
}

static int set_keys(lua_State *L) {
	ovpn_t *ovpn = gethandle(L);
	size_t len=0;
	const char *keys = lua_tolstring(L, 2, &len);
	assert(len == (64*4));
	ovpn_ctl_setkeys(ovpn, (const uint8_t *) keys);
	return 0;
}

static int set_tlssock(lua_State *L) {
	ovpn_t *ovpn = gethandle(L);
	struct ctl_s *ctl = &ovpn->ctl;
	int old, fd = -1;

	if(lua_isnumber(L, 2))
		fd = lua_tonumber(L, 2);

	if(ctl->debug)
		printf("set_tlssock %d\n",fd);

	//ctl->tls_sock = fd;
	fd_nonblock(fd);

	node_setfd(ovpn->chains, ctl->tls_write, fd);
	old = ctl->tls_read->fd;
	node_setfd(ovpn->chains, ctl->tls_read, dup(fd));
	if(old >= 0)
		close(old);

	return 0;
}

static int set_debug(lua_State *L) {
	ovpn_t *ovpn = gethandle(L);
	struct ctl_s *ctl = &ovpn->ctl;
	uint32_t debug = 0;

	if(lua_isnumber(L, 2))
		debug = lua_tonumber(L, 2);

	ovpn->chains->debug = debug&0xff;
	ctl->debug = (debug>>8)&0xff;

	return 0;
}

static int stats_enable(lua_State *L) {
	ovpn_t *ovpn = gethandle(L);
	chains_t *chains = ovpn->chains;
	int stats = 0;

	if(lua_isboolean(L, 2))
		stats = lua_toboolean(L, 2);

	if(stats)
		chains->flags |= CHAINS_STATS_EN;
	else
		chains->flags &= ~CHAINS_STATS_EN;

	return 0;
}

static int connect_ovpn(lua_State *L)
{
	ovpn_t *ovpn = gethandle(L);
	const char *peer = NULL;
	int port, res;

	peer = lua_tostring(L, 2);
	port = lua_tonumber(L, 3);
	res = ovpn_connect(ovpn, peer, port);
	if(res < 0)
		return 0;

	lua_pushboolean(L, 1);
	return 1;
}

static const luaL_Reg R[] =
{
	{ "__gc",			delete },
	{ "connect",		connect_ovpn },
	{ "get_sessionids",	get_sessionids },
	{ "set_keys",		set_keys },
	{ "set_tlssock",	set_tlssock },
	{ "set_debug",		set_debug },
	{ "stats_enable",	stats_enable },
	{ "get_stats",		get_stats },
	{ NULL,				NULL }
};

LUALIB_API int luaopen_libfrivpn(lua_State *L)
{
	lua_register(L, "tun_create", maketun);
	lua_register(L, "drop_privileges", drop_privileges);

	luaL_newmetatable(L,"ovpn");
	lua_pushnil(L);
	lua_setmetatable(L, -2);
	lua_pushvalue(L, -1);
	lua_setfield(L, -1, "__index");
	luaL_setfuncs(L, R, 0);
	lua_pushcclosure(L, ovpn_create, 1);
	lua_setglobal(L, "ovpn");
	return 1;
}
