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
#include <sys/prctl.h>
#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include <lua.h>
#include <lauxlib.h>

#include <arpa/inet.h>
#include <string.h>
#include <alloca.h>

#if defined(__i386__)
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR	AUDIT_ARCH_X86_64
#elif defined(__arm__)
# define ARCH_NR	AUDIT_ARCH_ARM
#else
# error "Platform does not support seccomp filter yet"
#endif

static int seccomp_getarch(lua_State *L) {
	lua_pushnumber(L, ARCH_NR);
	return 1;
}

static int seccomp_init_done = 0;

static int seccomp_filter(lua_State *L) {
	struct sock_filter *filter = NULL, *fp=NULL;
	struct sock_fprog prog;
	size_t n_entries=0;
	int idx, res;

	lua_settop(L, 1);
	luaL_checktype(L, 1, LUA_TTABLE);
	n_entries = lua_rawlen(L, 1);

	filter = alloca(sizeof(struct sock_filter) * n_entries);
	if(!filter) {
		luaL_error(L, "alloca failed");
		return 0;
	}
	memset(filter, 0, sizeof(struct sock_filter) * n_entries);

	lua_pushnil(L);  /* first key */
	for (idx=0,fp=filter; lua_next(L, 1); idx++,fp++) {
		size_t entry_len=0;
		const struct sock_filter *entry = (const struct sock_filter *) luaL_checklstring(L, -1, &entry_len);

		if(idx >= n_entries) {
			luaL_error(L, "filter index error");
			return 0;
		}

		if(entry_len != sizeof(struct sock_filter))
			luaL_error(L, "invalid filter size");

		*fp = *entry;
		fp->code = ntohs(fp->code);
		fp->k = ntohl(fp->k);

	   /* removes 'value'; keeps 'key' for next iteration */
	   lua_pop(L, 1);
	}

	if(idx != n_entries) {
		luaL_error(L, "filter index error");
		return 0;
	}

	prog.filter = filter;
	prog.len = n_entries;

	if(!seccomp_init_done) {
		res = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		if(res < 0)
			luaL_error(L, "PR_SET_NO_NEW_PRIVS failed");
		seccomp_init_done = 1;
	}

	res = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
	if(res < 0)
		luaL_error(L, "PR_SET_SECCOMP failed");

	return 0;
}

LUALIB_API int luaopen_libfrivpn_seccomp(lua_State *L)
{
	lua_register(L, "seccomp_filter", seccomp_filter);
	lua_register(L, "seccomp_arch", seccomp_getarch);
	return 0;
}
