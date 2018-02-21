cmake_minimum_required(VERSION 2.8.10)
project(frivpn)

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules)

find_package(Threads)
find_package(OpenSSL REQUIRED)
find_package(Lua REQUIRED)
find_package(LZO REQUIRED)

#set(CMAKE_BUILD_TYPE DEBUG)
set(CMAKE_C_FLAGS "-Wall -fPIE -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4")

set(FRIVPN_SOURCES chains.c ovpn.c ovpn_crypto.c ovpn_tcp_src.c ovpn_filter.c
	ovpn_lzo.c write_sink.c read_src.c ovpn_hmac.c ovpn_encap.c ovpn_ctl.c
    timer.c queue.c buffer.c ovpn_lua.c)

set(SECCOMP_SOURCES seccomp_lua.c)

include_directories(${LUA_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${LZO_INCLUDE_DIR})

add_library(frivpn SHARED ${FRIVPN_SOURCES})
target_include_directories(frivpn PUBLIC ${LUA_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${LZO_INCLUDE_DIR})
target_link_libraries(frivpn ${CMAKE_THREAD_LIBS_INIT} ${LUA_LIBRARIES} ${OPENSSL_LIBRARIES} ${LZO_LIBRARIES})

add_library(seccomp SHARED ${SECCOMP_SOURCES})
target_include_directories(seccomp PRIVATE ${LUA_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR} ${LZO_INCLUDE_DIR})
target_link_libraries(seccomp ${CMAKE_THREAD_LIBS_INIT} ${LUA_LIBRARIES} ${OPENSSL_LIBRARIES} ${LZO_LIBRARIES})
