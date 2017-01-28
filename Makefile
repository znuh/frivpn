
CC = gcc
CFLAGS = -Wall -g -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4

SOURCES = chains.c ovpn.c ovpn_crypto.c ovpn_tcp_src.c ovpn_filter.c \
	ovpn_lzo.c write_sink.c read_src.c ovpn_hmac.c mt_write_sink.c \
	ovpn_encap.c ovpn_ctl.c timer.c queue.c buffer.c copy.c
	
LIBS = -lpthread -lcrypto -llzo2

all:
	$(CC) $(CFLAGS) -shared -fPIC -o ovpn.so -I/usr/include/lua5.2 $(SOURCES) ovpn_lua.c $(LIBS) -llua5.2
	$(CC) $(CFLAGS) -shared -fPIC -o seccomp.so -I/usr/include/lua5.2 seccomp_lua.c -llua5.2

clean:
	rm -f *.o *.so

