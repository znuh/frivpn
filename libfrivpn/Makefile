
CC = gcc
CFLAGS = -Wall -g -fPIE -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fwrapv --param ssp-buffer-size=4

SOURCES = chains.c ovpn.c ovpn_crypto.c ovpn_tcp_src.c ovpn_filter.c \
	ovpn_lzo.c write_sink.c read_src.c ovpn_hmac.c \
	ovpn_encap.c ovpn_ctl.c timer.c queue.c buffer.c ovpn_lua.c

OBJECTS = $(patsubst %.c, %.o, $(SOURCES))
TARGETS = seccomp.so ovpn.so

LIBS = -lpthread -lcrypto -llzo2 -llua5.2
INCLUDES = -I/usr/include/lua5.2

all: $(TARGETS)

%.o:%.c
	$(CC) $(CFLAGS) -shared -fPIC -c -o $@ $< $(INCLUDES)

ovpn.so: $(OBJECTS)
	$(CC) $(CFLAGS) -shared -fPIC -o ovpn.so $(OBJECTS) $(LIBS)

seccomp.so:
	$(CC) $(CFLAGS) -shared -fPIC -o seccomp.so seccomp_lua.c $(INCLUDES) $(LIBS)

clean:
	rm -f $(OBJECTS) $(TARGETS)

