# frivpn
A multithreaded openvpn client (WIP)

# Installation

## Debian (stretch)

```
# apt install build-essential lua5.2 lua5.2-dev lua-posix lua-luaossl lua-cqueues libssl-dev liblzo2-dev
$ git clone https://github.com/znuh/frivpn.git
$ cd frivpn
$ make
```

# Run it

The ovpn_client expects a config as the first parameter. See the
[configs](https://github.com/znuh/frivpn/tree/master/configs) directory for
configuration examples.

```
$ lua ovpn_client.lua configs/ipredator
```

# Troubleshooting & Caveats

While frivpn is generally compatible with any openvpn server, it (currently)
requires the server to be configured in the following way:

- TCP protocol (no UDP support as of now)
- Server cert, but no client certs
- Username & password auth
- tls-auth enabled
- comp-lzo enabled
- cipher AES-256-CBC
