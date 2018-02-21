# frivpn
A multi-threaded openvpn client (WIP)

With Raspberry Pis, ODROIDs and APUs becoming ubiquitous and cheap devices,
they are often used and configured as VPN gateways to the Internet. openvpn
can't use those devices to their full capacity, since it runs single-threaded
and quickly maxes out one CPU core due to the lack of hardware-accelerated
AES cryptography.

frivpn is multi-threaded and runs on multiple (all) CPU cores, which results
in the best possible VPN bandwidth and throughput.

| Device          | openvpn    | frivpn     |
| --------------- | :--------: | :--------: |
| APU.1D          | ~30 Mbit/s | ~60 Mbit/s |
| ODROID XU4      | ~24 Mbit/s | ~80 Mbit/s |
| Raspberry Pi 3  | ~?? Mbit/s | ~?? Mbit/s |

# Installation

## Dependencies

### Debian (stretch)

```
# apt install build-essential lua5.2 lua5.2-dev lua-posix lua-luaossl lua-cqueues libssl-dev liblzo2-dev
```

### Ubuntu 17.10

```
# apt install build-essential lua liblua5.2-dev lua-posix lua-luaossl lua-cqueues libssl-dev liblzo2-dev
```

## Build it

```
$ git clone https://github.com/znuh/frivpn.git
$ mkdir frivpn/build
$ cd frivpn/build
$ cmake ..
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
