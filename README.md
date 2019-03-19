# frivpn
A multi-threaded OpenVPN client (WIP)

With Raspberry Pis, ODROIDs and APUs becoming ubiquitous and cheap devices,
they are often used and configured as VPN gateways to the Internet. OpenVPN
can't use those devices to their full capacity, since it runs single-threaded
and quickly maxes out one CPU core due to the lack of hardware-accelerated
AES cryptography.

frivpn is multi-threaded and runs on multiple (all) CPU cores, which results
in the best possible VPN bandwidth and throughput.

| Device          | OpenVPN    | frivpn     | Comment                         |
| --------------- | :--------: | :--------: | ------------------------------- |
| APU.1D          | ~30 Mbit/s | ~60 Mbit/s | DualCore 1GHz AMD G series T40E |
| ODROID XU4      | ~24 Mbit/s | ~170 Mbit/s | QuadCore 2GHz Cortex-A15        |
| Raspberry Pi 3  | ~20 Mbit/s | ~?? Mbit/s | QuadCore 1.2GHz Cortex-A53      |
| Raspberry Pi 2  | ~15 Mbit/s | ~?? Mbit/s | QuadCore 900MHz Cortex-A7       |

# Installation

## Packages

#### ArchLinux

```
# yaourt -S frivpn-git
```

## From Source

### Dependencies

#### Debian (stretch)

```
# apt install build-essential cmake lua5.2 lua5.2-dev lua-posix lua-luaossl \
              lua-cqueues lua-socket libssl-dev liblzo2-dev
```

#### Ubuntu 17.10 (artful)

```
# apt install build-essential cmake lua liblua5.2-dev lua-posix lua-luaossl \
              lua-cqueues libssl-dev liblzo2-dev
```

#### ArchLinux

```
# yaourt -S cmake lua lua-posix lua-luaossl lua-cqueues openssl lzo
```

### Build it

```
$ git clone https://github.com/znuh/frivpn.git
$ mkdir frivpn/build
$ cd frivpn/build
$ cmake ..
$ make
```

# Run it

The frivpn_client expects a config as the first parameter. See the
[configs](https://github.com/znuh/frivpn/tree/master/configs) directory for
configuration examples.

```
$ ./frivpn_client.lua configs/ipredator
```

# Troubleshooting & Caveats

While frivpn is generally compatible with any OpenVPN server, it (currently)
requires the server to be configured in the following way:

- TCP protocol (no UDP support as of now)
- Server cert, but no client certs
- Username & password auth
- tls-auth enabled
- comp-lzo enabled
- cipher AES-256-CBC
- auth SHA1

Found an OpenVPN-compatible service that doesn't work with frivpn yet?
Open an issue and let us know!
