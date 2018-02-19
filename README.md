# frivpn
A multithreaded openvpn client (WIP)

# Installation

## Debian (stretch)

```
apt install build-essential lua5.2 lua5.2-dev lua-posix lua-luaossl lua-cqueues libssl-dev liblzo2-dev
git clone https://github.com/znuh/frivpn.git
cd frivpn
make
```

# Run it

The ovpn_client expects a lua config module as the first parameter. There is an
ipredator config provided as an example.

```
lua ovpn_client.lua ipredator
```
