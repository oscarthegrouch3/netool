# Netool

A python network toolkit built with Scapy and psutil

- network — show interface info (IP, MAC, netmask, broadcast)
- interfaces — list active network interfaces
- port — port scan a target (SYN, UDP, or Xmas)
- vlan — detect switch/port/VLAN via CDP
- dhcp — run a test DHCP server

## Requirements

pip install scapy psutil

Python 3.8+. `port`, `subnet`, `vlan`, and `dhcp` need root/admin (raw sockets).

## Usage

```bash
python3 main.py -h
python3 main.py <command> -h
```

### network

```bash
python3 main.py network -i wlp0s20f3
```
- `-i, --interface` — interface name (required)

### interfaces

```bash
python3 main.py interfaces
```
Lists all network interfaces that are currently UP.

### port

sudo python3 main.py port 192.168.1.1 -s syn -p 22,80,443

- `target` — IP or hostname (required)
- `-s, --scan` — `syn`, `udp`, or `xmas` (default: `syn`)
- `-p, --ports` — comma-separated ports/ranges, e.g. `22,80,1000-1010` (default: common ports)
- `-t, --timeout` — per-port timeout in seconds (default: `1.0`)
- `-w, --threads` — worker threads (default: `50`)

### vlan
sudo python3 main.py vlan -i eth0 -t 60

- `-i, --interface` — interface name (required)
- `-t, --timeout` — seconds to wait for a CDP packet (default: `60`)

### dhcp
sudo python3 main.py dhcp -i wlp0s20f3 -s 192.168.100.1 -c 5

- `-i, --interface` — interface to bind/listen on (required)
- `-s, --server-ip` — DHCP server IP (default: `192.168.100.1`)
- `-c, --count` — number of leases in pool (default: `3`)
