from scapy.all import ARP, Ether, srp
from scapy.data import MANUFDB
import socket
import ipaddress
import psutil


def subnet_scan(interface):
    for addr in psutil.net_if_addrs().get(interface, []):
        if addr.family == 2:
            ip, netmask = addr.address, addr.netmask
            break
    else:
        return {}

    subnet = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)

    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet)),
                      timeout=5, retry=3, verbose=False, iface=interface)

    hosts = {}
    for _, rcv in answered:

        vendor = MANUFDB.lookup(rcv.hwsrc)[1]
        if vendor == rcv.hwsrc:
            vendor = None

        try:
            hostname = socket.gethostbyaddr(rcv.psrc)[0]
        except socket.herror:
            hostname = None
        hosts[rcv.psrc] = {
            "mac":      rcv.hwsrc,
            "vendor":   vendor,
            "hostname": hostname,
        }

    return hosts


if __name__ == "__main__":
    result = subnet_scan("wlp0s20f3")
    print(result)