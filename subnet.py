from scapy.all import ARP, Ether, srp
from scapy.data import MANUFDB
import socket

def subnet_scan(subnet):
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=5, retry=3, verbose=False)
    hosts = {}

    for _, rcv in answered:
        vendor = MANUFDB.lookup(rcv.hwsrc)
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
    result = subnet_scan("192.168.200.26/24")
    print(result)