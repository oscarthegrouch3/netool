# Look up on local network
# Get device information e.g MAC, Device Manufacture and online device


from scapy.all import ARP, Ether, srp
from scapy.data import MANUFDB

def subnet_scan(subnet):
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet), timeout=5, retry=3, verbose=False)
    hosts = {}

    for _, rcv in answered:
        vendor = MANUFDB.lookup(rcv.hwsrc)
        hosts[rcv.psrc] = {"mac": rcv.hwsrc, "vendor": vendor}

    
    return hosts


if __name__ == "__main__":
    result = subnet_scan("192.168.200.26/24")
    print(result)