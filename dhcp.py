from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.sendrecv import sendp, sniff
from scapy.utils import mac2str
import subprocess
import logging

logger = logging.getLogger(__name__)

server_ip = "192.168.100.1"
subnet_mask = "255.255.255.0"

assigned = {}  # mac -> ip
ip_pool = []   # populated by generate_pool


def generate_pool(server_ip, count):
    prefix = ".".join(server_ip.split(".")[:3])
    return [f"{prefix}.{i}" for i in range(2, count + 2)]


def assign_ip(interface, server_ip, prefix=24):
    subprocess.run(["sudo", "ip", "addr", "add", f"{server_ip}/{prefix}", "dev", interface], check=True)
    subprocess.run(["sudo", "ip", "link", "set", interface, "up"], check=True)


def get_ip(mac):
    if mac in assigned:
        return assigned[mac]
    available = [ip for ip in ip_pool if ip not in assigned.values()]
    if not available:
        logger.error("IP pool exhausted")
        return None
    assigned[mac] = available[0]
    return assigned[mac]


def handle_dhcp(pkt):
    if DHCP not in pkt:
        return
    msg_type = next((opt[1] for opt in pkt[DHCP].options if opt[0] == "message-type"), None)
    if msg_type == 1:
        logger.info(f"DHCPDISCOVER from {pkt[Ether].src}")
        send_offer(pkt)
    elif msg_type == 3:
        logger.info(f"DHCPREQUEST from {pkt[Ether].src}")
        send_ack(pkt)


def build_base(pkt, offer_ip):
    mac = pkt[Ether].src
    xid = pkt[BOOTP].xid
    return (
        Ether(dst=mac) /
        IP(src=server_ip, dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr=offer_ip, siaddr=server_ip,
              chaddr=mac2str(mac), xid=xid)
    )


def send_offer(pkt):
    mac = pkt[Ether].src
    offer_ip = get_ip(mac)
    if not offer_ip:
        return
    offer = build_base(pkt, offer_ip) / DHCP(options=[
        ("message-type", "offer"),
        ("server_id", server_ip),
        ("lease_time", 86400),
        ("subnet_mask", subnet_mask),
        ("router", server_ip),
        "end"
    ])
    sendp(offer, iface=interface, verbose=False)


def send_ack(pkt):
    mac = pkt[Ether].src
    offer_ip = get_ip(mac)
    if not offer_ip:
        return
    ack = build_base(pkt, offer_ip) / DHCP(options=[
        ("message-type", "ack"),
        ("server_id", server_ip),
        ("lease_time", 86400),
        ("subnet_mask", subnet_mask),
        ("router", server_ip),
        "end"
    ])
    sendp(ack, iface=interface, verbose=False)


def dhcp_scan(interface, server_ip, count):
    global ip_pool
    ip_pool = generate_pool(server_ip, count)
    assign_ip(interface, server_ip)
    sniff(
        iface=interface,
        filter="udp and (port 67 or port 68)",
        prn=handle_dhcp,
        store=False,
        timeout=90,
    )


if __name__ == "__main__":
    interface = "wlp0s20f3"  # interface
    devices = 3  # number of devices to connect
    dhcp_scan(interface, server_ip, devices)