import logging
import socket
from scapy.all import ICMP, IP, ARP, Ether, srp, sr1, conf
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Disable Scapy verbose output
conf.verb = 0

def ping_sweep(subnet: str):
    """
    Performs a ping sweep across the specified subnet.
    Example subnet: '192.168.1.0/24'
    """
    logger.info(f"Starting ping sweep on {subnet}...")
    online_hosts = []
    
    try:
        import ipaddress
        network = ipaddress.ip_network(subnet, strict=False)
        
        for ip in network.hosts():
            pkt = IP(dst=str(ip))/ICMP()
            reply = sr1(pkt, timeout=0.2)
            if reply:
                online_hosts.append(str(ip))
                logger.info(f"Host {ip} is online")
                
    except Exception as e:
        logger.error(f"Error during ping sweep: {e}")
        
    return online_hosts

def arp_scan(subnet: str):
    """
    Performs an ARP scan to identify local devices and their MAC addresses.
    Returns a list of dictionaries containing IP and MAC.
    """
    logger.info(f"Starting ARP scan on {subnet}...")
    devices = []
    
    try:
        # Create an Ethernet broadcast packet combined with an ARP request
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        
        # srp = send and receive packets at layer 2
        answered, _ = srp(arp_request, timeout=2, verbose=False)
        
        for sent, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc
            })
            logger.info(f"Found device: IP={received.psrc}, MAC={received.hwsrc}")
            
    except Exception as e:
        logger.error(f"Error during ARP scan: {e}")
        
    return devices

def get_mac_vendor(mac: str):
    """
    Looks up the MAC address vendor using a public API.
    """
    try:
        # Using macvendors.com API
        response = requests.get(f"https://api.macvendors.com/{mac}", timeout=3)
        if response.status_code == 200:
            return response.text
        else:
            return "Unknown Vendor"
    except Exception as e:
        logger.warning(f"Could not lookup vendor for {mac}: {e}")
        return "Lookup Error"

def scan_subnet(subnet: str):
    """
    Full scan combining ARP and Vendor lookup.
    """
    results = []
    # ARP is more reliable for local networks than Ping
    devices = arp_scan(subnet)
    
    for device in devices:
        vendor = get_mac_vendor(device["mac"])
        results.append({
            "ip": device["ip"],
            "mac": device["mac"],
            "vendor": vendor
        })
        
    return results

if __name__ == "__main__":
    # Example usage: change to your actual subnet
    import network as net
    import interface as iface
    
    # Try to automatically detect an active interface and its subnet
    active_interfaces = iface.list_interfaces()
    if active_interfaces:
        target_iface = active_interfaces[0]
        net_info = net.network_scan(target_iface)
        
        if "ipv4" in net_info and net_info["ipv4"]:
            # Convert IP and Netmask to CIDR subnet
            import ipaddress
            ip = ipaddress.ip_interface(f"{net_info['ipv4']}/{net_info['netmask']}")
            target_subnet = str(ip.network)
            
            print(f"Detected interface {target_iface} with subnet {target_subnet}")
            print(f"Scanning subnet {target_subnet}...")
            found_devices = scan_subnet(target_subnet)
            
            print("\nScan Results:")
            print(f"{'IP Address':<15} {'MAC Address':<20} {'Vendor'}")
            print("-" * 50)
            for dev in found_devices:
                print(f"{dev['ip']:<15} {dev['mac']:<20} {dev['vendor']}")
        else:
            print("Could not detect IPv4 address for the interface.")
    else:
        print("No active interfaces found.")
