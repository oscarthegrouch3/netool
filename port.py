from scapy.all import IP, TCP, UDP, sr1, RandShort, conf
from concurrent.futures import ThreadPoolExecutor, as_completed

conf.verb = 0

# Default ports for scan
default_ports = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888,
]

# Scan Types

def syn_scan(target, port, timeout=1.0):
    pkt = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)
    if resp is None:
        state = "filtered"
    elif resp.haslayer(TCP):
        state = "open" if resp[TCP].flags == 0x12 else "closed"
    else:
        state = "filtered"
    return {"port": port, "state": state}


def udp_scan(target, port, timeout=1.0):
    pkt = IP(dst=target) / UDP(sport=RandShort(), dport=port)
    resp = sr1(pkt, timeout=timeout)
    if resp is None:
        state = "open|filtered"
    elif resp.haslayer(UDP):
        state = "open"
    else:
        state = "closed"
    return {"port": port, "state": state}


def xmas_scan(target, port, timeout=1.0):
    pkt = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="FPU")
    resp = sr1(pkt, timeout=timeout)
    if resp is None:
        state = "open|filtered"
    elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
        state = "closed"
    else:
        state = "filtered"
    return {"port": port, "state": state}

scan_options = {"syn": syn_scan, "udp": udp_scan, "xmas": xmas_scan}

# Run scan with 
def run(target: str, scan: str, ports: list = None, timeout: float = 1.0, threads: int = 50) -> dict:
 
    if scan not in scan_options:
        raise ValueError(f"Invalid scan type '{scan}'. Choose from: {', '.join(scan_options)}")

    fn = scan_options[scan]
    ports = ports or default_ports
    results = {}

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(fn, target, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                r = fut.result()
                results[r["port"]] = r["state"]
            except Exception as e:
                results[futures[fut]] = f"error: {e}"

    return results

if __name__ == "__main__":
    target    = "192.168.1.1"
    scan = "syn"  # "syn", "udp", or "xmas"

    results = run(target, scan)
    print(results)