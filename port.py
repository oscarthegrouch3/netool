"""
Scapy Port Scanner
Run as root/administrator for raw socket access.
"""

from scapy.all import IP, TCP, UDP, sr1, RandShort, conf
from concurrent.futures import ThreadPoolExecutor, as_completed

conf.verb = 0

COMMON_PORTS = [
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


SCANS = {"syn": syn_scan, "udp": udp_scan, "xmas": xmas_scan}

# Runner

def run_scan(target: str, scan_type: str, ports: list = None, timeout: float = 1.0, threads: int = 50) -> dict:
    """
    Scan a target and return {port: state} dict.

    Args:
        target:    IP address or hostname
        scan_type: "syn", "udp", or "xmas"
        ports:     list of ints (defaults to COMMON_PORTS)
        timeout:   seconds per probe
        threads:   max concurrent threads
    """
    if scan_type not in SCANS:
        raise ValueError(f"Invalid scan type '{scan_type}'. Choose from: {', '.join(SCANS)}")

    fn = SCANS[scan_type]
    ports = ports or COMMON_PORTS
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


# Entry Point

if __name__ == "__main__":
    target    = "192.168.1.1"
    scan_type = "syn"           # "syn", "udp", or "xmas"

    results = run_scan(target, scan_type)
    print(results)