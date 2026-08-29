import socket
import asyncio
import logging
import os
import requests
from scapy.all import IP, TCP, UDP, sr1, RandShort, conf
from concurrent.futures import ThreadPoolExecutor, as_completed
from asyncio import Semaphore

logger = logging.getLogger(__name__)

conf.verb = 0
# Create a Semaphore to prevent OS socket exhaustion and target-side rate limiting
MAX_CONCURRENT_SCANS = 500
scan_semaphore = Semaphore(MAX_CONCURRENT_SCANS)
NMAP_SERVICES_FILE = "data/nmap-services"

def load_nmap_services(top_n: int = 1000, protocol: str = "tcp") -> list:
    """
    Parses nmap-services file to get the top N most frequent ports for a given protocol.
    Format: Service name, portnum/protocol, open-frequency, optional comments
    """
    ports = []
    try:
        if not os.path.exists(NMAP_SERVICES_FILE):
            logger.error(f"Nmap services file not found: {NMAP_SERVICES_FILE}")
            return []

        with open(NMAP_SERVICES_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                parts = line.split()
                if len(parts) < 3:
                    continue
                
                # parts[1] is portnum/protocol (e.g., "22/tcp")
                port_proto = parts[1].split('/')
                if len(port_proto) != 2:
                    continue
                
                p_num, p_proto = port_proto
                freq = parts[2]
                
                if p_proto.lower() == protocol.lower():
                    try:
                        ports.append((int(p_num), float(freq)))
                    except ValueError:
                        continue
        
        # Sort by frequency descending
        ports.sort(key=lambda x: x[1], reverse=True)
        return [p[0] for p in ports[:top_n]]
        
    except Exception as e:
        logger.exception(f"Error loading nmap services: {e}")
        return []

def fetch_remote_wordlist(url: str) -> list:
def load_ports_from_file(filepath: str) -> list:
    """
    Reads ports from a file. Supports one port per line or comma-separated.
    """
    ports = []
    try:
        if not os.path.exists(filepath):
            logger.error(f"Wordlist file not found: {filepath}")
            return []

        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                if ',' in line:
                    for p in line.split(','):
                        try:
                            ports.append(int(p.strip()))
                        except ValueError:
                            continue
                else:
                    try:
                        ports.append(int(line))
                    except ValueError:
                        logger.warning(f"Skipping invalid port value: {line}")
        
        return sorted(list(set(ports)))
    except Exception as e:
        logger.exception(f"Error reading port wordlist: {e}")
        return []

async def async_tcp_scan(target, port, timeout=1.0):
    """Fast TCP scan using asyncio and native sockets."""
    try:
        conn = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        await writer.wait_closed()
        return {"port": port, "state": "open"}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return {"port": port, "state": "closed|filtered"}
    except Exception as e:
        logger.error(f"Error scanning port {port}: {e}")
        return {"port": port, "state": "error"}

def syn_scan(target, port, timeout=1.0):
    """Scapy stealth SYN scans"""
    pkt = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        state = "filtered"
    elif resp.haslayer(TCP):
        state = "open" if resp[TCP].flags == 0x12 else "closed"
    else:
        state = "filtered"
    return {"port": port, "state": state}

def udp_scan(target, port, timeout=1.0):
    pkt = IP(dst=target) / UDP(sport=RandShort(), dport=port)
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        state = "open|filtered"
    elif resp.haslayer(UDP):
        state = "open"
    else:
        state = "closed"
    return {"port": port, "state": state}

def xmas_scan(target, port, timeout=1.0):
    pkt = IP(dst=target) / TCP(sport=RandShort(), dport=port, flags="FPU")
    resp = sr1(pkt, timeout=timeout, verbose=0)
    if resp is None:
        state = "open|filtered"
    elif resp.haslayer(TCP) and resp[TCP].flags == 0x14:
        state = "closed"
    else:
        state = "filtered"
    return {"port": port, "state": state}

scan_options = {
    "tcp": "async", 
    "syn": syn_scan, 
    "udp": udp_scan, 
    "xmas": xmas_scan
}

async def wrapped_scan(fn, target, port, timeout):
    """Wraps both sync and async scan functions with a semaphore to control concurrency."""
    async with scan_semaphore:
        if asyncio.iscoroutinefunction(fn):
            return await fn(target, port, timeout)
        else:
            # Run synchronous Scapy functions in a separate thread to avoid blocking the event loop
            return await asyncio.to_thread(fn, target, port, timeout)

async def run_optimized_scan(target, ports, timeout, scan_type):
    """Unified async runner for all scan types."""
    fn = scan_options[scan_type]
    
    # Handle the 'async' placeholder for TCP scans
    if scan_type == "tcp":
        fn = async_tcp_scan

    tasks = [wrapped_scan(fn, target, p, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    
    # Format results into the expected dictionary {port: state}
    return {r["port"]: r["state"] for r in results}

def port_scan(target: str, scan: str, ports: list = None, timeout: float = 1.0, threads: int = 50) -> dict:
    if scan not in scan_options:
        raise ValueError(f"Invalid scan type '{scan}'. Choose from: {', '.join(scan_options.keys())}")

    ports = ports or DEFAULT_PORTS
    
    try:
        # All scan types now go through the optimized async pipeline
        return asyncio.run(run_optimized_scan(target, ports, timeout, scan))
    except Exception as e:
        logger.exception(f"Fatal error during port scan: {e}")
        return {}

if __name__ == "__main__":
    target = "127.0.0.1"
    scan = "tcp"
    print(port_scan(target, scan))
