import psutil
import socket

# Basic network information e.g MAC, ipv4, ipv6, and broadcast
def network_scan(interface: str) -> dict:
    addrs = psutil.net_if_addrs().get(interface)

    # Check for selected interface
    if not addrs:
        return {"error": f"Interface '{interface}' not found"}

    info = {
        "ipv4": None,
        "ipv6": None,
        "mac": None,
        "netmask": None,
        "broadcast": None,
    }

    # Loop through addr values to add to info dictionary
    for addr in addrs:
        if addr.family == socket.AF_INET:
            info["ipv4"]      = addr.address
            info["netmask"]   = addr.netmask
            info["broadcast"] = addr.broadcast

        elif addr.family == socket.AF_INET6:
            info["ipv6"] = addr.address

        elif addr.family == psutil.AF_LINK:
            info["mac"] = addr.address

    return info


if __name__ == "__main__":
    interface = ""  # change to your interface, e.g. "Wi-Fi", "en0", "ens33"
    result = network_scan(interface)