from scapy.all import sniff, load_contrib  # type: ignore
from scapy.contrib.cdp import (  # type: ignore
    CDPMsgDeviceID,
    CDPMsgPortID,
    CDPMsgNativeVLAN,
    CDPAddrRecordIPv4,
    CDPMsgPlatform,
    CDPMsgDuplex,
    CDPMsgVTPMgmtDomain,
)
import logging

logger = logging.getLogger(__name__)

"""
Load CDP dissector
"""
load_contrib("cdp")

def capture(interface: str, timeout: int = 60):
    try:
        packets = sniff(count=1, iface=interface, filter="ether host 01:00:0c:cc:cc:cc", timeout=timeout)
    except Exception:
        logger.exception("Failed to capture CDP packet")
        return None

    if not packets:
        logger.warning("No CDP packets captured within timeout")
        return None

    return packets[0]


def parse(packet):
    try:
        switcher = packet["CDPMsgDeviceID"].val.decode("utf-8")
        port = packet["CDPMsgPortID"].iface.decode("utf-8")
        vlan = packet["CDPMsgNativeVLAN"].vlan
        return {"Switcher": switcher, "Port": port, "VLAN": vlan}
    except Exception:
        logger.exception("Failed to parse CDP packet")
        return {"Switcher": None, "Port": None, "VLAN": None}


def run(interface: str, timeout: int = 60):
    """Capture and parse a CDP packet."""
    packet = capture(interface, timeout)
    return parse(packet)


if __name__ == "__main__":
    interface = ""
    result = run(interface)