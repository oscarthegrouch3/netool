import argparse
import json
import sys

import network
import port
import dhcp
import vlan
import subnet


def cmd_network(args):
    result = network.network_scan(args.interface)
    print(json.dumps(result, indent=2))


def cmd_port(args):
    ports = None
    if args.ports:
        ports = []
        for part in args.ports.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-")
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))

    result = port.port_scan(
        target=args.target,
        scan=args.scan,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
    )
    for p, state in sorted(result.items()):
        print(f"{p:>6}/{args.scan:<4} {state}")


def cmd_dhcp(args):
    if args.count < 1:
        print("Error: --count must be at least 1", file=sys.stderr)
        sys.exit(1)
    dhcp.dhcp_scan(
        interface=args.interface,
        server_ip=args.server_ip,
        count=args.count,
    )

def cmd_vlan(args):
    result = vlan.run(args.interface, timeout=args.timeout)
    if result.get("Switcher") is None:
        print("No CDP packet captured (or it could not be parsed).")
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(
        description="Network toolkit for Port scanning, DHCP, VLAN/CDP, subnet discovery"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # network
    p_net = sub.add_parser("network", help="Show interface network info (IP, MAC, etc.)")
    p_net.add_argument("-i", "--interface", required=True, help="Interface name")
    p_net.set_defaults(func=cmd_network)

    # port
    p_port = sub.add_parser("port", help="Port scan a target")
    p_port.add_argument("-t", "--target", required=True, help="Target IP address or hostname")
    p_port.add_argument(
        "-s", "--scan", choices=["syn", "udp", "xmas"], default="syn",
        help="Scan type (default: %(default)s)"
    )
    p_port.add_argument(
        "-p", "--ports",
        help="Comma-separated ports/ranges, e.g. '22,80,1000-1010'. "
             "Default: built-in common port list."
    )
    p_port.add_argument("-t", "--timeout", type=float, default=1.0,
                         help="Per-port timeout in seconds (default: %(default)s)")
    p_port.add_argument("-w", "--threads", type=int, default=50,
                         help="Number of worker threads (default: %(default)s)")
    p_port.set_defaults(func=cmd_port)

    # dhcp
    p_dhcp = sub.add_parser("dhcp", help="Run a simple DHCP server")
    p_dhcp.add_argument("-i", "--interface", required=True, help="Interface to bind to")
    p_dhcp.add_argument("-s", "--server-ip", default="192.168.100.1",
                         help="DHCP server IP (default: %(default)s)")
    p_dhcp.add_argument("-c", "--count", type=int, default=3,
                         help="Number of leases in pool (default: %(default)s)")
    p_dhcp.set_defaults(func=cmd_dhcp)

    # vlan
    p_vlan = sub.add_parser("vlan", help="Capture CDP packet to learn switch/port/VLAN")
    p_vlan.add_argument("-i", "--interface", required=True, help="Interface name")
    p_vlan.add_argument("-t", "--timeout", type=int, default=60,
                         help="Capture timeout in seconds (default: %(default)s)")
    p_vlan.set_defaults(func=cmd_vlan)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(1)
    except PermissionError:
        print("Error: this operation requires elevated privileges (try sudo).", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()