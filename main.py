import click
import json
import sys
import logging
from rich.console import Console

import network
import port
import dhcp
import vlan
import interface
import scanner
from log import setup_logging

console = Console()

def validate_interface(interface_name):
    """Check if the provided interface is valid and active."""
    active_interfaces = interface.list_interfaces()
    if interface_name not in active_interfaces:
        console.print(f"[bold red]Error:[/bold red] Interface '{interface_name}' is not valid or not active.")
        console.print(f"[bold cyan]Available interfaces:[/bold cyan] {', '.join(active_interfaces)}")
        sys.exit(1)


@click.group()
@click.option("--log", is_flag=True, help="Enable logging to a file (default: netool.log)")
def cli(log):
    """Network toolkit for Port scanning, DHCP, VLAN/CDP, subnet discovery"""
    if log:
        setup_logging()


@cli.command()
@click.option("-i", "--interface", required=True, help="Interface name")
def network_cmd(interface):
    """Show interface network info (IP, MAC, etc.)"""
    validate_interface(interface)
    result = network.network_scan(interface)
    
    console.print(f"\n[bold magenta]Network information for interface: {interface}[/bold magenta]")
    for key, value in result.items():
        label = key.upper().replace("_", " ")
        console.print(f"[bold cyan]{label:<15}:[/bold cyan] {value if value else 'N/A'}")


@cli.command()
def interfaces():
    """List all current network interfaces"""
    result = interface.list_interfaces()
    if not result:
        console.print("[yellow]No active interfaces found.[/yellow]")
    else:
        console.print("\n[bold magenta]Active Interfaces:[/bold magenta]")
        for iface in result:
            console.print(f"[cyan]•[/cyan] {iface}")


@cli.command()
@click.option("-t", "--target", required=True, help="Target IP address or hostname")
@click.option("-s", "--scan", type=click.Choice(["syn", "udp", "xmas", "tcp"]), default="syn", help="Scan type")
@click.option("-p", "--ports", help="Ports: single int, comma-separated list, or range (e.g. '22', '80,443', '1000-1010')")
@click.option("-w", "--wordlist", type=click.Path(exists=True), help="Path to a local port wordlist file")
@click.option("-r", "--remote", is_flag=True, help="Pull common ports from SecLists")
@click.option("-top", "--top", type=int, help="Use top N ports from nmap-services (default: 1000 if not specified)")
@click.option("-to", "--timeout", type=float, default=1.0, help="Per-port timeout in seconds")
@click.option("-th", "--threads", type=int, default=50, help="Number of worker threads")
def port_cmd(target, scan, ports, wordlist, remote, top, timeout, threads):
    """Port scan a target"""
    parsed_ports = None
    
    # 1. Remote SecLists
    if remote:
        parsed_ports = port.fetch_remote_wordlist(port.SECLISTS_COMMON_PORTS_URL)
        if not parsed_ports:
            console.print("[yellow]Warning:[/yellow] Remote fetch failed.")

    # 2. Nmap Services (Top Ports)
    if not parsed_ports and top is not None:
        # Determine protocol for nmap services (udp scan uses udp, others use tcp)
        proto = "udp" if scan == "udp" else "tcp"
        parsed_ports = port.load_nmap_services(top_n=top, protocol=proto)
        if not parsed_ports:
            console.print("[red]Error:[/red] Could not load top ports from nmap-services.")
            sys.exit(1)

    # 3. Local Wordlist
    if not parsed_ports and wordlist:
        parsed_ports = port.load_ports_from_file(wordlist)
        if not parsed_ports:
            console.print("[bold red]Error:[/bold red] Local wordlist was empty or invalid.")
            sys.exit(1)
            
    # 4. Specific ports (single int, list, or range)
    if not parsed_ports and ports:
        parsed_ports = []
        for part in ports.split(","):
            part = part.strip()
            if not part: continue
            if "-" in part:
                try:
                    start, end = part.split("-")
                    parsed_ports.extend(range(int(start), int(end) + 1))
                except ValueError:
                    console.print(f"[red]Invalid range: {part}[/]")
            else:
                try:
                    parsed_ports.append(int(part))
                except ValueError:
                    console.print(f"[red]Invalid port: {part}[/]")

    # No inputs provided? Fallback to module defaults
    if not parsed_ports:
        parsed_ports = port.DEFAULT_PORTS

    result = port.port_scan(
        target=target,
        scan=scan,
        ports=parsed_ports,
        timeout=timeout,
        threads=threads,
    )
    console.print(f"\n[bold magenta]Port scan results for target: {target}[/bold magenta]")
    console.print(f"[bold cyan]Scan Type:[/bold cyan] {scan}")
    console.print("-" * 30)
    for p, state in sorted(result.items()):
        color = "[green]" if state == "open" else "[red]" if state == "closed" else "[yellow]"
        console.print(f"Port {p:>5} : {color}{state}[/]")
    console.print("-" * 30)


def print_dhcp_event(event_type, mac):
    """Callback to print DHCP events with Rich styling."""
    color = "[bold green]" if event_type == "REQUEST" else "[bold yellow]"
    console.print(f" {color}{event_type:<10}[/] | MAC: [cyan]{mac}[/]")


@cli.command()
@click.option("-i", "--interface", required=True, help="Interface name")
@click.option("-s", "--server-ip", default="192.168.100.1", help="DHCP server IP")
@click.option("-m", "--subnet-mask", default="255.255.255.0", help="Subnet mask")
@click.option("-c", "--count", type=int, default=3, help="Number of leases in pool")
def dhcp_cmd(interface, server_ip, subnet_mask, count):
    """DHCP scan"""
    if count < 1:
        click.echo("Error: --count must be at least 1", err=True)
        sys.exit(1)
    validate_interface(interface)
    
    console.print(f"\n[bold magenta]Starting DHCP Server on {interface}...[/bold magenta]")
    console.print(f"[cyan]Server IP:[/cyan] {server_ip} | [cyan]Subnet Mask:[/cyan] {subnet_mask} | [cyan]Pool Size:[/cyan] {count}")
    console.print("Listening for requests (timeout: 90s). Press Ctrl+C to stop early.\n")
    
    dhcp.dhcp_scan(
        interface=interface,
        server_ip=server_ip,
        count=count,
        subnet_mask=subnet_mask,
        callback=print_dhcp_event,
    )
    console.print("\n[bold magenta]DHCP scan complete.[/bold magenta]")


@cli.command()
@click.option("-s", "--subnet", required=True, help="Subnet to scan (e.g. 192.168.1.0/24)")
def scan_cmd(subnet):
    """Scan subnet for active devices and identify vendors"""
    console.print(f"\n[bold magenta]Scanning subnet: {subnet}...[/bold magenta]")
    
    # Using the scanner module's combined scan function
    results = scanner.scan_subnet(subnet)
    
    if not results:
        console.print("[yellow]No devices found in the specified subnet.[/yellow]")
        return

    # Table header
    console.print(f"\n[bold cyan]{'IP Address':<15} {'MAC Address':<20} {'Vendor'}[/bold cyan]")
    console.print("-" * 50)
    
    for dev in results:
        console.print(f"{dev['ip']:<15} {dev['mac']:<20} {dev['vendor']}")
    
    console.print("-" * 50)
    console.print(f"[bold green]Found {len(results)} device(s).[/bold green]\n")


@cli.command()
@click.option("-i", "--interface", required=True, help="Interface name")
@click.option("-t", "--timeout", type=int, default=60, help="Capture timeout in seconds")
def vlan_cmd(interface, timeout):
    """VLAN/CDP discovery"""
    validate_interface(interface)
    result = vlan.run(interface, timeout=timeout)
    if result.get("Switcher") is None:
        console.print("\n[yellow]No CDP packet captured (or it could not be parsed).[/yellow]")
    else:
        console.print(f"\n[bold magenta]CDP Information for {interface}:[/bold magenta]")
        for key, value in result.items():
            label = key.upper()
            console.print(f"[bold cyan]{label:<12}:[/bold cyan] {value}")


if __name__ == "__main__":
    cli()