#!/usr/bin/env python3
"""
network-scanner: A multithreaded TCP port scanner with banner grabbing.

Usage:
    python scanner.py <target> -p <port_range> [options]

Examples:
    python scanner.py 192.168.1.1 -p 1-1024
    python scanner.py scanme.nmap.org -p 22,80,443 -o results.json -t 200
"""

import argparse
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone


# ──────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────

# How long (seconds) to wait for a connection before giving up
CONNECT_TIMEOUT = 1.0

# How long (seconds) to wait when trying to read a banner
BANNER_TIMEOUT = 2.0

# Maximum worker threads (overridable via --threads)
DEFAULT_THREADS = 100


# ──────────────────────────────────────────────
# Port scanning
# ──────────────────────────────────────────────

def scan_port(target: str, port: int) -> dict | None:
    """
    Attempt a TCP connection to target:port.

    Returns a result dict if the port is open, or None if it is closed/filtered.
    The dict contains the port number, its state, the service name (if known),
    and any banner text retrieved.
    """
    try:
        # Create a standard IPv4 TCP socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(CONNECT_TIMEOUT)

            # connect_ex returns 0 on success instead of raising an exception,
            # which makes it easier to distinguish open vs closed without try/except.
            result = sock.connect_ex((target, port))

            if result != 0:
                # Non-zero means the connection was refused or timed out → closed/filtered
                return None

            # Port is open — try to resolve the well-known service name
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"

            # Attempt to grab a banner from the open port
            banner = grab_banner(sock, port)

            return {
                "port": port,
                "state": "open",
                "service": service,
                "banner": banner,
            }

    except (socket.timeout, ConnectionRefusedError, OSError):
        # Any socket-level error means we treat the port as not open
        return None


def grab_banner(sock: socket.socket, port: int) -> str:
    """
    Try to read a text banner from an already-connected socket.

    For HTTP ports (80, 443, 8080, 8443) we send a minimal HEAD request first
    because HTTP servers only respond after receiving a request.
    For everything else we just listen — many services (SSH, FTP, SMTP, …)
    send a greeting automatically on connect.

    Returns the banner string, or an empty string if nothing was received.
    """
    banner = ""
    try:
        sock.settimeout(BANNER_TIMEOUT)

        # HTTP services won't send anything until we request something
        http_ports = {80, 443, 8080, 8443, 8000, 8888}
        if port in http_ports:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")

        # Read up to 1 KB of banner data
        raw = sock.recv(1024)
        # Decode bytes → str, replace anything that isn't valid UTF-8
        banner = raw.decode("utf-8", errors="replace").strip()

    except (socket.timeout, OSError):
        # Silence is fine — many ports simply don't send banners
        pass

    return banner


# ──────────────────────────────────────────────
# Port range parsing
# ──────────────────────────────────────────────

def parse_ports(port_str: str) -> list[int]:
    """
    Parse a flexible port specification into a sorted list of integers.

    Accepted formats (combinable with commas):
        80            → [80]
        1-1024        → [1, 2, …, 1024]
        22,80,443     → [22, 80, 443]
        1-100,443,8080 → [1..100, 443, 8080]
    """
    ports = set()
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            # Range like "1-1024"
            start, end = part.split("-", 1)
            start, end = int(start.strip()), int(end.strip())
            if not (1 <= start <= 65535 and 1 <= end <= 65535):
                raise ValueError(f"Port numbers must be 1-65535 (got {start}-{end})")
            if start > end:
                raise ValueError(f"Start port must be ≤ end port (got {start}-{end})")
            ports.update(range(start, end + 1))
        else:
            # Single port like "443"
            port = int(part)
            if not (1 <= port <= 65535):
                raise ValueError(f"Port number must be 1-65535 (got {port})")
            ports.add(port)

    return sorted(ports)


# ──────────────────────────────────────────────
# Main scan orchestration
# ──────────────────────────────────────────────

def run_scan(target: str, ports: list[int], threads: int) -> list[dict]:
    """
    Scan all ports concurrently using a thread pool.

    ThreadPoolExecutor manages the pool; as_completed lets us process
    results as soon as each thread finishes rather than waiting for all.

    Returns a list of result dicts for open ports, sorted by port number.
    """
    open_ports = []
    total = len(ports)
    completed = 0

    print(f"\n[*] Scanning {target} | {total} port(s) | {threads} threads\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        # Submit one scan_port task per port; store future → port mapping
        future_to_port = {
            executor.submit(scan_port, target, port): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            completed += 1

            # Simple inline progress indicator (overwrites the same line)
            print(
                f"\r    Progress: {completed}/{total} ports scanned",
                end="",
                flush=True,
            )

            result = future.result()
            if result is not None:
                open_ports.append(result)

    # Move past the progress line
    print()

    # Sort results numerically by port for tidy output
    return sorted(open_ports, key=lambda r: r["port"])


# ──────────────────────────────────────────────
# Output formatting
# ──────────────────────────────────────────────

def print_results(target: str, results: list[dict], elapsed: float) -> None:
    """Print a formatted table of open ports to stdout."""
    print(f"\n{'-' * 60}")
    print(f"  Scan results for: {target}")
    print(f"  Completed in:     {elapsed:.2f}s")
    print(f"  Open ports found: {len(results)}")
    print(f"{'-' * 60}\n")

    if not results:
        print("  No open ports found.\n")
        return

    # Column widths
    print(f"  {'PORT':<10} {'SERVICE':<15} {'BANNER'}")
    print(f"  {'-'*8:<10} {'-'*13:<15} {'-'*30}")

    for r in results:
        port_str  = f"{r['port']}/tcp"
        service   = r["service"] or "unknown"
        # Truncate long banners so they fit on one line
        banner    = (r["banner"][:60] + "...") if len(r["banner"]) > 60 else r["banner"]
        banner    = banner.replace("\n", " ").replace("\r", "")
        print(f"  {port_str:<10} {service:<15} {banner}")

    print()


def save_results(
    target: str,
    ports_scanned: list[int],
    results: list[dict],
    elapsed: float,
    output_path: str,
) -> None:
    """Serialise the full scan report to a JSON file."""
    report = {
        "scan_info": {
            "target": target,
            "ports_scanned": len(ports_scanned),
            "open_ports": len(results),
            "scan_duration_seconds": round(elapsed, 3),
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "results": results,
    }

    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    print(f"  [+] Results saved to: {output_path}\n")


# ──────────────────────────────────────────────
# CLI argument parsing
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scanner",
        description="A fast multithreaded TCP port scanner with banner grabbing.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python scanner.py 192.168.1.1 -p 1-1024
  python scanner.py scanme.nmap.org -p 22,80,443
  python scanner.py 10.0.0.1 -p 1-65535 -t 500 -o report.json
        """,
    )

    parser.add_argument(
        "target",
        help="Target hostname or IP address to scan",
    )
    parser.add_argument(
        "-p", "--ports",
        required=True,
        metavar="PORTS",
        help="Port range to scan. Examples: 1-1024  |  80,443  |  1-100,8080",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        metavar="N",
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save results to a JSON file (e.g. results.json)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=CONNECT_TIMEOUT,
        metavar="SECS",
        help=f"Connection timeout in seconds (default: {CONNECT_TIMEOUT})",
    )

    return parser


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # Apply any custom timeout the user passed in
    global CONNECT_TIMEOUT
    CONNECT_TIMEOUT = args.timeout

    # Resolve hostname → IP address early so we catch DNS failures before scanning
    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror as exc:
        print(f"[!] Cannot resolve '{args.target}': {exc}", file=sys.stderr)
        sys.exit(1)

    if target_ip != args.target:
        print(f"[*] Resolved {args.target} → {target_ip}")

    # Parse the user-supplied port specification
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        print(f"[!] Invalid port specification: {exc}", file=sys.stderr)
        sys.exit(1)

    # Validate thread count
    if args.threads < 1:
        print("[!] Thread count must be at least 1.", file=sys.stderr)
        sys.exit(1)

    # Run the scan and time it
    start_time = datetime.now(timezone.utc)
    results = run_scan(target_ip, ports, args.threads)
    elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

    # Display results in the terminal
    print_results(target_ip, results, elapsed)

    # Optionally save to JSON
    if args.output:
        save_results(target_ip, ports, results, elapsed, args.output)


if __name__ == "__main__":
    main()
