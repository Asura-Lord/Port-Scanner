#!/usr/bin/env python3
"""
port-scanner.py — Port Scanner & Banner Grabber (clean CSV output)

- By default saves only OPEN ports to CSV (clean, structured)
- Multi-threaded scanning (fast)
- Supports single host or IP range / CIDR
- Graceful color output if colorama is installed (optional)
- No required external packages (colorama optional)
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import argparse
import csv
import sys
from datetime import datetime
import ipaddress

# Try optional color support (no hard requirement)
try:
    from colorama import init as color_init, Fore, Style
    color_init(autoreset=True)
    USE_COLOR = True
except Exception:
    USE_COLOR = False
    class Dummy:
        def __getattr__(self, name): return ''
    Fore = Style = Dummy()

# Defaults
DEFAULT_TIMEOUT = 1.0
DEFAULT_WORKERS = 200
BIG_SCAN_THRESHOLD = 200   # if ports > this and --save-auto set, auto-save

# Minimal probes for banner grabbing (safe)
PROBES = {
    21: b"QUIT\r\n",     # FTP
    22: b"\r\n",         # SSH minimal
    25: b"HELO example.com\r\n",
    80: b"HEAD / HTTP/1.0\r\n\r\n",
    110: b"QUIT\r\n",
    143: b"\r\n",
    443: b"HEAD / HTTP/1.0\r\n\r\n",
    3306: b"\r\n",
}

def parse_ports(portspec: str):
    """Parse: '22' or '20-25' or '1-1024,3306,3389'"""
    if not portspec:
        return list(range(1, 1025))
    out = set()
    for part in portspec.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            a, b = part.split('-', 1)
            a = int(a); b = int(b)
            out.update(range(min(a,b), max(a,b)+1))
        else:
            out.add(int(part))
    return sorted(p for p in out if 0 < p <= 65535)

def expand_targets(target_arg):
    """
    Expand target argument into list of IP strings.
    Accepts:
     - single hostname or IP (e.g., example.com or 192.168.1.5)
     - CIDR (e.g., 192.168.1.0/28)
     - range (e.g., 192.168.1.1-192.168.1.10)
    """
    # CIDR
    if '/' in target_arg:
        try:
            net = ipaddress.ip_network(target_arg, strict=False)
            return [str(ip) for ip in net.hosts()]
        except Exception as e:
            raise ValueError(f"Invalid CIDR: {e}")

    # Range a-b
    if '-' in target_arg and not any(c.isalpha() for c in target_arg):
        try:
            start, end = target_arg.split('-', 1)
            start_ip = ipaddress.ip_address(start.strip())
            end_ip = ipaddress.ip_address(end.strip())
            if start_ip.version != end_ip.version:
                raise ValueError("IP versions differ in range")
            ips = []
            cur = int(start_ip)
            last = int(end_ip)
            step = 1 if last >= cur else -1
            for i in range(cur, last + step, step):
                ips.append(str(ipaddress.ip_address(i)))
            return ips
        except Exception as e:
            raise ValueError(f"Invalid IP range: {e}")

    # Single hostname/IP -> resolve
    try:
        addr = socket.gethostbyname(target_arg)
        return [addr]
    except Exception:
        # if it's an IP literal but unresolvable, still return it
        return [target_arg]

def try_banner(host, port, timeout):
    """Return (port, status, banner_or_empty)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        rc = s.connect_ex((host, port))
        if rc != 0:
            s.close()
            return port, "closed", ""
        banner = ""
        # try to send a small probe if we have one
        probe = PROBES.get(port)
        try:
            if probe:
                s.sendall(probe)
        except Exception:
            pass
        try:
            data = s.recv(2048)
            if data:
                banner = data.decode(errors='replace').strip().splitlines()[0]
        except Exception:
            banner = ""
        s.close()
        return port, "open", banner or ""
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return port, "filtered", ""

def scan_host(host, ports, workers, timeout, verbose=True):
    if verbose:
        print(f"{Fore.CYAN}[+] Scanning {host} — ports: {len(ports)}{Style.RESET_ALL}" if USE_COLOR else f"[+] Scanning {host} — ports: {len(ports)}")
    results = []
    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(ports)))) as ex:
        futures = {ex.submit(try_banner, host, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                port, status, banner = fut.result()
            except Exception as e:
                port, status, banner = futures[fut], "error", ""
            results.append((port, status, banner))
            if verbose and status == "open":
                if USE_COLOR:
                    print(f"{Fore.GREEN}{port:5}  OPEN   {banner or '-'}{Style.RESET_ALL}")
                else:
                    print(f"{port:5}  OPEN   {banner or '-'}")
    results.sort(key=lambda x: x[0])
    return results

def save_open_csv(results_by_host, filename=None):
    """
    results_by_host: list of tuples (host, [(port,status,banner), ...])
    Save only OPEN ports into CSV with columns: host,port,banner
    """
    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"open_ports_{ts}.csv"
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["host", "port", "banner"])
        for host, results in results_by_host:
            for port, status, banner in results:
                if status == "open":
                    writer.writerow([host, port, banner or ""])
    return filename

def save_full_csv(results_by_host, filename=None):
    """Optionally save full results: host,port,status,banner"""
    if not filename:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_full_{ts}.csv"
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["host", "port", "status", "banner"])
        for host, results in results_by_host:
            for port, status, banner in results:
                writer.writerow([host, port, status, banner or ""])
    return filename

def build_parser():
    p = argparse.ArgumentParser(prog="port-scanner.py", description="Port Scanner & Banner Grabber (clean CSV output). Scan only targets you own or have permission to test.")
    p.add_argument("target", help="Target hostname/IP or CIDR or range (e.g., 10.0.0.1, 10.0.0.1-10.0.0.10, 192.168.1.0/28)")
    p.add_argument("-p", "--ports", default="1-1024", help="Ports to scan (e.g. 22,80,443 or 1-65535). Default: 1-1024")
    p.add_argument("-t", "--threads", type=int, default=DEFAULT_WORKERS, help=f"Worker threads (default {DEFAULT_WORKERS})")
    p.add_argument("-T", "--timeout", type=float, default=DEFAULT_TIMEOUT, help=f"Socket timeout (default {DEFAULT_TIMEOUT}s)")
    p.add_argument("--save-open", nargs='?', const="auto", help="Save only OPEN ports to CSV. Provide filename or use flag to auto-name.")
    p.add_argument("--save-all", nargs='?', const="auto", help="Save full results (all ports) to CSV. Provide filename or use flag to auto-name.")
    p.add_argument("--save-auto", action="store_true", help=f"Auto-save OPEN CSV if ports > {BIG_SCAN_THRESHOLD}")
    p.add_argument("--preset", choices=["common","web"], help="Preset ports: common or web")
    p.add_argument("--silent", action="store_true", help="Quiet output (only summary)")
    return p

def main():
    parser = build_parser()
    args = parser.parse_args()

    # Build target list
    try:
        targets = expand_targets(args.target)
    except Exception as e:
        print(f"[!] Invalid target: {e}")
        sys.exit(1)

    # Build ports
    if args.preset == "common":
        ports = [21,22,23,25,53,80,110,143,443,3306,3389,8080]
    elif args.preset == "web":
        ports = [80,443,8080,8000,8443]
    else:
        try:
            ports = parse_ports(args.ports)
        except Exception as e:
            print(f"[!] Invalid ports: {e}")
            sys.exit(1)

    save_open_requested = bool(args.save_open) or args.save_auto
    save_all_requested = bool(args.save_all)

    if args.save_open == "auto":
        save_open_filename = None
    elif args.save_open:
        save_open_filename = args.save_open
    else:
        save_open_filename = None

    if args.save_all == "auto":
        save_all_filename = None
    elif args.save_all:
        save_all_filename = args.save_all
    else:
        save_all_filename = None

    # auto-save behavior
    if args.save_auto and len(ports) > BIG_SCAN_THRESHOLD:
        save_open_requested = True

    results_by_host = []

    for host in targets:
        # resolve host if hostname given; keep literal if not resolvable
        try:
            resolved = socket.gethostbyname(host)
        except Exception:
            resolved = host
        if not args.silent:
            print(f"\n{Fore.MAGENTA}== Target: {host} ({resolved}) =={Style.RESET_ALL}" if USE_COLOR else f"\n== Target: {host} ({resolved}) ==")
        results = scan_host(resolved, ports, args.threads, args.timeout, verbose=not args.silent)
        results_by_host.append((host, results))

    # Summary
    total_open = sum(1 for _, res in results_by_host for _, st, _ in res if st == "open")
    if not args.silent:
        print(f"\nScan complete. Total open ports found across targets: {total_open}")

    # Save CSVs as requested
    if save_open_requested:
        filename = save_open_csv(results_by_host, filename=save_open_filename)
        print(f"[+] Saved OPEN ports CSV: {filename}")
    if save_all_requested:
        filename = save_full_csv(results_by_host, filename=save_all_filename)
        print(f"[+] Saved FULL results CSV: {filename}")

if __name__ == "__main__":
    main()
