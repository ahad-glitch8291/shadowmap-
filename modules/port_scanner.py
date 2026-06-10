"""
modules/port_scanner.py
TCP port scanner using raw sockets.

LESSON: Ports are numbered 0–65535. Each number is like a door
on a server. Different services listen on standard ports:
  22   → SSH  (remote shell access — if open, try default creds)
  80   → HTTP (unencrypted web — check for HTTP→HTTPS redirect)
  443  → HTTPS (encrypted web)
  21   → FTP  (file transfer — often has anon login!)
  25   → SMTP (email — open relays can be abused for spam)
  3306 → MySQL (database exposed to internet = CRITICAL finding)
  5432 → PostgreSQL
  8080/8443 → Admin panels, dev servers, proxies

HOW TCP CONNECT SCAN WORKS:
  We attempt a full TCP 3-way handshake (SYN → SYN-ACK → ACK).
  If the server completes it → port is OPEN.
  If it sends RST → port is CLOSED.
  If no response → FILTERED (firewall is dropping packets).

  This is the most reliable scan but also the most detectable
  (it shows up in server logs). Nmap's SYN scan (-sS) is stealthier
  but requires root privileges.

LESSON: Always get written permission before port scanning.
Port scanning without authorization is illegal in many jurisdictions.
"""

import socket
import concurrent.futures
from colorama import Fore, Style


# Service names for common ports — so we display human-readable output
PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 993: "IMAPS", 995: "POP3S", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    8888: "Jupyter", 9200: "Elasticsearch", 27017: "MongoDB",
}

# Risk levels — helps us flag critical findings
HIGH_RISK_PORTS = {21, 23, 3306, 5432, 3389, 5900, 6379, 9200, 27017}
MEDIUM_RISK_PORTS = {22, 25, 445, 8080, 8888}


def scan_port(host, port, timeout=1.5):
    """
    Attempt TCP connection to host:port.
    Returns (port, service, banner) if open, None if closed.

    LESSON: socket.connect_ex() returns 0 on success (port open),
    or an error code on failure. This is cleaner than catching exceptions
    for control flow.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))

        if result == 0:
            # Port is open — try to grab a banner
            banner = ""
            try:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(256).decode("utf-8", errors="ignore").split("\n")[0]
            except Exception:
                pass
            sock.close()
            service = PORT_SERVICES.get(port, "Unknown")
            return (port, service, banner.strip())
        sock.close()
        return None
    except socket.gaierror:
        return None  # DNS resolution failed
    except Exception:
        return None


def run_port_scan(targets, ports, threads=100):
    """
    Scan multiple targets across multiple ports.
    Uses threading — we can run 100 socket attempts simultaneously.
    """
    all_results = {}

    for host in targets:
        print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} Scanning {host} ({len(ports)} ports)...")
        open_ports = []

        # Build all (host, port) tasks
        tasks = [(host, p) for p in ports]

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, h, p): (h, p) for h, p in tasks}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    port, service, banner = result
                    open_ports.append({
                        "port": port,
                        "service": service,
                        "banner": banner,
                        "risk": "HIGH" if port in HIGH_RISK_PORTS else
                                "MEDIUM" if port in MEDIUM_RISK_PORTS else "LOW"
                    })

        # Sort by port number and display
        open_ports.sort(key=lambda x: x["port"])

        if open_ports:
            for p in open_ports:
                risk_color = (Fore.RED if p["risk"] == "HIGH" else
                              Fore.YELLOW if p["risk"] == "MEDIUM" else Fore.GREEN)
                risk_label = f"[{p['risk']}]"
                print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} "
                      f"Port {Fore.WHITE}{p['port']:<6}{Style.RESET_ALL} "
                      f"{p['service']:<14} "
                      f"{risk_color}{risk_label}{Style.RESET_ALL}",
                      end="")
                if p["banner"]:
                    print(f"  ← {p['banner'][:60]}", end="")
                print()
        else:
            print(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} No open ports found on {host}")

        all_results[host] = open_ports

    return all_results