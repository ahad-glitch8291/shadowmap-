"""
modules/banner_grab.py — Service version detection via banner grabbing

LESSON: Banner grabbing is one of the oldest recon techniques.
When you connect to a service, it often announces itself:

  SSH:   "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
  FTP:   "220 vsftpd 2.3.4"
  SMTP:  "220 mail.example.com ESMTP Sendmail 8.14.4"
  HTTP:  "Server: Apache/2.4.7 (Ubuntu)"

This is called a "banner" — the service's introduction message.
It tells you the software name, version, and sometimes the OS.

WHY THIS MATTERS:
Once you know "vsftpd 2.3.4" you search CVE databases and find
CVE-2011-2523 — a literal backdoor. Version info = exploit roadmap.

DEFENSE: Good sysadmins suppress banners. If SSH says "SSH-2.0-OpenSSH"
with no version, or Apache returns "Server: Apache" with no version number,
the admin has done their job. Note this as good hygiene in your report.
"""

import socket
import ssl
import re
from colorama import Fore, Style


# Port → (service_name, probe_to_send, protocol)
# We send a probe to trigger the banner response
SERVICE_PROBES = {
    21:   ("FTP",        b"",                          "tcp"),
    22:   ("SSH",        b"",                          "tcp"),
    23:   ("Telnet",     b"",                          "tcp"),
    25:   ("SMTP",       b"EHLO vulnscan\r\n",         "tcp"),
    53:   ("DNS",        b"",                          "udp"),
    80:   ("HTTP",       b"HEAD / HTTP/1.0\r\n\r\n",   "tcp"),
    110:  ("POP3",       b"",                          "tcp"),
    143:  ("IMAP",       b"",                          "tcp"),
    443:  ("HTTPS",      b"HEAD / HTTP/1.0\r\n\r\n",   "ssl"),
    445:  ("SMB",        b"",                          "tcp"),
    993:  ("IMAPS",      b"",                          "ssl"),
    1433: ("MSSQL",      b"",                          "tcp"),
    3306: ("MySQL",      b"",                          "tcp"),
    3389: ("RDP",        b"",                          "tcp"),
    5432: ("PostgreSQL", b"",                          "tcp"),
    5900: ("VNC",        b"",                          "tcp"),
    6379: ("Redis",      b"PING\r\n",                  "tcp"),
    8080: ("HTTP-Alt",   b"HEAD / HTTP/1.0\r\n\r\n",   "tcp"),
    8443: ("HTTPS-Alt",  b"HEAD / HTTP/1.0\r\n\r\n",   "ssl"),
    9200: ("Elasticsearch", b"",                       "tcp"),
    27017:("MongoDB",    b"",                          "tcp"),
}


def grab_banner(host, port, timeout=3):
    """
    Connect to host:port and grab the service banner.
    Returns dict with service info or None if port closed.

    LESSON: We handle SSL ports separately because we need to
    wrap the socket in an SSL context. This is how HTTPS works —
    a regular TCP connection wrapped in TLS encryption.
    """
    service_info = SERVICE_PROBES.get(port, ("Unknown", b"", "tcp"))
    service_name, probe, protocol = service_info

    result = {
        "port": port,
        "service": service_name,
        "banner": "",
        "version": "",
        "protocol": protocol,
        "open": False
    }

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        # Try connecting
        if sock.connect_ex((host, port)) != 0:
            sock.close()
            return None  # Port closed

        result["open"] = True

        # Wrap in SSL if needed
        if protocol == "ssl":
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            except ssl.SSLError:
                pass  # SSL failed but port is open

        # Send probe if we have one
        if probe:
            try:
                sock.send(probe)
            except Exception:
                pass

        # Read the banner
        try:
            banner_bytes = sock.recv(1024)
            result["banner"] = banner_bytes.decode("utf-8", errors="ignore").strip()
        except Exception:
            pass

        sock.close()

        # Extract version from banner
        result["version"] = extract_version(result["banner"], service_name)
        return result

    except socket.gaierror:
        return None
    except Exception:
        return None


def extract_version(banner, service):
    """
    Parse version strings from banners.

    LESSON: Version extraction is pattern matching. Different services
    announce their version in different formats. We use regex to
    pull the version number out consistently.
    """
    banner_lower = banner.lower()

    patterns = [
        # SSH: "SSH-2.0-OpenSSH_6.6.1p1"
        r"openssh[_\s]([\d.]+\w*)",
        # Apache: "Apache/2.4.7"
        r"apache/([\d.]+)",
        # Nginx: "nginx/1.18.0"
        r"nginx/([\d.]+)",
        # vsftpd: "vsftpd 2.3.4"
        r"vsftpd\s+([\d.]+)",
        # ProFTPD: "ProFTPD 1.3.3"
        r"proftpd\s+([\d.]+)",
        # IIS: "Microsoft-IIS/6.0"
        r"microsoft-iis/([\d.]+)",
        # MySQL: "5.5.62-0ubuntu0"
        r"([\d]+\.[\d]+\.[\d]+)-\d+ubuntu",
        # Generic version pattern
        r"([\d]+\.[\d]+\.[\d]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, banner_lower)
        if match:
            return match.group(1)

    return ""


def scan_host(host, ports=None, timeout=3):
    """
    Scan a host across multiple ports and return all open services.
    This is the main entry point for banner grabbing.
    """
    if ports is None:
        ports = list(SERVICE_PROBES.keys())

    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Banner grabbing {host} across {len(ports)} ports...")

    open_services = []
    for port in sorted(ports):
        result = grab_banner(host, port, timeout)
        if result:
            service = result["service"]
            version = result["version"]
            banner_short = result["banner"][:60].replace("\n", " ") if result["banner"] else ""

            version_str = f" {Fore.YELLOW}{version}{Style.RESET_ALL}" if version else ""
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} "
                  f"{port:<6} {service:<14}{version_str}")
            if banner_short and version not in banner_short:
                print(f"{'':>8} {Fore.WHITE}↳ {banner_short}{Style.RESET_ALL}")

            open_services.append(result)

    return open_services