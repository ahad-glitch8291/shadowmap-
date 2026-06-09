"""
modules/ssl_check.py — SSL/TLS configuration auditing

LESSON: SSL/TLS is what makes HTTPS secure. But misconfigured
SSL is worse than no SSL — it gives users false confidence.

What we check:
  1. Certificate validity — is it expired? self-signed?
  2. Protocol version — SSLv3/TLS1.0 are broken
  3. Certificate info — who issued it, when does it expire?
  4. Hostname mismatch — cert for different domain = MITM risk

REAL ATTACKS enabled by weak SSL:
  POODLE  → SSLv3 padding oracle — decrypt HTTPS traffic
  BEAST   → TLS 1.0 CBC mode attack — session hijacking
  DROWN   → SSLv2 cross-protocol attack
  MITM    → Expired/self-signed cert = anyone can impersonate server
"""

import ssl
import socket
from datetime import datetime
from colorama import Fore, Style
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.vuln_db import SSL_ISSUES


def check_ssl(host, port=443, timeout=5):
    """Check SSL/TLS configuration on a given host:port."""
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Checking SSL/TLS on {host}:{port}...")
    results = {
        "port": port, "findings": [], "cert_info": {},
        "protocols": [], "vulnerable": False
    }

    # ── Certificate check ───────────────────────────────────────────────────────
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

                results["cert_info"] = {
                    "protocol": protocol,
                    "cipher":   cipher[0] if cipher else "unknown",
                    "bits":     cipher[2] if cipher else 0,
                }

                print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Protocol : {protocol}")
                print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Cipher   : {cipher[0] if cipher else 'unknown'} ({cipher[2] if cipher else '?'} bits)")

                if cert:
                    # Subject
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    cn      = subject.get("commonName", "unknown")
                    org     = issuer.get("organizationName", "unknown")

                    results["cert_info"]["common_name"] = cn
                    results["cert_info"]["issuer"] = org
                    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} CN       : {cn}")
                    print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Issuer   : {org}")

                    # Self-signed check
                    if subject == issuer:
                        print(f"  {Fore.RED}[!!!] Self-signed certificate — MITM risk!{Style.RESET_ALL}")
                        results["findings"].append({
                            "severity": "HIGH",
                            "issue": "Self-signed certificate",
                            "detail": "Certificate is not trusted by a CA — MITM attacks possible",
                            "fix": "Obtain a certificate from a trusted CA (e.g. Let's Encrypt)"
                        })
                        results["vulnerable"] = True

                    # Expiry check
                    not_after = cert.get("notAfter", "")
                    if not_after:
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (expiry - datetime.utcnow()).days
                            results["cert_info"]["expires_in_days"] = days_left

                            if days_left < 0:
                                print(f"  {Fore.RED}[!!!] Certificate EXPIRED {abs(days_left)} days ago!{Style.RESET_ALL}")
                                results["findings"].append({
                                    "severity": "CRITICAL",
                                    "issue": "Expired SSL certificate",
                                    "detail": f"Certificate expired {abs(days_left)} days ago",
                                    "fix": "Renew certificate immediately"
                                })
                                results["vulnerable"] = True
                            elif days_left < 30:
                                print(f"  {Fore.YELLOW}[!] Certificate expires in {days_left} days{Style.RESET_ALL}")
                                results["findings"].append({
                                    "severity": "MEDIUM",
                                    "issue": "Certificate expiring soon",
                                    "detail": f"Expires in {days_left} days",
                                    "fix": "Renew certificate soon"
                                })
                            else:
                                print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} Certificate valid for {days_left} more days")
                        except Exception:
                            pass

                    # Hostname mismatch
                    if cn and host not in cn and not cn.startswith("*"):
                        print(f"  {Fore.RED}[!] Hostname mismatch: cert is for '{cn}' not '{host}'{Style.RESET_ALL}")
                        results["findings"].append({
                            "severity": "HIGH",
                            "issue": "Certificate hostname mismatch",
                            "detail": f"Cert CN={cn} does not match {host}",
                            "fix": "Obtain certificate matching the correct hostname"
                        })

    except ssl.SSLError as e:
        print(f"  {Fore.RED}[!] SSL Error: {e}{Style.RESET_ALL}")
        results["findings"].append({
            "severity": "HIGH",
            "issue": "SSL handshake failed",
            "detail": str(e),
            "fix": "Review SSL configuration"
        })
    except ConnectionRefusedError:
        print(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} Port {port} not open")
        return None
    except Exception as e:
        print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} Could not connect: {e}")
        return None

    # ── Weak protocol checks ────────────────────────────────────────────────────
    print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} Checking for weak protocol support...")

    weak_protocols = {
        "SSLv2":   ssl.PROTOCOL_TLS_CLIENT if hasattr(ssl, 'PROTOCOL_SSLv2') else None,
        "SSLv3":   getattr(ssl, 'PROTOCOL_SSLv3', None),
        "TLSv1.0": getattr(ssl, 'PROTOCOL_TLSv1', None),
        "TLSv1.1": getattr(ssl, 'PROTOCOL_TLSv1_1', None),
    }

    for proto_name, proto_const in weak_protocols.items():
        if proto_const is None:
            # Protocol not supported by this Python version (good — it's disabled)
            severity, description = SSL_ISSUES.get(proto_name, ("INFO", ""))
            print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {proto_name} — Not supported by server (good)")
            continue

        try:
            ctx = ssl.SSLContext(proto_const)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=3) as s:
                with ctx.wrap_socket(s) as ss:
                    severity, description = SSL_ISSUES.get(proto_name, ("MEDIUM", "Weak protocol"))
                    color = Fore.RED if severity == "CRITICAL" else Fore.YELLOW
                    print(f"  {color}[{severity}]{Style.RESET_ALL} {proto_name} supported — {description}")
                    results["findings"].append({
                        "severity": severity,
                        "issue": f"Weak protocol: {proto_name}",
                        "detail": description,
                        "fix": f"Disable {proto_name} in server configuration"
                    })
                    results["vulnerable"] = True
        except Exception:
            print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} {proto_name} — Rejected by server")

    if not results["findings"]:
        print(f"\n  {Fore.GREEN}[✓]{Style.RESET_ALL} SSL/TLS configuration looks solid")

    return results


def run_ssl_checks(host, open_services):
    """Run SSL checks on all HTTPS/SSL ports found."""
    ssl_ports = [s["port"] for s in open_services
                 if s["service"] in ("HTTPS", "HTTPS-Alt", "IMAPS")]

    if not ssl_ports:
        # Also check 443 even if not found in initial scan
        ssl_ports = [443]

    all_results = {}
    for port in ssl_ports:
        result = check_ssl(host, port)
        if result:
            all_results[port] = result

    return all_results