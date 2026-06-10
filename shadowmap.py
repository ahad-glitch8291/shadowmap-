#!/usr/bin/env python3
"""
shadowmap.py — Passive OSINT & Recon Automation Tool
Phase 1 | Cybersecurity Learning Project

Usage:
    python3 shadowmap.py -d example.com
    python3 shadowmap.py -d example.com --modules dns whois subdomains ports
"""

import argparse
import json
import os
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

# ── Import our modules ─────────────────────────────────────────────────────────
from modules.dns_recon    import run_dns_recon
from modules.whois_lookup import run_whois
from modules.subdomains   import run_subdomain_enum
from modules.port_scanner import run_port_scan
from modules.tech_detect  import run_tech_detect
from modules.reporter     import generate_report

BANNER = f"""
{Fore.CYAN}
  ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗███╗   ███╗ █████╗ ██████╗
  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║████╗ ████║██╔══██╗██╔══██╗
  ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██╔████╔██║███████║██████╔╝
  ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║╚██╔╝██║██╔══██║██╔═══╝
  ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██║ ╚═╝ ██║██║  ██║██║
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝
{Style.RESET_ALL}
  {Fore.YELLOW}Passive OSINT & Recon Engine{Style.RESET_ALL}  |  {Fore.RED}For authorized use only{Style.RESET_ALL}
"""

ALL_MODULES = ["dns", "whois", "subdomains", "ports", "tech"]


def print_section(title):
    print(f"\n{Fore.CYAN}{'─'*60}")
    print(f"  {Fore.WHITE}{title}")
    print(f"{Fore.CYAN}{'─'*60}{Style.RESET_ALL}")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="shadowmap — Passive OSINT & Recon Automation Tool"
    )
    parser.add_argument("-d", "--domain",   required=True,  help="Target domain (e.g. example.com)")
    parser.add_argument("-m", "--modules",  nargs="+",      default=ALL_MODULES,
                        choices=ALL_MODULES, help="Modules to run (default: all)")
    parser.add_argument("-o", "--output",   default="reports", help="Output directory for reports")
    parser.add_argument("-w", "--wordlist", default=None,   help="Custom subdomain wordlist path")
    parser.add_argument("--ports",          default="21,22,25,53,80,443,8080,8443,3306,5432",
                        help="Ports to scan (comma-separated)")
    parser.add_argument("--threads",        default=50, type=int, help="Threads for subdomain enum")
    args = parser.parse_args()

    # ── Sanitise input ──────────────────────────────────────────────────────────
    domain = args.domain.lower().strip().replace("http://","").replace("https://","").rstrip("/")
    if "/" in domain:
        domain = domain.split("/")[0]

    print(f"  {Fore.GREEN}[*]{Style.RESET_ALL} Target  : {Fore.WHITE}{domain}")
    print(f"  {Fore.GREEN}[*]{Style.RESET_ALL} Modules : {', '.join(args.modules)}")
    print(f"  {Fore.GREEN}[*]{Style.RESET_ALL} Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    results = {"domain": domain, "timestamp": datetime.now().isoformat(), "modules": {}}

    # ── Run selected modules ────────────────────────────────────────────────────
    if "dns" in args.modules:
        print_section("DNS Reconnaissance")
        results["modules"]["dns"] = run_dns_recon(domain)

    if "whois" in args.modules:
        print_section("WHOIS Lookup")
        results["modules"]["whois"] = run_whois(domain)

    if "subdomains" in args.modules:
        print_section("Subdomain Enumeration")
        results["modules"]["subdomains"] = run_subdomain_enum(
            domain, wordlist=args.wordlist, threads=args.threads
        )

    if "ports" in args.modules:
        print_section("Port Scanning")
        targets = [domain]
        # Also scan any live subdomains we found
        if "subdomains" in results["modules"]:
            targets += results["modules"]["subdomains"].get("live", [])[:5]  # top 5
        port_list = [int(p) for p in args.ports.split(",")]
        results["modules"]["ports"] = run_port_scan(targets, port_list)

    if "tech" in args.modules:
        print_section("Technology Fingerprinting")
        results["modules"]["tech"] = run_tech_detect(domain)

    # ── Generate report ─────────────────────────────────────────────────────────
    print_section("Generating Report")
    os.makedirs(args.output, exist_ok=True)
    report_path = generate_report(domain, results, args.output)

    print(f"\n{Fore.GREEN}[✓] Scan complete!")
    print(f"    JSON : {args.output}/{domain}_results.json")
    print(f"    HTML : {report_path}{Style.RESET_ALL}\n")

    # Save raw JSON too
    json_path = os.path.join(args.output, f"{domain}_results.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)


if __name__ == "__main__":
    main()