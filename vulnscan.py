#!/usr/bin/env python3
"""
vulnscan.py — Network Vulnerability Scanner
Phase 2 | Cybersecurity Learning Project

Usage:
    python3 vulnscan.py -t scanme.nmap.org
    python3 vulnscan.py -t 45.33.32.156 --ports 22,80,443,21,3306
    python3 vulnscan.py -t example.com --skip-creds
"""

import argparse
import json
import os
import sys
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

from modules.banner_grab import scan_host
from modules.cve_match   import run_cve_matching
from modules.cred_test   import run_credential_tests
from modules.ssl_check   import run_ssl_checks
from modules.reporter    import generate_report

BANNER = f"""
{Fore.RED}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
  {Fore.YELLOW}Network Vulnerability Scanner{Style.RESET_ALL}  |  {Fore.RED}Authorized use only{Style.RESET_ALL}
"""

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                 993, 1433, 3306, 3389, 5432, 5900, 6379,
                 8080, 8443, 9200, 27017]


def print_section(title):
    print(f"\n{Fore.RED}{'─'*60}")
    print(f"  {Fore.WHITE}{title}")
    print(f"{Fore.RED}{'─'*60}{Style.RESET_ALL}")


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description="vulnscan — Network Vulnerability Scanner")
    parser.add_argument("-t", "--target",     required=True, help="Target IP or domain")
    parser.add_argument("-p", "--ports",      default=None,  help="Comma-separated ports (default: common ports)")
    parser.add_argument("-o", "--output",     default="reports", help="Output directory")
    parser.add_argument("--skip-creds",       action="store_true", help="Skip credential testing")
    parser.add_argument("--skip-ssl",         action="store_true", help="Skip SSL checks")
    parser.add_argument("--timeout",          default=3, type=int, help="Socket timeout seconds")
    args = parser.parse_args()

    target = args.target.lower().strip().replace("https://","").replace("http://","").rstrip("/")

    ports = DEFAULT_PORTS
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(",")]

    print(f"  {Fore.GREEN}[*]{Style.RESET_ALL} Target  : {Fore.WHITE}{target}")
    print(f"  {Fore.GREEN}[*]{Style.RESET_ALL} Ports   : {len(ports)} ports")
    print(f"  {Fore.GREEN}[*]{Style.RESET_ALL} Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = {
        "target":           target,
        "timestamp":        datetime.now().isoformat(),
        "services":         [],
        "cve_findings":     [],
        "credential_tests": {},
        "ssl_checks":       {},
    }

    # ── Step 1: Banner grabbing ─────────────────────────────────────────────────
    print_section("Step 1 — Service Discovery & Banner Grabbing")
    services = scan_host(target, ports, timeout=args.timeout)
    results["services"] = services

    if not services:
        print(f"  {Fore.YELLOW}[!] No open ports found. Target may be firewalled.{Style.RESET_ALL}")
        return

    print(f"\n  {Fore.GREEN}[✓]{Style.RESET_ALL} Found {len(services)} open service(s)")

    # ── Step 2: CVE matching ────────────────────────────────────────────────────
    print_section("Step 2 — CVE Vulnerability Matching")
    cve_findings = run_cve_matching(services)
    results["cve_findings"] = cve_findings

    # ── Step 3: Credential testing ──────────────────────────────────────────────
    if not args.skip_creds:
        print_section("Step 3 — Default Credential Testing")
        cred_results = run_credential_tests(target, services)
        results["credential_tests"] = cred_results
    else:
        print(f"\n  {Fore.YELLOW}[i] Skipping credential tests (--skip-creds){Style.RESET_ALL}")

    # ── Step 4: SSL/TLS checks ──────────────────────────────────────────────────
    if not args.skip_ssl:
        print_section("Step 4 — SSL/TLS Security Audit")
        ssl_results = run_ssl_checks(target, services)
        results["ssl_checks"] = ssl_results
    else:
        print(f"\n  {Fore.YELLOW}[i] Skipping SSL checks (--skip-ssl){Style.RESET_ALL}")

    # ── Step 5: Report ──────────────────────────────────────────────────────────
    print_section("Step 5 — Generating Report")
    os.makedirs(args.output, exist_ok=True)
    report_path = generate_report(target, results, args.output)

    # Save JSON
    json_path = os.path.join(args.output, f"{target}_vulnscan.json")
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2, default=str)

    total_findings = len(cve_findings) + sum(
        1 for r in results["credential_tests"].values() if r.get("vulnerable")
    )

    print(f"\n{Fore.RED}{'═'*60}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}[✓] Scan complete!")
    print(f"      Open services : {len(services)}")
    print(f"      CVE findings  : {len(cve_findings)}")
    print(f"      HTML report   : {report_path}")
    print(f"{Fore.RED}{'═'*60}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()