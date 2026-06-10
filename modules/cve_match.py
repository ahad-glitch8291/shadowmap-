"""
modules/cve_match.py — Match detected service versions against CVE database

LESSON: This is the core of how vulnerability scanners work.
The logic is simple:
  1. You know the service: "Apache/2.4.7"
  2. You look it up in a CVE database
  3. You find all CVEs affecting that version
  4. You rate the severity and tell the pentester

Real tools like Nessus do this with a database of 100,000+ CVEs
updated daily. We build the same logic with a focused database.

CVSS SCORING (Common Vulnerability Scoring System):
  10.0      → Critical (remote code execution, no auth needed)
  7.0-9.9   → High (serious impact, often exploitable)
  4.0-6.9   → Medium (requires some conditions)
  0.1-3.9   → Low (limited impact)

Knowing CVSS scores is essential for pentest reports — it tells
the client which vulns to fix first.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.vuln_db import VULN_DB
from colorama import Fore, Style


SEVERITY_COLORS = {
    "CRITICAL": Fore.RED,
    "HIGH":     Fore.LIGHTRED_EX,
    "MEDIUM":   Fore.YELLOW,
    "LOW":      Fore.CYAN,
    "INFO":     Fore.WHITE,
}


def match_cves(service_name, banner, version):
    """
    Match a service banner + version against our CVE database.
    Returns list of matching CVE dicts.

    LESSON: We use simple substring matching — if "apache/2.4.7"
    appears in the banner, we check every Apache CVE pattern.
    Real scanners use version range comparisons (semver) but
    substring matching catches most real-world cases.
    """
    matches = []
    banner_lower = (banner or "").lower()
    version_lower = (version or "").lower()
    service_lower = service_name.lower()

    # Map port service names to DB keys
    service_map = {
        "http": "http", "https": "http", "http-alt": "http",
        "https-alt": "http", "ssh": "ssh", "ftp": "ftp",
        "smtp": "smtp", "mysql": "mysql", "rdp": "rdp",
        "smb": "smb",
    }

    db_key = service_map.get(service_lower)
    if not db_key:
        return matches

    for vuln in VULN_DB.get(db_key, []):
        pattern = vuln["pattern"].lower()

        # Match if pattern found in banner or version string
        # Empty pattern (like RDP/SMB) matches any open instance of that service
        if pattern == "" or pattern in banner_lower or pattern in version_lower:
            matches.append(vuln)

    return matches


def run_cve_matching(open_services):
    """
    Run CVE matching across all discovered open services.
    Returns structured findings with severity ratings.
    """
    all_findings = []
    critical_count = 0
    high_count = 0

    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Matching services against CVE database...")

    for svc in open_services:
        port    = svc["port"]
        service = svc["service"]
        banner  = svc["banner"]
        version = svc["version"]

        cves = match_cves(service, banner, version)

        if cves:
            print(f"\n  {Fore.WHITE}Port {port} / {service}"
                  + (f" ({version})" if version else "") + f"{Style.RESET_ALL}")

            for cve in cves:
                severity = cve["severity"]
                color = SEVERITY_COLORS.get(severity, Fore.WHITE)
                cvss = cve["cvss"]

                print(f"  {color}[{severity}]{Style.RESET_ALL} "
                      f"{Fore.YELLOW}{cve['cve']}{Style.RESET_ALL} "
                      f"(CVSS: {cvss})")
                print(f"    ↳ {cve['description']}")
                print(f"    {Fore.GREEN}Fix: {cve['fix']}{Style.RESET_ALL}")

                if severity == "CRITICAL":
                    critical_count += 1
                elif severity == "HIGH":
                    high_count += 1

                all_findings.append({
                    "port":        port,
                    "service":     service,
                    "version":     version,
                    "cve":         cve["cve"],
                    "cvss":        cvss,
                    "severity":    severity,
                    "description": cve["description"],
                    "fix":         cve["fix"],
                })
        else:
            # No CVEs found — but still report the service
            print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} "
                  f"Port {port} / {service}"
                  + (f" ({version})" if version else "")
                  + " — No known CVEs matched")

    # Summary
    print(f"\n  {'─'*50}")
    print(f"  {Fore.RED}Critical: {critical_count}{Style.RESET_ALL}  "
          f"{Fore.LIGHTRED_EX}High: {high_count}{Style.RESET_ALL}  "
          f"Total findings: {len(all_findings)}")

    return all_findings