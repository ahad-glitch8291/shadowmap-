"""
modules/dns_recon.py
Extracts all meaningful DNS records for a domain.

LESSON: DNS is the phonebook of the internet. Every domain has records
that map names → IP addresses, mail servers, text info, etc.
Attackers love DNS because it's public and reveals infrastructure.

Record types we care about:
  A     → IPv4 address (where the website lives)
  AAAA  → IPv6 address
  MX    → Mail exchange servers (who handles email)
  NS    → Name servers (who controls DNS for this domain)
  TXT   → Text records — often leak SPF, DKIM, verification codes
  CNAME → Aliases (can reveal cloud providers: *.amazonaws.com etc.)
  SOA   → Start of Authority (admin email, serial number)
"""

import dns.resolver
import dns.exception
from colorama import Fore, Style


RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def query_record(domain, rtype):
    """Query a single DNS record type. Returns list of strings."""
    try:
        answers = dns.resolver.resolve(domain, rtype, lifetime=5)
        results = []
        for rdata in answers:
            results.append(str(rdata))
        return results
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers):
        return []
    except Exception as e:
        return [f"[error: {e}]"]


def analyze_txt_records(txt_records):
    """
    TXT records often contain security configurations.
    LESSON: If SPF is missing → domain can be spoofed for phishing!
    """
    findings = []
    for record in txt_records:
        r = record.lower()
        if "v=spf1" in r:
            findings.append(("SPF", record, "Email spoofing protection found"))
            if "~all" in r:
                findings.append(("SPF-WEAK", record, "⚠ SoftFail (~all) — spoofing partially possible"))
            elif "-all" in r:
                findings.append(("SPF-STRONG", record, "✓ HardFail (-all) — good SPF policy"))
        if "v=dmarc1" in r:
            findings.append(("DMARC", record, "DMARC policy found"))
        if "v=dkim1" in r:
            findings.append(("DKIM", record, "DKIM signing key found"))
        if "google-site-verification" in r:
            findings.append(("CLOUD", record, "Google Workspace detected"))
        if "ms=" in r or "office365" in r:
            findings.append(("CLOUD", record, "Microsoft 365 detected"))
    return findings


def run_dns_recon(domain):
    """Main DNS recon function. Returns structured results dict."""
    results = {}
    all_ips = []

    for rtype in RECORD_TYPES:
        records = query_record(domain, rtype)
        results[rtype] = records

        if records:
            # Print to console
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {Fore.YELLOW}{rtype:<6}{Style.RESET_ALL}", end=" ")
            for i, r in enumerate(records):
                if i == 0:
                    print(r)
                else:
                    print(f"{'':>12} {r}")

            # Collect IPs
            if rtype == "A":
                all_ips.extend(records)
        else:
            print(f"  {Fore.RED}[-]{Style.RESET_ALL} {Fore.YELLOW}{rtype:<6}{Style.RESET_ALL} No record found")

    # Analyze TXT for security posture
    txt_analysis = analyze_txt_records(results.get("TXT", []))
    if txt_analysis:
        print(f"\n  {Fore.CYAN}[i] TXT Security Analysis:{Style.RESET_ALL}")
        for tag, _, message in txt_analysis:
            color = Fore.RED if "WEAK" in tag else Fore.GREEN
            print(f"      {color}{message}{Style.RESET_ALL}")

    results["ips_found"] = all_ips
    results["txt_analysis"] = [{"tag": t, "message": m} for t, _, m in txt_analysis]

    return results