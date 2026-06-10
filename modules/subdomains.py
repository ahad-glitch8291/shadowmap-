"""
modules/subdomains.py
Subdomain enumeration using two techniques:

TECHNIQUE 1 — DNS Brute Force
  We take a wordlist of common subdomain names (mail, dev, api, admin...)
  and try resolving: mail.example.com, dev.example.com, etc.
  If DNS returns an IP → the subdomain exists.

  LESSON: Companies often expose dev/staging/admin subdomains with
  weaker security than their main site. These are prime targets.

TECHNIQUE 2 — Certificate Transparency (CT) Logs
  When a company gets an SSL certificate, it's logged publicly in
  CT logs (crt.sh). We query this to find subdomains that DNS
  brute force might miss.

  LESSON: CT logs are a goldmine for recon — they reveal subdomains
  the target never intended to be found. No brute force needed.

We use threading to run many DNS queries in parallel — this is a
core performance technique you'll use in all network tools.
"""

import dns.resolver
import dns.exception
import requests
import concurrent.futures
import os
from colorama import Fore, Style


# Default wordlist — common subdomain names attackers try first
DEFAULT_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "m", "shop", "ftp", "mail2", "test", "portal",
    "ns", "ww1", "host", "support", "dev", "web", "api", "admin", "staging",
    "app", "cloud", "login", "auth", "dashboard", "static", "cdn", "media",
    "assets", "img", "images", "beta", "old", "new", "backup", "git",
    "gitlab", "jenkins", "jira", "confluence", "docs", "wiki", "status",
    "monitor", "metrics", "grafana", "kibana", "elasticsearch", "redis",
    "db", "database", "mysql", "postgres", "mongo", "internal", "intranet",
    "extranet", "cpanel", "whm", "plesk", "demo", "sandbox", "uat", "prod",
    "production", "preprod", "stage", "qa", "dev2", "api2", "v1", "v2",
]


def resolve_subdomain(subdomain):
    """
    Try to resolve a single subdomain.
    Returns (subdomain, ip) if it exists, or None if it doesn't.

    LESSON: We catch specific DNS exceptions so we don't crash on
    NXDOMAIN (doesn't exist) vs Timeout (network issue) vs real errors.
    """
    try:
        answers = dns.resolver.resolve(subdomain, "A", lifetime=3)
        ip = str(answers[0])
        return (subdomain, ip)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers):
        return None
    except Exception:
        return None


def fetch_ct_subdomains(domain):
    """
    Query crt.sh for certificate transparency logs.

    LESSON: Every time an HTTPS certificate is issued, it's logged
    in public CT logs by law (RFC 6962). crt.sh aggregates these.
    No rate limit, no auth required — completely passive.
    """
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Querying certificate transparency logs (crt.sh)...")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=10, headers={"User-Agent": "shadowmap/1.0"})
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                # CT entries can contain multiple names separated by newlines
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and "*" not in sub:
                        subdomains.add(sub)
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} CT logs: found {len(subdomains)} subdomains")
        else:
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} crt.sh returned {resp.status_code}")
    except Exception as e:
        print(f"  {Fore.RED}[!]{Style.RESET_ALL} CT log query failed: {e}")
    return subdomains


def brute_force_subdomains(domain, wordlist_path=None, threads=50):
    """
    DNS brute force using threading.

    LESSON: We use ThreadPoolExecutor — Python's way of running many
    tasks concurrently. DNS queries are I/O bound (we're waiting for
    network responses), so threading gives massive speedup.
    CPU-bound tasks would use multiprocessing instead.
    """
    # Load wordlist
    if wordlist_path and os.path.isfile(wordlist_path):
        with open(wordlist_path) as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Using custom wordlist: {len(words)} entries")
    else:
        words = DEFAULT_WORDLIST
        print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Using built-in wordlist: {len(words)} entries")

    candidates = [f"{w}.{domain}" for w in words]
    found = {}

    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Brute-forcing with {threads} threads...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(resolve_subdomain, sub): sub for sub in candidates}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                subdomain, ip = result
                found[subdomain] = ip
                print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {subdomain} → {Fore.WHITE}{ip}{Style.RESET_ALL}")

    return found


def run_subdomain_enum(domain, wordlist=None, threads=50):
    """Combine both techniques and return unified results."""
    results = {"found": {}, "live": [], "ct_only": [], "brute_only": []}

    # Technique 1: CT logs (passive, fast)
    ct_subs = fetch_ct_subdomains(domain)

    # Technique 2: Brute force
    print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} Starting DNS brute force...")
    brute_found = brute_force_subdomains(domain, wordlist, threads)

    # Resolve CT-discovered subdomains too
    if ct_subs:
        print(f"\n  {Fore.CYAN}[*]{Style.RESET_ALL} Resolving CT log subdomains...")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(resolve_subdomain, sub): sub for sub in ct_subs}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    subdomain, ip = result
                    if subdomain not in brute_found:
                        brute_found[subdomain] = ip
                        print(f"  {Fore.CYAN}[CT]{Style.RESET_ALL} {subdomain} → {Fore.WHITE}{ip}{Style.RESET_ALL}")

    results["found"] = brute_found
    results["live"] = list(brute_found.keys())
    results["ct_discovered"] = list(ct_subs)
    results["total"] = len(brute_found)

    print(f"\n  {Fore.GREEN}[✓]{Style.RESET_ALL} Total live subdomains found: {Fore.WHITE}{results['total']}{Style.RESET_ALL}")
    return results