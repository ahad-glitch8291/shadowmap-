"""
modules/tech_detect.py
Technology fingerprinting via HTTP headers and response analysis.

LESSON: Servers leak a LOT about themselves in HTTP response headers.
Once you know the tech stack, you know which CVEs to look for.

Headers that reveal tech:
  Server: Apache/2.4.41 (Ubuntu)       → exact web server version
  X-Powered-By: PHP/7.2.0             → language + version (PHP 7.2 is EOL!)
  X-Generator: WordPress 5.8          → CMS version
  X-AspNet-Version: 4.0.30319        → .NET version
  Via: nginx/1.18                     → proxy/load balancer

LESSON: Headers like X-Powered-By should be REMOVED in production.
This is called "security through obscurity" — it's not real security
but it does raise the cost for attackers. A hardened server returns:
  Server: (blank)
  X-Powered-By: (absent)

We also check security headers — their ABSENCE is a finding:
  Content-Security-Policy  → prevents XSS attacks
  Strict-Transport-Security → forces HTTPS
  X-Frame-Options           → prevents clickjacking
  X-Content-Type-Options    → prevents MIME sniffing
"""

import requests
import re
from colorama import Fore, Style
from urllib3.exceptions import InsecureRequestWarning

# Suppress SSL warnings for fingerprinting (intentional)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# Signatures: (header_or_body_pattern, technology_name)
TECH_SIGNATURES = {
    "headers": {
        "server": [
            (r"apache",         "Apache"),
            (r"nginx",          "Nginx"),
            (r"iis",            "Microsoft IIS"),
            (r"lighttpd",       "Lighttpd"),
            (r"cloudflare",     "Cloudflare"),
            (r"litespeed",      "LiteSpeed"),
        ],
        "x-powered-by": [
            (r"php/(\S+)",      "PHP"),
            (r"asp\.net",       "ASP.NET"),
            (r"express",        "Express.js"),
        ],
        "x-generator": [
            (r"wordpress",      "WordPress"),
            (r"drupal",         "Drupal"),
            (r"joomla",         "Joomla"),
        ],
        "via": [
            (r"varnish",        "Varnish Cache"),
            (r"squid",          "Squid Proxy"),
        ],
    },
    "cookies": {
        "PHPSESSID":    "PHP",
        "JSESSIONID":   "Java/Tomcat",
        "ASP.NET_SessionId": "ASP.NET",
        "laravel_session": "Laravel",
        "ci_session":   "CodeIgniter",
        "rack.session": "Ruby/Rack",
    }
}

SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HSTS — forces HTTPS"),
    ("Content-Security-Policy",   "CSP — prevents XSS"),
    ("X-Frame-Options",           "Clickjacking protection"),
    ("X-Content-Type-Options",    "MIME sniffing protection"),
    ("Referrer-Policy",           "Referrer control"),
    ("Permissions-Policy",        "Feature/permission control"),
    ("X-XSS-Protection",         "Legacy XSS filter (deprecated but checked)"),
]


def fingerprint_headers(headers):
    """Identify technologies from HTTP headers."""
    detected = {}
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header_name, patterns in TECH_SIGNATURES["headers"].items():
        value = headers_lower.get(header_name, "")
        for pattern, tech in patterns:
            match = re.search(pattern, value, re.IGNORECASE)
            if match:
                # Try to extract version number
                version_match = re.search(r"[\d.]+", value)
                version = version_match.group() if version_match else ""
                detected[tech] = version
                break

    return detected


def check_security_headers(headers):
    """Check which security headers are present or missing."""
    present = []
    missing = []
    headers_lower = {k.lower() for k in headers.keys()}

    for header, description in SECURITY_HEADERS:
        if header.lower() in headers_lower:
            present.append((header, description))
        else:
            missing.append((header, description))

    return present, missing


def run_tech_detect(domain):
    """Fetch the target and fingerprint its technology stack."""
    results = {"technologies": {}, "security_headers": {}, "raw_headers": {}}

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        try:
            print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Fetching {url}...")
            resp = requests.get(
                url, timeout=8, verify=False,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0 (compatible; shadowmap/1.0)"}
            )
            print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} Response: {resp.status_code} | "
                  f"Final URL: {resp.url[:60]}")

            # Store raw headers
            results["raw_headers"] = dict(resp.headers)
            results["final_url"] = resp.url
            results["status_code"] = resp.status_code

            # Fingerprint
            tech = fingerprint_headers(resp.headers)

            # Check cookies
            for cookie_name, tech_name in TECH_SIGNATURES["cookies"].items():
                if cookie_name in resp.cookies:
                    tech[tech_name] = tech.get(tech_name, "detected via cookie")

            if tech:
                print(f"\n  {Fore.CYAN}[i] Technology Stack:{Style.RESET_ALL}")
                for name, version in tech.items():
                    print(f"      {Fore.WHITE}{name}{Style.RESET_ALL}"
                          + (f" {version}" if version else ""))
            else:
                print(f"  {Fore.YELLOW}[-]{Style.RESET_ALL} No technology signatures detected "
                      f"(server may be hardened)")

            results["technologies"] = tech

            # Security header audit
            present, missing = check_security_headers(resp.headers)
            results["security_headers"]["present"] = [h for h, _ in present]
            results["security_headers"]["missing"] = [h for h, _ in missing]

            print(f"\n  {Fore.CYAN}[i] Security Header Audit:{Style.RESET_ALL}")
            for h, desc in present:
                print(f"      {Fore.GREEN}✓{Style.RESET_ALL} {h} — {desc}")
            for h, desc in missing:
                print(f"      {Fore.RED}✗{Style.RESET_ALL} {Fore.RED}{h}{Style.RESET_ALL} — MISSING — {desc}")

            if missing:
                print(f"\n  {Fore.RED}  ⚠ {len(missing)} security headers missing — "
                      f"potential vulnerabilities{Style.RESET_ALL}")

            break  # Success — don't try HTTP if HTTPS worked

        except requests.exceptions.SSLError:
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} SSL error on {url} — trying HTTP...")
        except requests.exceptions.ConnectionError:
            print(f"  {Fore.RED}[-]{Style.RESET_ALL} Could not connect to {url}")
        except Exception as e:
            print(f"  {Fore.RED}[!]{Style.RESET_ALL} Error: {e}")

    return results