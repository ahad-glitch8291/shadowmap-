# shadowmap 🕵️

A passive OSINT & reconnaissance automation tool built in Python.

## What it does
- DNS enumeration (A, MX, NS, TXT, CNAME records)
- WHOIS intelligence gathering
- Subdomain enumeration via DNS brute force + Certificate Transparency logs
- Port scanning with service detection
- Technology fingerprinting via HTTP headers
- Generates professional HTML report

## Usage
```bash
pip install dnspython python-whois requests colorama
python3 shadowmap.py -d example.com
python3 shadowmap.py -d example.com --modules dns whois tech
```

## Legal
For authorized security testing only. Always get written permission before scanning.

## Part of my cybersecurity portfolio
Built as Phase 1 of a 5-phase ethical hacking project roadmap.
