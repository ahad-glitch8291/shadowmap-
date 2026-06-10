"""
data/vuln_db.py — Local vulnerability database

LESSON: Real scanners like Nessus and OpenVAS use massive CVE databases
updated daily. We build a focused one covering the most commonly found
vulnerabilities in real pentests.

A CVE (Common Vulnerabilities and Exposures) is a unique ID assigned
to every publicly known security flaw. Format: CVE-YEAR-NUMBER
Each has a CVSS score (0-10):
  9.0-10.0 → Critical
  7.0-8.9  → High
  4.0-6.9  → Medium
  0.1-3.9  → Low

This database maps service banners → known CVEs.
The key insight: if a server tells you "Apache 2.4.7", you can look up
every CVE affecting that version. This is exactly what Nessus does.
"""

# Structure: service → list of {version_pattern, cve, cvss, description, fix}
VULN_DB = {
    "ssh": [
        {
            "pattern": "openssh_6",
            "cve": "CVE-2016-6515",
            "cvss": 7.8,
            "severity": "HIGH",
            "description": "OpenSSH 6.x — DoS via crafted authentication requests (auth_password)",
            "fix": "Upgrade to OpenSSH 8.0+"
        },
        {
            "pattern": "openssh_6",
            "cve": "CVE-2016-0777",
            "cvss": 6.4,
            "severity": "MEDIUM",
            "description": "OpenSSH 6.x — Roaming feature leaks private key material to malicious server",
            "fix": "Upgrade to OpenSSH 7.1p2+ or disable UseRoaming"
        },
        {
            "pattern": "openssh_7.2",
            "cve": "CVE-2016-6210",
            "cvss": 5.3,
            "severity": "MEDIUM",
            "description": "OpenSSH 7.2 — Username enumeration via timing attack",
            "fix": "Upgrade to OpenSSH 7.3+"
        },
        {
            "pattern": "openssh_5",
            "cve": "CVE-2010-4478",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "OpenSSH 5.x — J-PAKE authentication bypass allows login without credentials",
            "fix": "Upgrade to OpenSSH 7.0+ immediately"
        },
    ],
    "http": [
        {
            "pattern": "apache/2.4.7",
            "cve": "CVE-2014-0226",
            "cvss": 6.8,
            "severity": "MEDIUM",
            "description": "Apache 2.4.7 — Race condition in mod_status enables heap buffer overflow",
            "fix": "Upgrade to Apache 2.4.10+"
        },
        {
            "pattern": "apache/2.4.7",
            "cve": "CVE-2014-0117",
            "cvss": 4.3,
            "severity": "MEDIUM",
            "description": "Apache 2.4.7 — mod_proxy DoS via crafted HTTP requests",
            "fix": "Upgrade to Apache 2.4.10+"
        },
        {
            "pattern": "apache/2.2",
            "cve": "CVE-2011-3192",
            "cvss": 7.8,
            "severity": "HIGH",
            "description": "Apache 2.2 — Range header DoS (Apache Killer) — easy to exploit remotely",
            "fix": "Upgrade to Apache 2.4+ immediately"
        },
        {
            "pattern": "nginx/1.1",
            "cve": "CVE-2013-2028",
            "cvss": 7.5,
            "severity": "HIGH",
            "description": "Nginx 1.1 — Stack buffer overflow via crafted HTTP chunked transfer",
            "fix": "Upgrade to Nginx 1.5.0+"
        },
        {
            "pattern": "iis/6.0",
            "cve": "CVE-2017-7269",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": "IIS 6.0 — WebDAV buffer overflow — CRITICAL, actively exploited in the wild",
            "fix": "Upgrade to IIS 8.5+ or disable WebDAV immediately"
        },
    ],
    "ftp": [
        {
            "pattern": "vsftpd 2.3.4",
            "cve": "CVE-2011-2523",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": "vsftpd 2.3.4 — BACKDOOR in source code! Smiley face ':)' in username triggers shell on port 6200",
            "fix": "Replace immediately — this version was trojaned"
        },
        {
            "pattern": "proftpd 1.3.3",
            "cve": "CVE-2010-4221",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": "ProFTPD 1.3.3 — Remote code execution via TELNET_IAC buffer overflow",
            "fix": "Upgrade to ProFTPD 1.3.4+"
        },
        {
            "pattern": "wu-ftpd",
            "cve": "CVE-2001-0550",
            "cvss": 10.0,
            "severity": "CRITICAL",
            "description": "WU-FTPD — Remote root exploit via glob expansion — ancient but still found",
            "fix": "Replace with vsftpd or ProFTPD immediately"
        },
    ],
    "smtp": [
        {
            "pattern": "sendmail",
            "cve": "CVE-2014-3956",
            "cvss": 4.3,
            "severity": "MEDIUM",
            "description": "Sendmail — File descriptor leak via sm_io_fopen",
            "fix": "Upgrade to Sendmail 8.14.9+"
        },
        {
            "pattern": "exim 4",
            "cve": "CVE-2019-10149",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "Exim 4 — Remote command execution via malformed recipient address (The Return of the WIZard)",
            "fix": "Upgrade to Exim 4.92+"
        },
    ],
    "mysql": [
        {
            "pattern": "5.5",
            "cve": "CVE-2016-6662",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "MySQL 5.5 — Remote root code execution via config file injection",
            "fix": "Upgrade to MySQL 5.7.15+"
        },
        {
            "pattern": "5.6",
            "cve": "CVE-2016-6662",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "MySQL 5.6 — Remote root code execution via config file injection",
            "fix": "Upgrade to MySQL 5.7.15+"
        },
    ],
    "rdp": [
        {
            "pattern": "",  # affects all RDP
            "cve": "CVE-2019-0708",
            "cvss": 9.8,
            "severity": "CRITICAL",
            "description": "BlueKeep — Pre-auth RCE in RDP. No credentials needed. Wormable.",
            "fix": "Apply MS19-0708 patch immediately, disable RDP if unused"
        },
    ],
    "smb": [
        {
            "pattern": "",
            "cve": "CVE-2017-0144",
            "cvss": 9.3,
            "severity": "CRITICAL",
            "description": "EternalBlue — SMBv1 RCE used by WannaCry ransomware. Still unpatched on many systems.",
            "fix": "Disable SMBv1, apply MS17-010 patch"
        },
    ],
}

# Default credentials to test — most commonly found in the wild
DEFAULT_CREDS = {
    "ssh": [
        ("root", "root"), ("root", "toor"), ("root", "password"),
        ("admin", "admin"), ("admin", "password"), ("admin", "1234"),
        ("user", "user"), ("pi", "raspberry"), ("ubuntu", "ubuntu"),
        ("vagrant", "vagrant"), ("test", "test"),
    ],
    "ftp": [
        ("anonymous", "anonymous"), ("anonymous", ""),
        ("ftp", "ftp"), ("admin", "admin"),
        ("root", "root"), ("guest", "guest"),
    ],
    "mysql": [
        ("root", ""), ("root", "root"), ("root", "password"),
        ("root", "mysql"), ("admin", "admin"),
    ],
}

# SSL/TLS weak configurations
SSL_ISSUES = {
    "SSLv2":   ("CRITICAL", "SSLv2 is completely broken — DROWN attack possible"),
    "SSLv3":   ("HIGH",     "SSLv3 vulnerable to POODLE attack — padding oracle"),
    "TLSv1.0": ("MEDIUM",   "TLS 1.0 vulnerable to BEAST attack"),
    "TLSv1.1": ("LOW",      "TLS 1.1 deprecated — upgrade to TLS 1.2+"),
}