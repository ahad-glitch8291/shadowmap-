"""
modules/cred_test.py — Default credential testing

LESSON: The most common way into systems isn't a fancy exploit —
it's default passwords. Studies show 40%+ of breaches involve
weak or default credentials. Every pentest includes credential testing.

Services we test:
  SSH  → Try common username/password combos via Paramiko
  FTP  → Try anonymous login + common creds via ftplib
  MySQL→ Try connecting with no password or common passwords

IMPORTANT ETHICS NOTE:
This module tests credentials only on systems you have authorization
to test. The DEFAULT_CREDS list mirrors what real attackers try.
Knowing what attackers do = knowing what to defend against.

LESSON — How SSH authentication works:
  1. Client connects, server sends its public key
  2. Client sends username + password (encrypted)
  3. Server checks against /etc/shadow
  4. Success or failure response

Paramiko is a Python SSH library that lets us automate this process.
When we get "Authentication failed" = credentials wrong
When we get no exception = credentials correct (we found a way in!)

RATE LIMITING: We add delays between attempts to be non-destructive.
Real attackers use delays to avoid triggering account lockouts.
"""

import socket
import ftplib
import time
from colorama import Fore, Style

try:
    import paramiko
    PARAMIKO_AVAILABLE = True
except ImportError:
    PARAMIKO_AVAILABLE = False

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from data.vuln_db import DEFAULT_CREDS


def test_ssh_creds(host, port=22, timeout=5):
    """
    Test SSH default credentials using Paramiko.

    LESSON: Paramiko implements the SSH2 protocol in pure Python.
    We use it the same way an attacker would — systematically
    trying credential combinations.

    AuthenticationException = wrong password (keep trying)
    No exception             = logged in! (critical finding)
    """
    if not PARAMIKO_AVAILABLE:
        print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} Paramiko not installed — skipping SSH credential test")
        print(f"      Install with: pip install paramiko")
        return {"tested": False, "reason": "paramiko not installed"}

    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Testing {len(DEFAULT_CREDS['ssh'])} SSH credential pairs on {host}:{port}...")

    results = {"tested": True, "vulnerable": False, "valid_creds": [], "attempts": 0}

    for username, password in DEFAULT_CREDS["ssh"]:
        results["attempts"] += 1
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(
                host, port=port,
                username=username, password=password,
                timeout=timeout, allow_agent=False,
                look_for_keys=False, banner_timeout=10
            )
            # If we reach here — login succeeded!
            print(f"  {Fore.RED}[!!!] CRITICAL — Default credentials work!{Style.RESET_ALL}")
            print(f"        Username: {username}  Password: {password}")
            results["vulnerable"] = True
            results["valid_creds"].append((username, password))
            client.close()

        except paramiko.AuthenticationException:
            # Wrong credentials — expected, keep going
            print(f"  {Fore.WHITE}[-]{Style.RESET_ALL} {username}:{password} — failed")

        except paramiko.SSHException as e:
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} SSH error: {e}")
            break  # SSH is refusing connections, stop

        except socket.timeout:
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} Timeout on {host}:{port}")
            break

        except Exception as e:
            if "Connection refused" in str(e):
                print(f"  {Fore.RED}[-]{Style.RESET_ALL} SSH port {port} not accessible")
                break
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} {username}:{password} — {str(e)[:50]}")

        finally:
            client.close()

        time.sleep(0.3)  # Small delay — avoid triggering lockouts

    if not results["vulnerable"]:
        print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} No default SSH credentials found ({results['attempts']} tested)")

    return results


def test_ftp_creds(host, port=21, timeout=5):
    """
    Test FTP — always check for anonymous login first.

    LESSON: Anonymous FTP allows anyone to login with username
    "anonymous" and any password (usually your email). Many old
    servers still have this enabled. It's a free file read/write
    on the server with zero authentication.
    """
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Testing FTP credentials on {host}:{port}...")
    results = {"tested": True, "vulnerable": False, "valid_creds": [], "anonymous": False}

    for username, password in DEFAULT_CREDS["ftp"]:
        try:
            ftp = ftplib.FTP()
            ftp.connect(host, port, timeout=timeout)
            ftp.login(username, password)

            # Success!
            if username == "anonymous":
                print(f"  {Fore.RED}[!!!] Anonymous FTP login enabled!{Style.RESET_ALL}")
                results["anonymous"] = True
            else:
                print(f"  {Fore.RED}[!!!] Default FTP credentials work: {username}:{password}{Style.RESET_ALL}")

            # Try to list directory — shows what's accessible
            try:
                files = ftp.nlst()
                print(f"        Accessible files: {files[:5]}")
            except Exception:
                pass

            results["vulnerable"] = True
            results["valid_creds"].append((username, password))
            ftp.quit()

        except ftplib.error_perm:
            print(f"  {Fore.WHITE}[-]{Style.RESET_ALL} FTP {username}:{password} — failed")
        except ConnectionRefusedError:
            print(f"  {Fore.RED}[-]{Style.RESET_ALL} FTP port {port} refused connection")
            break
        except Exception as e:
            print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} FTP {username}: {str(e)[:60]}")
            if "timed out" in str(e).lower():
                break

        time.sleep(0.2)

    if not results["vulnerable"]:
        print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} No default FTP credentials found")

    return results


def test_mysql_creds(host, port=3306, timeout=5):
    """
    Test MySQL for no-password root access.

    LESSON: MySQL exposed to the internet with no root password
    is an instant critical finding. Shockingly common on servers
    set up by developers who "just want it to work locally"
    and then accidentally expose port 3306.

    We use raw socket + MySQL protocol handshake rather than
    importing mysql-connector to keep dependencies minimal.
    Just connecting and getting the greeting packet tells us
    MySQL is there — then we report it.
    """
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Testing MySQL access on {host}:{port}...")
    results = {"tested": True, "vulnerable": False, "exposed": False}

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) == 0:
            # Read the MySQL greeting packet
            data = sock.recv(256)
            if data and len(data) > 4:
                # MySQL greeting starts with packet length + protocol version
                greeting = data.decode("utf-8", errors="ignore")
                print(f"  {Fore.RED}[!!!] MySQL is internet-exposed!{Style.RESET_ALL}")
                print(f"        Greeting: {greeting[:80].strip()}")
                results["exposed"] = True
                results["vulnerable"] = True

                # Try to extract MySQL version from greeting
                import re
                version_match = re.search(r"(\d+\.\d+\.\d+)", greeting)
                if version_match:
                    results["version"] = version_match.group(1)
                    print(f"        Version: MySQL {results['version']}")
            sock.close()
        else:
            print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} MySQL port not accessible externally (good)")
    except Exception as e:
        print(f"  {Fore.YELLOW}[!]{Style.RESET_ALL} MySQL check: {str(e)[:60]}")

    return results


def run_credential_tests(host, open_ports):
    """Run appropriate credential tests based on what ports are open."""
    results = {}
    port_numbers = [s["port"] for s in open_ports]

    if 22 in port_numbers:
        print(f"\n  {Fore.CYAN}── SSH Credential Test ──{Style.RESET_ALL}")
        results["ssh"] = test_ssh_creds(host, 22)

    if 21 in port_numbers:
        print(f"\n  {Fore.CYAN}── FTP Credential Test ──{Style.RESET_ALL}")
        results["ftp"] = test_ftp_creds(host, 21)

    if 3306 in port_numbers:
        print(f"\n  {Fore.CYAN}── MySQL Exposure Test ──{Style.RESET_ALL}")
        results["mysql"] = test_mysql_creds(host, 3306)

    return results