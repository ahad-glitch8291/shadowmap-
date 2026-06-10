import whois
from colorama import Fore, Style
from datetime import datetime


def safe_str(value):
    if value is None:
        return "N/A"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value[:3])
    return str(value)


def days_until(date):
    if date is None:
        return None
    if isinstance(date, list):
        date = date[0]
    try:
        now = datetime.now()
        if hasattr(date, 'replace'):
            date = date.replace(tzinfo=None)
        return (date - now).days
    except Exception:
        return None


def run_whois(domain):
    print(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Querying WHOIS for {domain}...")
    try:
        w = whois.whois(domain)
    except Exception as e:
        print(f"  {Fore.RED}[!] WHOIS failed: {e}{Style.RESET_ALL}")
        return {"error": str(e)}

    fields = {
        "Registrar":    w.registrar,
        "Registrant":   w.get("org") or w.get("name"),
        "Admin email":  w.get("emails"),
        "Name servers": w.name_servers,
        "Created":      w.creation_date,
        "Updated":      w.updated_date,
        "Expires":      w.expiration_date,
        "Status":       w.status,
        "DNSSEC":       w.get("dnssec"),
    }

    results = {}
    for label, value in fields.items():
        s = safe_str(value)
        results[label] = s
        print(f"  {Fore.GREEN}[+]{Style.RESET_ALL} {Fore.YELLOW}{label:<18}{Style.RESET_ALL} {s}")

    print(f"\n  {Fore.CYAN}[i] Intelligence Notes:{Style.RESET_ALL}")

    creation = w.creation_date
    if creation:
        if isinstance(creation, list): creation = creation[0]
        try:
            age_days = (datetime.now() - creation.replace(tzinfo=None)).days
            age_years = age_days // 365
            if age_years < 1:
                print(f"  {Fore.RED}  ⚠ Domain is LESS than 1 year old{Style.RESET_ALL}")
            else:
                print(f"  {Fore.GREEN}  ✓ Domain age: ~{age_years} years old{Style.RESET_ALL}")
        except Exception:
            pass

    exp_days = days_until(w.expiration_date)
    if exp_days is not None:
        if exp_days < 30:
            print(f"  {Fore.RED}  ⚠ Expires in {exp_days} days — hijack target!{Style.RESET_ALL}")
        elif exp_days < 90:
            print(f"  {Fore.YELLOW}  ⚠ Expires in {exp_days} days{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}  ✓ Expires in {exp_days} days{Style.RESET_ALL}")

    registrant = str(w.get("org") or w.get("name") or "")
    if any(x in registrant.lower() for x in ["privacy", "redacted", "whoisguard", "protected"]):
        print(f"  {Fore.YELLOW}  [i] WHOIS privacy protection active{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}  ⚠ No WHOIS privacy — registrant info is public{Style.RESET_ALL}")

    results["days_until_expiry"] = exp_days
    return results
