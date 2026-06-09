"""
modules/reporter.py — Professional vulnerability report generator

LESSON: In real pentesting, the report IS the product.
A client pays for a pentest and receives a report. The quality
of that report determines if they'll hire you again.

A good vuln report has:
  1. Executive Summary — business risk in plain English
  2. Findings table — sorted by severity (Critical first)
  3. Per-finding detail — what it is, proof it exists, how to fix it
  4. Remediation roadmap — what to fix first
"""

import os
from datetime import datetime
from colorama import Fore, Style


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#2ecc71",
    "INFO":     "#3498db",
}


def count_by_severity(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        sev = f.get("severity", "LOW")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def severity_badge(sev):
    color = SEVERITY_COLORS.get(sev, "#888")
    return f'<span style="background:{color};color:{"#000" if sev=="MEDIUM" else "#fff"};padding:3px 10px;border-radius:4px;font-size:12px;font-weight:bold">{sev}</span>'


def generate_report(host, results, output_dir):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    services  = results.get("services", [])
    cve_finds = results.get("cve_findings", [])
    cred_res  = results.get("credential_tests", {})
    ssl_res   = results.get("ssl_checks", {})

    # Collect ALL findings into one list
    all_findings = list(cve_finds)

    # Add credential findings
    for svc, res in cred_res.items():
        if res.get("vulnerable"):
            for user, pwd in res.get("valid_creds", []):
                all_findings.append({
                    "port": {"ssh": 22, "ftp": 21, "mysql": 3306}.get(svc, 0),
                    "service": svc.upper(),
                    "version": "",
                    "cve": "N/A",
                    "cvss": 10.0,
                    "severity": "CRITICAL",
                    "description": f"Default credentials valid — {user}:{pwd}",
                    "fix": "Change default credentials immediately"
                })
        if res.get("anonymous"):
            all_findings.append({
                "port": 21, "service": "FTP", "version": "",
                "cve": "N/A", "cvss": 7.5, "severity": "HIGH",
                "description": "Anonymous FTP login enabled",
                "fix": "Disable anonymous FTP access"
            })

    # Add SSL findings
    for port, ssl_data in ssl_res.items():
        if ssl_data:
            for f in ssl_data.get("findings", []):
                all_findings.append({
                    "port": port, "service": "SSL/TLS", "version": "",
                    "cve": "N/A", "cvss": 7.0,
                    "severity": f["severity"],
                    "description": f"{f['issue']} — {f['detail']}",
                    "fix": f["fix"]
                })

    # Sort by severity
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity","LOW"), 4))
    counts = count_by_severity(all_findings)

    # Risk level
    if counts["CRITICAL"] > 0:
        risk_level, risk_color = "CRITICAL RISK", "#e74c3c"
    elif counts["HIGH"] > 0:
        risk_level, risk_color = "HIGH RISK", "#e67e22"
    elif counts["MEDIUM"] > 0:
        risk_level, risk_color = "MEDIUM RISK", "#f1c40f"
    else:
        risk_level, risk_color = "LOW RISK", "#2ecc71"

    # Build services table
    svc_rows = ""
    for s in services:
        banner_short = (s.get("banner","") or "")[:60].replace("<","&lt;")
        svc_rows += f"""<tr>
            <td><strong>{s['port']}</strong></td>
            <td>{s['service']}</td>
            <td><code>{s.get('version','') or '—'}</code></td>
            <td style="font-size:12px;color:#8b949e">{banner_short or '—'}</td>
        </tr>"""

    # Build findings table
    finding_rows = ""
    for f in all_findings:
        cve_badge = f'<code style="color:#79c0ff">{f["cve"]}</code>' if f["cve"] != "N/A" else "—"
        finding_rows += f"""<tr>
            <td>{severity_badge(f['severity'])}</td>
            <td>{f['port']}/{f['service']}</td>
            <td>{cve_badge}</td>
            <td>{f['cvss']}</td>
            <td>{f['description']}</td>
            <td style="color:#2ecc71;font-size:12px">{f['fix']}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>vulnscan — {host}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
  header{{background:linear-gradient(135deg,#1a0a0a,#1a1a2e);padding:40px;border-bottom:3px solid {risk_color}}}
  header h1{{color:{risk_color};font-size:2em;font-family:monospace}}
  header p{{color:#8b949e;margin-top:8px}}
  .risk-badge{{display:inline-block;background:{risk_color};color:white;padding:6px 18px;
              border-radius:6px;font-weight:bold;margin-top:12px;font-size:1.1em}}
  main{{max-width:1100px;margin:0 auto;padding:32px 16px}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:12px;padding:24px;margin-bottom:24px}}
  .card h2{{color:#58a6ff;margin-bottom:16px;font-size:1.2em}}
  .stats{{display:flex;gap:16px;margin-bottom:24px}}
  .stat{{flex:1;background:#161b22;border:1px solid #30363d;border-radius:12px;
         padding:20px;text-align:center}}
  .stat-num{{font-size:2.5em;font-weight:bold;display:block}}
  .stat-label{{color:#8b949e;font-size:13px;margin-top:4px}}
  table{{width:100%;border-collapse:collapse;font-size:14px}}
  th{{background:#21262d;color:#8b949e;padding:10px 12px;text-align:left;font-weight:600}}
  td{{padding:10px 12px;border-bottom:1px solid #21262d;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  tr:hover{{background:#1c2128}}
  code{{background:#21262d;padding:2px 6px;border-radius:4px;font-family:monospace;color:#79c0ff}}
  .badge{{display:inline-block;background:#21262d;color:#c9d1d9;padding:3px 10px;
          border-radius:20px;font-size:12px;margin:3px}}
  footer{{text-align:center;color:#484f58;padding:32px;font-size:13px}}
</style>
</head>
<body>
<header>
  <h1>🔍 vulnscan</h1>
  <p>Network Vulnerability Assessment Report</p>
  <div style="margin-top:12px">
    <span class="badge">🎯 {host}</span>
    <span class="badge">📅 {timestamp}</span>
    <span class="badge">🔎 {len(services)} services</span>
    <span class="badge">⚠ {len(all_findings)} findings</span>
  </div>
  <div class="risk-badge">Overall Risk: {risk_level}</div>
</header>
<main>

  <!-- Stats -->
  <div class="stats">
    <div class="stat">
      <span class="stat-num" style="color:#e74c3c">{counts['CRITICAL']}</span>
      <div class="stat-label">Critical</div>
    </div>
    <div class="stat">
      <span class="stat-num" style="color:#e67e22">{counts['HIGH']}</span>
      <div class="stat-label">High</div>
    </div>
    <div class="stat">
      <span class="stat-num" style="color:#f1c40f">{counts['MEDIUM']}</span>
      <div class="stat-label">Medium</div>
    </div>
    <div class="stat">
      <span class="stat-num" style="color:#2ecc71">{counts['LOW']}</span>
      <div class="stat-label">Low</div>
    </div>
    <div class="stat">
      <span class="stat-num" style="color:#58a6ff">{len(services)}</span>
      <div class="stat-label">Open Services</div>
    </div>
  </div>

  <!-- Services -->
  <div class="card">
    <h2>🔌 Discovered Services</h2>
    <table>
      <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>Banner</th></tr></thead>
      <tbody>{svc_rows or '<tr><td colspan="4" style="color:#484f58">No open services found</td></tr>'}</tbody>
    </table>
  </div>

  <!-- Findings -->
  <div class="card">
    <h2>⚠️ Vulnerability Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Port/Service</th><th>CVE</th><th>CVSS</th><th>Description</th><th>Remediation</th></tr></thead>
      <tbody>{finding_rows or '<tr><td colspan="6" style="color:#2ecc71">✓ No vulnerabilities found</td></tr>'}</tbody>
    </table>
  </div>

</main>
<footer>
  Generated by vulnscan | For authorized security testing only<br>
  <span style="color:#30363d">Phase 2 — Cybersecurity Learning Project</span>
</footer>
</body>
</html>"""

    path = os.path.join(output_dir, f"{host.replace('/','_')}_vulnscan.html")
    with open(path, "w") as f:
        f.write(html)

    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} Report → {path}")
    return path