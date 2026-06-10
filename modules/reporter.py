"""
modules/reporter.py
Generates a clean, professional HTML report from scan results.

LESSON: Professional pentesters always deliver reports, not just terminal output.
A good report shows:
  - Executive summary (what did we find overall?)
  - Technical details per finding
  - Risk ratings
  - Recommendations

This is what makes your tool LinkedIn/portfolio-worthy — it looks professional
and produces something you can screenshot.
"""

import os
import json
from datetime import datetime
from colorama import Fore, Style


def severity_badge(risk):
    colors = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#27ae60", "INFO": "#3498db"}
    return f'<span style="background:{colors.get(risk,"#888")};color:white;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold">{risk}</span>'


def generate_report(domain, results, output_dir):
    """Generate an HTML report and return the file path."""

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    modules = results.get("modules", {})

    # ── Build HTML sections ─────────────────────────────────────────────────────

    # DNS section
    dns_html = ""
    if "dns" in modules:
        dns = modules["dns"]
        rows = ""
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            records = dns.get(rtype, [])
            if records:
                for r in records:
                    rows += f"<tr><td><code>{rtype}</code></td><td>{r}</td></tr>"
        analysis = dns.get("txt_analysis", [])
        analysis_html = ""
        for item in analysis:
            color = "#e74c3c" if "WEAK" in item.get("tag","") else "#27ae60"
            analysis_html += f'<div style="color:{color};margin:4px 0">● {item["message"]}</div>'

        dns_html = f"""
        <div class="card">
          <h2>🔍 DNS Records</h2>
          <table><thead><tr><th>Type</th><th>Record</th></tr></thead>
          <tbody>{rows}</tbody></table>
          {f'<div class="subcard"><h3>Security Analysis</h3>{analysis_html}</div>' if analysis_html else ""}
        </div>"""

    # WHOIS section
    whois_html = ""
    if "whois" in modules:
        w = modules["whois"]
        rows = ""
        for k, v in w.items():
            if k not in ("days_until_expiry",) and v and v != "N/A":
                rows += f"<tr><td>{k}</td><td>{v}</td></tr>"
        exp = w.get("days_until_expiry")
        exp_note = ""
        if exp is not None:
            color = "#e74c3c" if exp < 30 else "#f39c12" if exp < 90 else "#27ae60"
            exp_note = f'<div style="color:{color};margin-top:8px">Expires in {exp} days</div>'
        whois_html = f"""
        <div class="card">
          <h2>📋 WHOIS Intelligence</h2>
          <table><thead><tr><th>Field</th><th>Value</th></tr></thead>
          <tbody>{rows}</tbody></table>
          {exp_note}
        </div>"""

    # Subdomains section
    subs_html = ""
    if "subdomains" in modules:
        subs = modules["subdomains"]
        found = subs.get("found", {})
        rows = ""
        for sub, ip in sorted(found.items()):
            rows += f"<tr><td>{sub}</td><td><code>{ip}</code></td></tr>"
        ct_count = len(subs.get("ct_discovered", []))
        subs_html = f"""
        <div class="card">
          <h2>🌐 Subdomain Enumeration</h2>
          <div class="stat-row">
            <div class="stat"><span class="stat-num">{len(found)}</span>Live subdomains</div>
            <div class="stat"><span class="stat-num">{ct_count}</span>CT log entries</div>
          </div>
          {f'<table><thead><tr><th>Subdomain</th><th>IP Address</th></tr></thead><tbody>{rows}</tbody></table>' if rows else '<p class="muted">No live subdomains found</p>'}
        </div>"""

    # Ports section
    ports_html = ""
    if "ports" in modules:
        port_data = modules["ports"]
        cards = ""
        for host, ports in port_data.items():
            rows = ""
            for p in ports:
                risk = p.get("risk", "LOW")
                banner = p.get("banner", "")
                rows += f"""<tr>
                  <td><strong>{p['port']}</strong></td>
                  <td>{p['service']}</td>
                  <td>{severity_badge(risk)}</td>
                  <td style="font-size:12px;color:#888">{banner[:60] if banner else '—'}</td>
                </tr>"""
            if rows:
                cards += f"""
                <h3>{host}</h3>
                <table><thead><tr><th>Port</th><th>Service</th><th>Risk</th><th>Banner</th></tr></thead>
                <tbody>{rows}</tbody></table>"""
        ports_html = f"""
        <div class="card">
          <h2>🔌 Open Ports</h2>
          {cards if cards else '<p class="muted">No open ports detected</p>'}
        </div>"""

    # Tech section
    tech_html = ""
    if "tech" in modules:
        t = modules["tech"]
        techs = t.get("technologies", {})
        present = t.get("security_headers", {}).get("present", [])
        missing = t.get("security_headers", {}).get("missing", [])

        tech_badges = "".join(
            f'<span style="background:#2c3e50;color:#ecf0f1;padding:4px 12px;border-radius:20px;margin:4px;display:inline-block">{name} {ver}</span>'
            for name, ver in techs.items()
        ) or "<span class='muted'>No signatures detected (hardened server)</span>"

        sec_rows = ""
        for h in present:
            sec_rows += f'<tr><td>✅</td><td>{h}</td><td style="color:#27ae60">Present</td></tr>'
        for h in missing:
            sec_rows += f'<tr><td>❌</td><td>{h}</td><td style="color:#e74c3c">Missing</td></tr>'

        tech_html = f"""
        <div class="card">
          <h2>⚙️ Technology Stack</h2>
          <div style="margin:12px 0">{tech_badges}</div>
          <h3>Security Header Audit</h3>
          <table><thead><tr><th></th><th>Header</th><th>Status</th></tr></thead>
          <tbody>{sec_rows}</tbody></table>
          <div style="margin-top:8px;color:#e74c3c">⚠ {len(missing)} missing security headers</div>
        </div>"""

    # ── Full HTML ───────────────────────────────────────────────────────────────
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>shadowmap — {domain}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
  header {{ background: linear-gradient(135deg, #0a3d62, #1a1a2e); padding: 40px; border-bottom: 2px solid #00d2ff; }}
  header h1 {{ color: #00d2ff; font-size: 2em; font-family: monospace; }}
  header p {{ color: #8b949e; margin-top: 8px; }}
  .badge {{ display:inline-block; background:#00d2ff22; color:#00d2ff; border:1px solid #00d2ff44;
            padding:4px 12px; border-radius:20px; font-size:13px; margin:4px; }}
  main {{ max-width: 1000px; margin: 0 auto; padding: 32px 16px; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 12px;
           padding: 24px; margin-bottom: 24px; }}
  .card h2 {{ color: #58a6ff; margin-bottom: 16px; font-size: 1.2em; }}
  .card h3 {{ color: #8b949e; margin: 16px 0 8px; font-size: 1em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
  th {{ background: #21262d; color: #8b949e; padding: 8px 12px; text-align: left; font-weight: 600; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #21262d; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: #1c2128; }}
  code {{ background: #21262d; padding: 2px 6px; border-radius: 4px; font-family: monospace; color: #79c0ff; }}
  .stat-row {{ display: flex; gap: 16px; margin-bottom: 16px; }}
  .stat {{ background: #21262d; padding: 16px; border-radius: 8px; text-align: center; flex: 1; }}
  .stat-num {{ display: block; font-size: 2em; font-weight: bold; color: #58a6ff; }}
  .muted {{ color: #484f58; font-style: italic; }}
  .subcard {{ background: #21262d; border-radius: 8px; padding: 12px; margin-top: 12px; }}
  footer {{ text-align: center; color: #484f58; padding: 32px; font-size: 13px; }}
</style>
</head>
<body>
<header>
  <h1>🕵️ shadowmap</h1>
  <p>OSINT &amp; Recon Report</p>
  <div style="margin-top:16px">
    <span class="badge">🎯 {domain}</span>
    <span class="badge">📅 {timestamp}</span>
    <span class="badge">🔧 Modules: {', '.join(results.get('modules', {}).keys())}</span>
  </div>
</header>
<main>
  {dns_html}
  {whois_html}
  {subs_html}
  {ports_html}
  {tech_html}
</main>
<footer>
  Generated by shadowmap | For authorized security testing only<br>
  <span style="color:#30363d">Raw JSON also saved alongside this report</span>
</footer>
</body>
</html>"""

    report_path = os.path.join(output_dir, f"{domain}_report.html")
    with open(report_path, "w") as f:
        f.write(html)

    print(f"  {Fore.GREEN}[✓]{Style.RESET_ALL} HTML report written to {report_path}")
    return report_path