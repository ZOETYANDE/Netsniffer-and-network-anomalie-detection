"""
NetSniffer v2.0 — HTML Report Generator
Professional dark-themed audit report with severity badges.
"""

from html import escape as h


COLORS = {
    "CRITICAL": {"bg": "#dc2626", "border": "#991b1b", "glow": "rgba(220,38,38,0.3)"},
    "HIGH":     {"bg": "#ea580c", "border": "#c2410c", "glow": "rgba(234,88,12,0.3)"},
    "MEDIUM":   {"bg": "#d97706", "border": "#b45309", "glow": "rgba(217,119,6,0.3)"},
    "LOW":      {"bg": "#0284c7", "border": "#0369a1", "glow": "rgba(2,132,199,0.3)"},
}
ICONS = {"CRITICAL": "&#x1F534;", "HIGH": "&#x1F7E0;", "MEDIUM": "&#x1F7E1;", "LOW": "&#x1F535;"}
RISK_COLORS = {"CRITICAL": "#dc2626", "HIGH": "#ea580c", "MEDIUM": "#d97706", "LOW": "#22c55e"}


def _badge(sev):
    c = COLORS.get(sev, COLORS["LOW"])
    icon = ICONS.get(sev, "")
    return f'<span class="badge" style="background:{c["bg"]};border:1px solid {c["border"]};box-shadow:0 0 12px {c["glow"]}">{icon} {sev}</span>'


def generate_html(data, findings, org, baseline):
    meta = data.get("metadata", {})
    ts = h(meta.get("timestamp", "N/A"))
    hostname = h(meta.get("hostname", "N/A"))
    user = h(meta.get("user", "N/A"))
    kernel = h(meta.get("kernel", "N/A"))
    os_info = h(meta.get("os", "N/A"))
    org_name = h(org.get("name", "IT Security Audit"))
    classification = h(org.get("classification", "CONFIDENTIAL"))

    total = len(findings)
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    risk_score = counts["CRITICAL"] * 40 + counts["HIGH"] * 25 + counts["MEDIUM"] * 10 + counts["LOW"] * 5
    risk_label = "CRITICAL" if risk_score >= 80 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 20 else "LOW"
    risk_color = RISK_COLORS.get(risk_label, "#6b7280")
    categories = len(set(f.category for f in findings)) if findings else 0

    # Summary cards
    cards = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = COLORS[sev]
        cards += f'<div class="summary-card" style="border-left:4px solid {c["bg"]}"><div class="card-count" style="color:{c["bg"]}">{counts[sev]}</div><div class="card-label">{ICONS[sev]} {sev}</div></div>'

    # Table rows
    rows = ""
    for f in findings:
        rows += f'<tr><td class="mono">{h(f.id)}</td><td>{_badge(f.severity)}</td><td>{h(f.category)}</td><td><strong>{h(f.title)}</strong></td></tr>'

    # Detail cards
    details = ""
    for f in findings:
        c = COLORS.get(f.severity, COLORS["LOW"])
        details += f'''<div class="finding-card" style="border-left:4px solid {c["bg"]}">
<div class="finding-header"><span class="finding-id">{h(f.id)}</span>{_badge(f.severity)}<span class="finding-category">{h(f.category)}</span></div>
<h3>{h(f.title)}</h3><div class="finding-body">
<div class="finding-section"><h4>Description</h4><p>{h(f.description)}</p></div>
<div class="finding-section evidence"><h4>Evidence</h4><pre>{h(f.evidence)}</pre></div>
<div class="finding-section recommendation"><h4>Recommendation</h4><p>{h(f.recommendation)}</p></div>
</div></div>'''

    # Baseline
    gw = baseline.get("gateway", baseline.get("gateway_ip", "N/A"))
    gw_str = ", ".join(gw) if isinstance(gw, list) else gw
    bl = f'''<div class="baseline-grid">
<div class="baseline-item"><span class="bl-label">Segments</span><span class="bl-value">{h(', '.join(baseline.get('segments', [])))}</span></div>
<div class="baseline-item"><span class="bl-label">DNS Servers</span><span class="bl-value">{h(', '.join(baseline.get('dns_servers', [])))}</span></div>
<div class="baseline-item"><span class="bl-label">DNS Provider</span><span class="bl-value">{h(baseline.get('dns_provider', 'N/A'))}</span></div>
<div class="baseline-item"><span class="bl-label">Gateways</span><span class="bl-value">{h(gw_str)}</span></div>
<div class="baseline-item"><span class="bl-label">Machine IP</span><span class="bl-value">{h(baseline.get('machine_ip', 'N/A'))}</span></div>
<div class="baseline-item"><span class="bl-label">Blocked Domains</span><span class="bl-value">{h(', '.join(baseline.get('blocked_domains', [])))}</span></div>
</div>'''

    table_section = f'''<table class="findings-table"><thead><tr><th style="width:90px">ID</th><th style="width:120px">Severity</th><th style="width:180px">Category</th><th>Finding</th></tr></thead><tbody>{rows}</tbody></table>''' if findings else '<div class="no-findings"><div class="icon">&#x2705;</div><h3>No Anomalies Detected</h3><p>All checks passed.</p></div>'

    details_section = f'<div class="section"><div class="section-header"><span class="section-icon">&#x1F50D;</span><h2>Detailed Findings</h2></div>{details}</div>' if findings else ""

    return f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>NetSniffer Audit Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root{{--bg:#0a0e1a;--bg2:#111827;--card:#1a1f35;--border:#2a3055;--text:#e2e8f0;--text2:#94a3b8;--muted:#64748b;--accent:#6366f1;--grad:linear-gradient(135deg,#6366f1,#8b5cf6,#a855f7)}}
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);line-height:1.6}}
.container{{max-width:1200px;margin:0 auto;padding:0 24px}}
.report-header{{background:linear-gradient(135deg,#0f172a,#1e1b4b,#0f172a);border-bottom:1px solid var(--border);padding:48px 0 40px;position:relative;overflow:hidden}}
.report-header::before{{content:'';position:absolute;top:-50%;right:-10%;width:500px;height:500px;background:radial-gradient(circle,rgba(99,102,241,0.15),transparent 70%);pointer-events:none}}
.header-top{{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px;position:relative;z-index:1}}
.logo{{display:flex;align-items:center;gap:16px}}
.logo-icon{{width:52px;height:52px;background:var(--grad);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px;box-shadow:0 4px 20px rgba(99,102,241,0.3)}}
.logo-text h1{{font-size:26px;font-weight:800;background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.logo-text p{{font-size:13px;color:var(--muted)}}
.report-meta{{text-align:right;font-size:13px;color:var(--text2)}}
.report-meta .classification{{background:rgba(220,38,38,0.15);border:1px solid rgba(220,38,38,0.3);border-radius:6px;padding:4px 12px;font-weight:700;color:#fca5a5;font-size:11px;text-transform:uppercase;letter-spacing:1px;display:inline-block;margin-bottom:8px}}
.header-info{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;position:relative;z-index:1}}
.info-item{{background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:14px 18px}}
.info-item .label{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);margin-bottom:4px;font-weight:600}}
.info-item .value{{font-size:14px;font-weight:500}}
.risk-banner{{background:var(--bg2);border:1px solid var(--border);border-radius:12px;padding:28px 32px;margin:-24px 0 32px;display:flex;align-items:center;justify-content:space-between;gap:24px;box-shadow:0 10px 40px rgba(0,0,0,0.4);position:relative;z-index:2}}
.risk-score{{display:flex;align-items:center;gap:20px}}
.risk-circle{{width:80px;height:80px;border-radius:50%;display:flex;flex-direction:column;align-items:center;justify-content:center;border:3px solid;font-weight:800;font-size:28px}}
.risk-circle small{{font-size:10px;font-weight:600;text-transform:uppercase;opacity:0.8}}
.risk-details h2{{font-size:18px;font-weight:700;margin-bottom:4px}}
.risk-details p{{font-size:13px;color:var(--text2)}}
.section{{margin-bottom:40px;animation:fadeInUp 0.5s ease-out}}
.section-header{{display:flex;align-items:center;gap:12px;margin-bottom:20px;padding-bottom:12px;border-bottom:1px solid var(--border)}}
.section-header h2{{font-size:20px;font-weight:700}}
.section-header .section-icon{{font-size:22px}}
.section-header .section-count{{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:4px 14px;font-size:12px;font-weight:600;color:var(--text2);margin-left:auto}}
.summary-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:36px}}
.summary-card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:24px;text-align:center;transition:all 0.3s;box-shadow:0 4px 20px rgba(0,0,0,0.3)}}
.summary-card:hover{{transform:translateY(-2px);background:#222845}}
.card-count{{font-size:42px;font-weight:800;line-height:1;margin-bottom:8px}}
.card-label{{font-size:13px;color:var(--text2);font-weight:600;text-transform:uppercase;letter-spacing:0.5px}}
.findings-table{{width:100%;border-collapse:separate;border-spacing:0;background:var(--card);border:1px solid var(--border);border-radius:12px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.3)}}
.findings-table th{{background:rgba(99,102,241,0.08);padding:14px 20px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:0.8px;color:var(--muted);font-weight:700;border-bottom:1px solid var(--border)}}
.findings-table td{{padding:14px 20px;border-bottom:1px solid rgba(255,255,255,0.04);font-size:14px;vertical-align:middle}}
.findings-table tr:last-child td{{border-bottom:none}}
.findings-table tr:hover td{{background:rgba(255,255,255,0.02)}}
.mono{{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent);font-weight:500}}
.badge{{display:inline-flex;align-items:center;gap:6px;padding:4px 14px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;white-space:nowrap;color:#fff}}
.finding-card{{background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:20px;overflow:hidden;box-shadow:0 4px 20px rgba(0,0,0,0.3);transition:all 0.3s;animation:fadeInUp 0.4s ease-out}}
.finding-card:hover{{box-shadow:0 8px 30px rgba(0,0,0,0.4);transform:translateY(-1px)}}
.finding-header{{display:flex;align-items:center;gap:12px;padding:16px 24px;background:rgba(255,255,255,0.02);border-bottom:1px solid rgba(255,255,255,0.04)}}
.finding-id{{font-family:'JetBrains Mono',monospace;font-size:13px;color:var(--accent);font-weight:600}}
.finding-category{{margin-left:auto;font-size:12px;color:var(--muted);font-weight:500}}
.finding-card h3{{padding:16px 24px 0;font-size:16px;font-weight:700}}
.finding-body{{padding:16px 24px 24px}}
.finding-section{{margin-bottom:16px}}
.finding-section:last-child{{margin-bottom:0}}
.finding-section h4{{font-size:12px;text-transform:uppercase;letter-spacing:0.8px;color:var(--muted);margin-bottom:8px;font-weight:700}}
.finding-section p{{font-size:14px;color:var(--text2);line-height:1.7}}
.finding-section pre{{background:rgba(0,0,0,0.3);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:14px 18px;font-family:'JetBrains Mono',monospace;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
.finding-section.evidence{{background:rgba(0,0,0,0.15);border-radius:8px;padding:16px;margin:0 -8px}}
.finding-section.recommendation{{background:rgba(99,102,241,0.05);border:1px solid rgba(99,102,241,0.1);border-radius:8px;padding:16px;margin:0 -8px}}
.finding-section.recommendation p{{color:#a5b4fc}}
.baseline-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px}}
.baseline-item{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px 20px;display:flex;flex-direction:column;gap:6px}}
.bl-label{{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--muted);font-weight:700}}
.bl-value{{font-size:14px;font-weight:500;font-family:'JetBrains Mono',monospace}}
.no-findings{{text-align:center;padding:60px 32px;background:var(--card);border:1px solid var(--border);border-radius:12px}}
.no-findings .icon{{font-size:48px;margin-bottom:16px}}
.no-findings h3{{font-size:20px;margin-bottom:8px;color:#22c55e}}
.no-findings p{{color:var(--text2)}}
.report-footer{{text-align:center;padding:32px 0;border-top:1px solid var(--border);margin-top:48px}}
.report-footer p{{font-size:12px;color:var(--muted)}}
.report-footer .brand{{font-weight:700;background:var(--grad);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
@keyframes fadeInUp{{from{{opacity:0;transform:translateY(20px)}}to{{opacity:1;transform:translateY(0)}}}}
@media(max-width:768px){{.summary-grid{{grid-template-columns:repeat(2,1fr)}}.header-top{{flex-direction:column;gap:16px}}.risk-banner{{flex-direction:column;text-align:center}}.baseline-grid{{grid-template-columns:1fr}}}}
@media print{{body{{background:#fff;color:#1a1a1a}}.report-header{{background:#f8fafc;border-bottom:2px solid #e2e8f0}}.logo-text h1{{-webkit-text-fill-color:#6366f1}}.summary-card,.finding-card,.baseline-item,.risk-banner{{background:#fff;border-color:#e2e8f0;box-shadow:none}}.findings-table th{{background:#f1f5f9}}.finding-section pre{{background:#f8fafc;border-color:#e2e8f0}}}}
</style></head><body>
<header class="report-header"><div class="container">
<div class="header-top"><div class="logo"><div class="logo-icon">&#x1F6E1;&#xFE0F;</div><div class="logo-text"><h1>NetSniffer v2.0</h1><p>Network Anomaly Detection &mdash; {h(org_name)}</p></div></div>
<div class="report-meta"><div class="classification">{classification}</div><br>Report: {ts}</div></div>
<div class="header-info">
<div class="info-item"><div class="label">Hostname</div><div class="value">{hostname}</div></div>
<div class="info-item"><div class="label">Operator</div><div class="value">{user}</div></div>
<div class="info-item"><div class="label">Kernel</div><div class="value">{kernel}</div></div>
<div class="info-item"><div class="label">OS</div><div class="value">{os_info}</div></div>
</div></div></header>
<main class="container">
<div class="risk-banner"><div class="risk-score">
<div class="risk-circle" style="border-color:{risk_color};color:{risk_color}">{risk_score}<small>Score</small></div>
<div class="risk-details"><h2>Overall Risk: {risk_label}</h2><p>{total} finding{"s" if total != 1 else ""} across {categories} categories</p></div>
</div><div>{_badge(risk_label)}</div></div>
<div class="section"><div class="section-header"><span class="section-icon">&#x1F4CA;</span><h2>Findings Summary</h2></div><div class="summary-grid">{cards}</div></div>
<div class="section"><div class="section-header"><span class="section-icon">&#x1F4CB;</span><h2>Findings Index</h2><span class="section-count">{total} total</span></div>{table_section}</div>
{details_section}
<div class="section"><div class="section-header"><span class="section-icon">&#x2699;&#xFE0F;</span><h2>Network Baseline</h2></div>{bl}</div>
</main>
<footer class="report-footer"><div class="container"><p>Generated by <span class="brand">NetSniffer v2.0</span> &mdash; Network Anomaly Detection Suite</p><p style="margin-top:6px">This report is {classification.lower()}. Distribution restricted to authorized personnel.</p></div></footer>
</body></html>'''
