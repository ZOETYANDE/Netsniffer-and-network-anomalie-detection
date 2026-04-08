"""
NetSniffer v2.0 — Export Module
Exports findings to JSON, CSV, and generates summary data.
"""

import json
import csv
import os
from datetime import datetime, timezone


def export_json(findings, metadata, output_path):
    """Export findings as structured JSON."""
    data = {
        "report": {
            "tool": "NetSniffer",
            "version": "2.0",
            "generated": datetime.now(timezone.utc).isoformat(),
            "source_timestamp": metadata.get("timestamp", ""),
            "hostname": metadata.get("hostname", ""),
        },
        "summary": _summary(findings),
        "findings": [
            {
                "id": f.id,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "recommendation": f.recommendation,
                "rule_id": f.rule_id,
            }
            for f in findings
        ],
    }
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    print(f"  [+] JSON: {output_path}")


def export_csv(findings, output_path):
    """Export findings as CSV."""
    with open(output_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["ID", "Severity", "Category", "Title", "Description", "Evidence", "Recommendation"])
        for f in findings:
            writer.writerow([f.id, f.severity, f.category, f.title, f.description, f.evidence, f.recommendation])
    print(f"  [+] CSV:  {output_path}")


def export_syslog(findings, output_path):
    """Export findings in CEF (Common Event Format) for SIEM integration."""
    severity_map = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
    lines = []
    for f in findings:
        sev = severity_map.get(f.severity, 0)
        cef = (
            f"CEF:0|NetSniffer|AnomalyDetector|2.0|{f.rule_id}|{f.title}|{sev}|"
            f"cat={f.category} severity={f.severity} msg={f.description}"
        )
        lines.append(cef)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"  [+] CEF:  {output_path}")


def _summary(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    risk = counts["CRITICAL"] * 40 + counts["HIGH"] * 25 + counts["MEDIUM"] * 10 + counts["LOW"] * 5
    label = "CRITICAL" if risk >= 80 else "HIGH" if risk >= 50 else "MEDIUM" if risk >= 20 else "LOW"
    return {"total": len(findings), "counts": counts, "risk_score": risk, "risk_label": label}
