#!/usr/bin/env python3
"""
NetSniffer v2.0 -- Network Anomaly Analyzer
Enterprise-grade anomaly detection with multi-format export.

Usage:
    python3 analyzer.py
    python3 analyzer.py --config config/baseline.yml --format html,json,csv
    python3 analyzer.py --input outputs/audit_output.json --output-dir outputs/
    python3 analyzer.py --input outputs/ --merge   # Merge multi-host results
"""

import argparse
import json
import os
import sys
import glob
from pathlib import Path

# Fix Windows console encoding
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ("utf-8", "utf8"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Add project root to path
SCRIPT_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SCRIPT_DIR))

from lib.config import load_yaml_config, load_exceptions, DEFAULT_BASELINE, DEFAULT_ORG
from lib.detector import AnomalyDetector
from lib.reporter import generate_html
from lib.exporter import export_json, export_csv, export_syslog


VERSION = "2.0"


def print_banner():
    print()
    print("=" * 64)
    print("  NetSniffer v2.0 -- Network Anomaly Analyzer")
    print("  Enterprise Anomaly Detection Suite")
    print("=" * 64)
    print()


def print_summary(findings):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    icons = {"CRITICAL": "[!]", "HIGH": "[*]", "MEDIUM": "[-]", "LOW": "[.]"}
    print("+" + "-" * 42 + "+")
    print("|          FINDINGS SUMMARY                |")
    print("+" + "-" * 42 + "+")
    for sev, count in counts.items():
        bar = "#" * count + "." * (10 - min(count, 10))
        print(f"|  {icons[sev]} {sev:<10} {bar}  {count:>3}  |")
    print("+" + "-" * 42 + "+")
    print(f"|  Total: {len(findings):<33}|")
    print("+" + "-" * 42 + "+")
    print()

    for f in findings:
        icon = icons.get(f.severity, "[?]")
        print(f"  {icon} [{f.id}] [{f.severity}] {f.title}")
    print()


def load_audit_data(input_path, merge=False):
    """Load one or more audit JSON files."""
    datasets = []

    if os.path.isdir(input_path):
        files = sorted(glob.glob(os.path.join(input_path, "audit_output*.json")))
        if not files:
            print(f"[!] No audit_output*.json files found in {input_path}")
            sys.exit(1)
        for fp in files:
            print(f"  Loading: {fp}")
            with open(fp, "r", encoding="utf-8") as fh:
                datasets.append(json.load(fh))
    elif os.path.isfile(input_path):
        with open(input_path, "r", encoding="utf-8") as fh:
            datasets.append(json.load(fh))
    else:
        print(f"[!] Input not found: {input_path}")
        sys.exit(1)

    return datasets


def analyze_dataset(data, baseline, exceptions):
    """Run detection on a single dataset."""
    # Merge baseline from JSON data with config baseline
    json_baseline = data.get("baseline", {})
    merged = baseline.copy()
    for k, v in json_baseline.items():
        if v and k not in ("machine_ip", "machine_segment"):  # Prefer config for these
            merged[k] = v
    # But config values take precedence if set
    for k, v in baseline.items():
        if v is not None:
            merged[k] = v

    detector = AnomalyDetector(data, merged, exceptions)
    return detector.run_all()


def main():
    parser = argparse.ArgumentParser(
        description="NetSniffer v2.0 -- Network Anomaly Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 analyzer.py
  python3 analyzer.py --config config/baseline.yml --format html,json,csv
  python3 analyzer.py --input outputs/ --merge
  python3 analyzer.py --format html,json,csv,cef
        """,
    )
    parser.add_argument("-i", "--input", default=None,
        help="Input JSON file or directory (default: outputs/audit_output.json or audit_output.json)")
    parser.add_argument("-o", "--output-dir", default=None,
        help="Output directory for reports (default: outputs/)")
    parser.add_argument("-c", "--config", default=None,
        help="Path to baseline YAML config (default: config/baseline.yml)")
    parser.add_argument("-e", "--exceptions", default=None,
        help="Path to exceptions YAML (default: config/exceptions.yml)")
    parser.add_argument("-f", "--format", default="html",
        help="Output formats, comma-separated: html,json,csv,cef (default: html)")
    parser.add_argument("--merge", action="store_true",
        help="Merge multi-host results into a single report")
    parser.add_argument("-q", "--quiet", action="store_true",
        help="Suppress banner and detailed output")

    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    # Resolve paths
    config_path = args.config or str(SCRIPT_DIR / "config" / "baseline.yml")
    exceptions_path = args.exceptions or str(SCRIPT_DIR / "config" / "exceptions.yml")

    # Input: try outputs/ first, then current dir
    if args.input:
        input_path = args.input
    elif os.path.exists(str(SCRIPT_DIR / "outputs" / "audit_output.json")):
        input_path = str(SCRIPT_DIR / "outputs" / "audit_output.json")
    elif os.path.exists("audit_output.json"):
        input_path = "audit_output.json"
    else:
        print("[!] No audit data found. Run collector.sh first.")
        print("    Looked in: outputs/audit_output.json, ./audit_output.json")
        sys.exit(1)

    # Output dir
    output_dir = args.output_dir or str(SCRIPT_DIR / "outputs")
    os.makedirs(output_dir, exist_ok=True)

    # Load config
    print(f"[*] Config: {config_path}")
    baseline, org, _ = load_yaml_config(config_path)
    exceptions = load_exceptions(exceptions_path)
    if exceptions:
        print(f"[*] Loaded {len(exceptions)} exception(s)")

    # Load data
    print(f"[*] Loading audit data from: {input_path}")
    datasets = load_audit_data(input_path, args.merge)
    print(f"[*] Loaded {len(datasets)} dataset(s)")

    # Analyze
    all_findings = []
    primary_data = datasets[0]

    for i, data in enumerate(datasets):
        label = data.get("metadata", {}).get("host_label", f"host-{i+1}")
        if len(datasets) > 1:
            print(f"\n--- Analyzing: {label} ---")
        findings = analyze_dataset(data, baseline, exceptions)
        # Tag findings with host label for multi-host
        for f in findings:
            if len(datasets) > 1:
                f.title = f"[{label}] {f.title}"
        all_findings.extend(findings)

    # Dedupe and sort
    from lib.detector import SEVERITY_ORDER
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    # Re-number IDs
    for i, f in enumerate(all_findings, 1):
        f.id = f"NET-{i:03d}"

    # Print summary
    if not args.quiet:
        print_summary(all_findings)

    # Export
    formats = [f.strip().lower() for f in args.format.split(",")]
    print("[*] Generating reports...")

    if "html" in formats:
        html_path = os.path.join(output_dir, "audit_report.html")
        html = generate_html(primary_data, all_findings, org, baseline)
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html)
        print(f"  [+] HTML: {html_path}")

    if "json" in formats:
        export_json(all_findings, primary_data.get("metadata", {}), os.path.join(output_dir, "audit_report.json"))

    if "csv" in formats:
        export_csv(all_findings, os.path.join(output_dir, "audit_report.csv"))

    if "cef" in formats:
        export_syslog(all_findings, os.path.join(output_dir, "audit_report.cef"))

    print()
    print(f"[+] Reports saved to: {output_dir}/")
    print()


if __name__ == "__main__":
    main()
