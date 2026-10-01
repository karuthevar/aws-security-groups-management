#!/usr/bin/env python3
"""
AWS Security Audit Report Consolidation Engine
Merges multi-account and multi-region audit JSON reports into a single consolidated report,
calculates account risk concentration, and generates executive metrics without calendar timelines.
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from pathlib import Path


def parse_arguments():
    parser = argparse.ArgumentParser(description="Consolidate AWS Security Audit Reports")
    parser.add_argument("--reports-dir", "-d", help="Directory containing audit JSON reports")
    parser.add_argument("--files", "-f", nargs="+", help="Specific JSON files to consolidate")
    parser.add_argument("--output", "-o", required=True, help="Consolidated JSON output file path")
    return parser.parse_args()


def load_findings(file_paths):
    all_findings = []
    seen_signatures = set()

    for path in file_paths:
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    findings = data
                elif isinstance(data, dict) and "findings" in data:
                    findings = data["findings"]
                else:
                    continue

                for finding in findings:
                    if not isinstance(finding, dict):
                        continue
                    # Signature for deduplication
                    sig = (
                        finding.get("AccountId", ""),
                        finding.get("Region", ""),
                        finding.get("RuleId", ""),
                        finding.get("ResourceId", ""),
                    )
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        all_findings.append(finding)
        except Exception as e:
            print(f"Warning: Failed to parse {path}: {e}", file=sys.stderr)

    return all_findings


def compute_metrics(findings):
    accounts = set()
    regions = set()
    quick_wins = 0
    low_impact = 0
    high_risk = 0
    criticals = 0
    highs = 0
    account_stats = defaultdict(lambda: {"total": 0, "quick_wins": 0, "criticals": 0, "highs": 0, "name": ""})

    for f in findings:
        acc_id = f.get("AccountId", "Unknown")
        acc_name = f.get("AccountName", acc_id)
        region = f.get("Region", "global")
        impact = f.get("RemediationImpact", "LOW_IMPACT_REVIEW")
        sev = f.get("Severity", "MEDIUM")
        status = f.get("Status", "NON_COMPLIANT")

        if acc_id != "Unknown":
            accounts.add(acc_id)
        if region != "global":
            regions.add(region)

        if status == "NON_COMPLIANT":
            account_stats[acc_id]["total"] += 1
            account_stats[acc_id]["name"] = acc_name

            if impact == "ZERO_IMPACT_QUICK_WIN":
                quick_wins += 1
                account_stats[acc_id]["quick_wins"] += 1
            elif impact == "LOW_IMPACT_REVIEW":
                low_impact += 1
            elif impact == "HIGH_RISK_PLANNED_WINDOW":
                high_risk += 1

            if sev == "CRITICAL":
                criticals += 1
                account_stats[acc_id]["criticals"] += 1
            elif sev == "HIGH":
                highs += 1
                account_stats[acc_id]["highs"] += 1

    return {
        "total_findings": len(findings),
        "total_accounts": len(accounts),
        "total_regions": len(regions),
        "zero_impact_quick_wins": quick_wins,
        "low_impact_reviews": low_impact,
        "high_risk_planned_windows": high_risk,
        "critical_findings": criticals,
        "high_findings": highs,
        "account_concentration": dict(account_stats),
    }


def main():
    args = parse_arguments()
    files_to_process = []

    if args.files:
        files_to_process.extend(args.files)

    if args.reports_dir:
        pattern = os.path.join(args.reports_dir, "**", "*.json")
        for f in glob.glob(pattern, recursive=True):
            if "manifest" not in f.lower() and f != os.path.abspath(args.output):
                files_to_process.append(f)

    if not files_to_process:
        print("Error: No valid JSON files found to consolidate.", file=sys.stderr)
        sys.exit(1)

    print(f"Consolidating {len(files_to_process)} report files...")
    findings = load_findings(files_to_process)
    metrics = compute_metrics(findings)

    # Ensure output directory exists
    output_dir = os.path.dirname(os.path.abspath(args.output))
    os.makedirs(output_dir, exist_ok=True)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    print("\n" + "=" * 60)
    print(" AWS SECURITY REPORT CONSOLIDATION SUMMARY ")
    print("=" * 60)
    print(f"Total Unique Findings       : {metrics['total_findings']}")
    print(f"Total Accounts Represented  : {metrics['total_accounts']}")
    print(f"Total Regions Evaluated     : {metrics['total_regions']}")
    print(f"Zero-Impact Quick Wins      : {metrics['zero_impact_quick_wins']} (100% Zero Downtime)")
    print(f"Low-Impact Reviews          : {metrics['low_impact_reviews']}")
    print(f"High-Risk Planned Windows   : {metrics['high_risk_planned_windows']}")
    print(f"Critical Severity Findings  : {metrics['critical_findings']}")
    print(f"Consolidated Report Saved   : {args.output}")
    print("=" * 60)


if __name__ == "__main__":
    main()
