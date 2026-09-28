#!/usr/bin/env python3
import os
import glob
import json
from collections import Counter, defaultdict

def analyze():
    target_dir = os.path.join("reports", "09 28 26")
    files = glob.glob(os.path.join(target_dir, "**", "compliance_report_*.json"), recursive=True)
    
    all_findings = []
    for f in files:
        try:
            with open(f, "r", encoding="utf-8") as jf:
                data = json.load(jf)
                if isinstance(data, list):
                    all_findings.extend(data)
        except Exception as e:
            print(f"Error reading {f}: {e}")

    # Deduplicate
    deduped = {}
    for item in all_findings:
        key = (item.get("AccountId"), item.get("Region"), item.get("RuleId"), item.get("ResourceId"))
        deduped[key] = item
    findings = list(deduped.values())

    print(f"Total Unique Findings: {len(findings)}")

    print("\n=== CRITICAL FINDINGS ===")
    for f in findings:
        if f.get("Severity") == "CRITICAL":
            print(f"Account: {f.get('AccountId')} ({f.get('AccountName')}) | Domain: {f.get('Domain')}")
            print(f"  Rule: {f.get('RuleName')}")
            print(f"  Resource: {f.get('ResourceId')}")
            print(f"  Description: {f.get('Description')}")
            print(f"  CLI: {f.get('RemediationCLI')}\n")

    print("=== ZERO IMPACT QUICK WINS (Safe to fix with 0 downtime) ===")
    zero_wins = [f for f in findings if f.get("RemediationImpact") == "ZERO_IMPACT_QUICK_WIN"]
    print(f"Total Zero-Impact Quick Wins: {len(zero_wins)}")
    zw_rules = Counter(f.get("RuleName") for f in zero_wins)
    for r, count in zw_rules.most_common():
        print(f"  {count:3d} x {r}")

    print("\n=== HIGH SEVERITY FINDINGS ===")
    highs = [f for f in findings if f.get("Severity") == "HIGH"]
    print(f"Total High Severity: {len(highs)}")
    high_rules = Counter(f.get("RuleName") for f in highs)
    for r, count in high_rules.most_common():
        print(f"  {count:3d} x {r}")

    print("\n=== FINDINGS BY ACCOUNT & IMPACT ===")
    acc_matrix = defaultdict(lambda: Counter())
    for f in findings:
        acc = f.get("AccountId")
        impact = f.get("RemediationImpact")
        sev = f.get("Severity")
        acc_matrix[acc]["TOTAL"] += 1
        acc_matrix[acc][impact] += 1
        acc_matrix[acc][sev] += 1

    for acc, c in sorted(acc_matrix.items(), key=lambda x: x[1]["TOTAL"], reverse=True):
        print(f"Account {acc}:")
        print(f"  Total: {c['TOTAL']} | Zero-Impact Wins: {c['ZERO_IMPACT_QUICK_WIN']} | Critical: {c['CRITICAL']} | High: {c['HIGH']} | Medium: {c['MEDIUM']} | Low: {c['LOW']}")

if __name__ == "__main__":
    analyze()
