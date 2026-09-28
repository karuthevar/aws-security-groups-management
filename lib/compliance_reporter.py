#!/usr/bin/env python3
"""
AWS Enterprise Compliance & Security Dashboard Reporter
Reads compliance findings JSON, injects data into templates/compliance_template.html,
and outputs a standalone interactive HTML dashboard and executive terminal summary.
"""

import sys
import os
import json
import datetime
from typing import List, Dict, Any

def generate_compliance_html(
    findings_file: str,
    output_html_file: str,
    template_path: str,
    metadata: Dict[str, Any]
) -> None:
    if not os.path.exists(findings_file):
        print(f"[ERROR] Findings file not found: {findings_file}", file=sys.stderr)
        sys.exit(1)
        
    if not os.path.exists(template_path):
        print(f"[ERROR] HTML template not found: {template_path}", file=sys.stderr)
        sys.exit(1)

    with open(findings_file, "r", encoding="utf-8") as f:
        findings = json.load(f)

    with open(template_path, "r", encoding="utf-8") as f:
        template_content = f.read()

    # Calculate summary metrics if not already present
    zero_wins = sum(1 for x in findings if x.get("RemediationImpact") == "ZERO_IMPACT_QUICK_WIN" and x.get("Status") == "NON_COMPLIANT")
    criticals = sum(1 for x in findings if x.get("Severity") == "CRITICAL" and x.get("Status") == "NON_COMPLIANT")
    highs = sum(1 for x in findings if x.get("Severity") == "HIGH" and x.get("Status") == "NON_COMPLIANT")
    compliant = sum(1 for x in findings if x.get("Status") == "COMPLIANT")
    non_compliant = sum(1 for x in findings if x.get("Status") == "NON_COMPLIANT")

    meta_payload = {
        "scanDate": metadata.get("scanDate", datetime.datetime.now(datetime.timezone.utc).isoformat()),
        "accountCount": metadata.get("accountCount", len(set(x.get("AccountId") for x in findings if x.get("AccountId")))),
        "regionCount": metadata.get("regionCount", len(set(x.get("Region") for x in findings if x.get("Region")))),
        "totalEvaluations": len(findings),
        "zeroImpactWins": zero_wins,
        "criticalFindings": criticals,
        "highFindings": highs,
        "compliantCount": compliant,
        "nonCompliantCount": non_compliant
    }

    # Replace placeholders
    html_out = template_content.replace(
        "/* __COMPLIANCE_PAYLOAD__ */ []",
        json.dumps(findings, indent=None)
    )
    html_out = html_out.replace(
        "/* __METADATA_PAYLOAD__ */ {}",
        json.dumps(meta_payload, indent=None)
    )

    os.makedirs(os.path.dirname(os.path.abspath(output_html_file)), exist_ok=True)
    with open(output_html_file, "w", encoding="utf-8") as f:
        f.write(html_out)

    print(f"[SUCCESS] Interactive Compliance Dashboard generated: {output_html_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python compliance_reporter.py <findings_json> <output_html> [template_html] [account_count] [region_count]")
        sys.exit(1)

    f_json = sys.argv[1]
    out_html = sys.argv[2]
    script_dir = os.path.dirname(os.path.abspath(__file__))
    t_path = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] != "" else os.path.join(script_dir, "..", "templates", "compliance_template.html")
    acc_count = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4].isdigit() else 1
    reg_count = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5].isdigit() else 1

    generate_compliance_html(
        findings_file=f_json,
        output_html_file=out_html,
        template_path=t_path,
        metadata={"accountCount": acc_count, "regionCount": reg_count}
    )
