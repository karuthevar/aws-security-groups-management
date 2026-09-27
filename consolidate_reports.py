#!/usr/bin/env python3
"""
AWS Organization Security Group Multi-Report Consolidator
Aggregates reports from multiple AWS Organizations into a unified audit dataset,
an interactive single-file HTML dashboard, and remediation action manifests.
"""

import os
import sys
import glob
import json
import re
import datetime

def consolidate_reports(reports_dir: str, output_dir: str):
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "report_template.html")
    
    # 1. Discover JSON files
    json_pattern = os.path.join(reports_dir, "security_audit_report_*.json")
    json_files = sorted(glob.glob(json_pattern))
    json_files = [f for f in json_files if "consolidated" not in os.path.basename(f)]

    # 2. Discover HTML files
    html_pattern = os.path.join(reports_dir, "security_audit_report_*.html")
    html_files = sorted(glob.glob(html_pattern))
    html_files = [f for f in html_files if "consolidated" not in os.path.basename(f)]

    # Generate missing HTML reports for any JSON files present
    for jf in json_files:
        hf = jf.rsplit('.', 1)[0] + '.html'
        if not os.path.exists(hf) and os.path.exists(template_path):
            try:
                with open(jf, "r", encoding="utf-8") as fp:
                    jdata = json.load(fp)
                with open(template_path, "r", encoding="utf-8") as fp:
                    tmpl = fp.read()
                meta = {
                    'scanDate': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'accountCount': len(set(x.get('AccountId') for x in jdata if x.get('AccountId'))) or 1,
                    'regionCount': len(set(x.get('Region') for x in jdata if x.get('Region'))) or 1,
                    'totalSGs': len(jdata)
                }
                out = tmpl.replace('/* __DATA_PAYLOAD__ */ []', json.dumps(jdata))
                if '/* __METADATA_PAYLOAD__ */ {}' in out:
                    out = out.replace('/* __METADATA_PAYLOAD__ */ {}', json.dumps(meta))
                else:
                    out = re.sub(r'const METADATA\s*=\s*/\* __METADATA_PAYLOAD__ \*/\s*\{[^}]*\};', f'const METADATA = {json.dumps(meta)};', out)
                with open(hf, "w", encoding="utf-8") as fp:
                    fp.write(out)
                print(f"  [AUTO-GENERATED] Created missing HTML dashboard: {hf}")
                if hf not in html_files:
                    html_files.append(hf)
            except Exception as e:
                print(f"  [WARN] Failed to auto-generate HTML for {jf}: {e}")

    # Use JSON files if available, otherwise HTML files
    discovered_sources = []
    if json_files:
        for jf in json_files:
            match = re.search(r"security_audit_report_(\d+)\.json", os.path.basename(jf))
            org_root_id = match.group(1) if match else "Unknown"
            discovered_sources.append(("json", jf, org_root_id))
    elif html_files:
        for hf in html_files:
            match = re.search(r"security_audit_report_(\d+)\.html", os.path.basename(hf))
            org_root_id = match.group(1) if match else "Unknown"
            discovered_sources.append(("html", hf, org_root_id))
    else:
        print(f"No security audit report JSON or HTML files found in {reports_dir}")
        return

    print(f"Discovered {len(discovered_sources)} AWS Organization report(s) to consolidate:")
    all_sgs = []
    org_summaries = {}

    for src_type, fpath, org_root_id in discovered_sources:
        filename = os.path.basename(fpath)
        if src_type == "json":
            try:
                with open(fpath, "r", encoding="utf-8") as fp:
                    records = json.load(fp)
            except Exception as e:
                print(f"  [ERROR] Failed to load JSON from {filename}: {e}")
                continue
        else:
            with open(fpath, "r", encoding="utf-8") as fp:
                content = fp.read()

            idx1 = content.find("const RAW_DATA = ") + len("const RAW_DATA = ")
            idx2 = content.find("const METADATA = ")
            if idx1 == -1 or idx2 == -1:
                print(f"  [WARN] Skipping {filename}: could not parse RAW_DATA payload.")
                continue

            raw_json = content[idx1:idx2].strip().rstrip(";")
            try:
                records = json.loads(raw_json)
            except Exception as e:
                print(f"  [ERROR] Failed to decode JSON in {filename}: {e}")
                continue

        org_accounts = set()
        org_regions = set()

        for sg in records:
            sg["OrgRootAccountId"] = org_root_id
            
            # Refresh and standardize recommendation titles and descriptions
            is_default = sg.get("IsDefault", False) or sg.get("GroupName") == "default"
            is_attached = sg.get("IsAttached", False)
            ingress_rules = sg.get("IpPermissions", [])
            ingress_count = len(ingress_rules)
            max_severity = sg.get("MaxSeverity", "CLEAN")

            if is_default:
                if ingress_count > 0:
                    sg["Recommendation"] = "DEFAULT_RESTRICT"
                    sg["ActionTitle"] = "Remove Ingress Rules (Default SG - Make Clean)"
                    sg["ActionDesc"] = f"AWS Default Security Group cannot be deleted via AWS API. Remove its {ingress_count} inbound rule(s) to isolate and make it clean."
                else:
                    sg["Recommendation"] = "DEFAULT_CLEAN"
                    sg["ActionTitle"] = "Default SG - Clean (0 Inbound Rules)"
                    sg["ActionDesc"] = "AWS Default Security Group has 0 inbound rules. Already restricted and clean."
            elif not is_attached:
                sg["Recommendation"] = "CAN_DELETE"
                sg["ActionTitle"] = "Safe to Delete (No Attached Resources)"
                sg["ActionDesc"] = "No active resources (0 ENIs) are attached. Safe to back up and permanently delete."
            elif is_attached and max_severity in ("CRITICAL", "HIGH"):
                sg["Recommendation"] = "RESTRICT_IMMEDIATELY"
                sg["ActionTitle"] = "Restrict Ingress Immediately"
            elif is_attached and max_severity == "MEDIUM":
                sg["Recommendation"] = "REVIEW_EXPOSURE"
                sg["ActionTitle"] = "Review Public Exposure"
            else:
                sg["Recommendation"] = "SAFE_IN_USE"
                sg["ActionTitle"] = "Safe & Monitored"

            if sg.get("AccountId"):
                org_accounts.add(sg.get("AccountId"))
            if sg.get("Region"):
                org_regions.add(sg.get("Region"))

            all_sgs.append(sg)

        org_summaries[org_root_id] = {
            "Filename": filename,
            "TotalSGs": len(records),
            "AccountCount": len(org_accounts),
            "RegionCount": len(org_regions),
            "CanDeleteCount": len([x for x in records if x.get("Recommendation") == "CAN_DELETE"]),
            "DefaultCleanCount": len([x for x in records if x.get("Recommendation") == "DEFAULT_RESTRICT"])
        }
        print(f"  [OK] Processed Org {org_root_id}: {len(records)} SGs across {len(org_accounts)} accounts and {len(org_regions)} regions")

    total_sgs_count = len(all_sgs)
    unique_accounts = len(set(x.get("AccountId") for x in all_sgs if x.get("AccountId")))
    unique_regions = len(set(x.get("Region") for x in all_sgs if x.get("Region")))
    can_delete_sgs = [x for x in all_sgs if x.get("Recommendation") == "CAN_DELETE"]
    default_sgs_to_clean = [x for x in all_sgs if x.get("Recommendation") == "DEFAULT_RESTRICT"]
    critical_threats = [x for x in all_sgs if x.get("MaxSeverity") == "CRITICAL"]

    # 1. Output Consolidated JSON dataset
    json_path = os.path.join(output_dir, "consolidated_security_audit_report.json")
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump(all_sgs, fp, indent=2)
    print(f"\n[OUTPUT 1] Consolidated JSON: {json_path} ({total_sgs_count} records)")

    # 2. Output Consolidated Interactive HTML Dashboard
    script_dir = os.path.dirname(os.path.abspath(__file__))
    template_path = os.path.join(script_dir, "templates", "report_template.html")
    with open(template_path, "r", encoding="utf-8") as fp:
        template_html = fp.read()

    metadata = {
        "scanDate": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "accountCount": unique_accounts,
        "regionCount": unique_regions,
        "totalSGs": total_sgs_count
    }

    # Robust replacement of data and metadata payloads
    consolidated_html = template_html.replace(
        "/* __DATA_PAYLOAD__ */ []",
        json.dumps(all_sgs)
    )
    if "/* __METADATA_PAYLOAD__ */ {}" in consolidated_html:
        consolidated_html = consolidated_html.replace("/* __METADATA_PAYLOAD__ */ {}", json.dumps(metadata))
    else:
        consolidated_html = re.sub(
            r"const METADATA\s*=\s*/\* __METADATA_PAYLOAD__ \*/\s*\{[^}]*\};",
            f"const METADATA = {json.dumps(metadata)};",
            consolidated_html
        )

    consolidated_html = consolidated_html.replace(
        "Generated across Organization Accounts &bull; Threat & Attachment Security Review",
        f"Consolidated across {len(org_summaries)} AWS Organizations ({unique_accounts} Member Accounts, {unique_regions} Regions) &bull; Threat &amp; Remediation Audit"
    )

    html_path = os.path.join(output_dir, "consolidated_security_audit_report.html")
    with open(html_path, "w", encoding="utf-8") as fp:
        fp.write(consolidated_html)
    print(f"[OUTPUT 2] Consolidated HTML Dashboard: {html_path}")

    # 3. Output Actionable Remediation Manifest
    manifest_path = os.path.join(output_dir, "consolidated_cleanup_manifest.txt")
    manifest_lines = [
        "================================================================================",
        " CONSOLIDATED AWS SECURITY GROUP REMEDIATION MANIFEST",
        f" Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "================================================================================",
        f"Total AWS Organizations Scanned : {len(org_summaries)} ({', '.join(org_summaries.keys())})",
        f"Total Member Accounts Evaluated : {unique_accounts}",
        f"Total Security Groups Evaluated : {total_sgs_count}",
        "",
        "ACTIONABLE CLEANUP SUMMARY:",
        f"  1. Non-Default Unattached SGs to DELETE        : {len(can_delete_sgs)}",
        f"  2. Default SGs to REVOKE INGRESS (Make Clean)  : {len(default_sgs_to_clean)}",
        f"  Combined Actionable Cleanup Targets            : {len(can_delete_sgs) + len(default_sgs_to_clean)}",
        f"  Critical Threats Requiring Ingress Restriction : {len(critical_threats)}",
        "",
        "BREAKDOWN BY AWS ORGANIZATION:",
    ]

    for org_id, summary in org_summaries.items():
        manifest_lines.append(f"  * Org Root {org_id}: {summary['TotalSGs']} SGs | {summary['CanDeleteCount']} Delete Candidates | {summary['DefaultCleanCount']} Default SGs to Clean")

    manifest_lines.extend([
        "",
        "HOW TO EXECUTE REMEDIATION:",
        "--------------------------------------------------------------------------------",
        "Because each AWS Organization has its own Root Account and IAM credentials,",
        "run the cleanup tool in each respective Organization's root CloudShell/CLI session:",
        "",
        "For Org 679414842598:",
        "  Preview Dry-Run : ./cleanup_security_groups.sh --audit-file reports/consolidated_security_audit_report.json",
        "  Execute Cleanup : ./cleanup_security_groups.sh --audit-file reports/consolidated_security_audit_report.json --execute",
        "",
        "For Org 743683883393:",
        "  Preview Dry-Run : ./cleanup_security_groups.sh --audit-file reports/consolidated_security_audit_report.json",
        "  Execute Cleanup : ./cleanup_security_groups.sh --audit-file reports/consolidated_security_audit_report.json --execute",
        "",
        "For Org 908140080081:",
        "  Preview Dry-Run : ./cleanup_security_groups.sh --audit-file reports/consolidated_security_audit_report.json",
        "  Execute Cleanup : ./cleanup_security_groups.sh --audit-file reports/consolidated_security_audit_report.json --execute",
        "",
        "================================================================================",
        " SECTION 1: NON-DEFAULT UNATTACHED SECURITY GROUPS (ACTION: BACKUP & DELETE)",
        "================================================================================",
        "OrgRootId,AccountId,AccountName,Region,GroupId,GroupName,VpcId",
    ])

    for sg in can_delete_sgs:
        manifest_lines.append(f"{sg.get('OrgRootAccountId')},{sg.get('AccountId')},{sg.get('AccountName')},{sg.get('Region')},{sg.get('GroupId')},{sg.get('GroupName')},{sg.get('VpcId')}")

    manifest_lines.extend([
        "",
        "================================================================================",
        " SECTION 2: DEFAULT SECURITY GROUPS (ACTION: BACKUP & REVOKE INGRESS RULES ONLY)",
        "================================================================================",
        "OrgRootId,AccountId,AccountName,Region,GroupId,GroupName,VpcId,IngressRulesCount",
    ])

    for sg in default_sgs_to_clean:
        manifest_lines.append(f"{sg.get('OrgRootAccountId')},{sg.get('AccountId')},{sg.get('AccountName')},{sg.get('Region')},{sg.get('GroupId')},{sg.get('GroupName')},{sg.get('VpcId')},{sg.get('IngressRulesCount', 1)}")

    with open(manifest_path, "w", encoding="utf-8") as fp:
        fp.write("\n".join(manifest_lines) + "\n")
    print(f"[OUTPUT 3] Consolidated Cleanup Manifest: {manifest_path}")

    print("\n" + "=" * 80)
    print(" CONSOLIDATION COMPLETE!")
    print("=" * 80)
    print(f"Total Security Groups  : {total_sgs_count}")
    print(f"Candidates to DELETE   : {len(can_delete_sgs)}")
    print(f"Default SGs to CLEAN   : {len(default_sgs_to_clean)}")
    print(f"Critical Threats       : {len(critical_threats)}")
    print("=" * 80)

if __name__ == "__main__":
    reports_dir = sys.argv[1] if len(sys.argv) > 1 else "reports"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else reports_dir
    consolidate_reports(reports_dir, output_dir)
