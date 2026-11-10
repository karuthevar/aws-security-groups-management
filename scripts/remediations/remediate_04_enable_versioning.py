#!/usr/bin/env python3
"""
remediate_04_enable_versioning.py
================================================================================
Remediation Item S3-REM-04: Enable S3 Versioning & Ransomware Safeguards

Enables bucket versioning to protect against accidental deletion, malicious overwrites,
and ransomware attacks. Optionally configures a noncurrent version expiration lifecycle
rule to prevent runaway storage costs.

Safety Design:
  - DRY-RUN BY DEFAULT: No changes applied unless --execute (or --apply) is passed.
  - Automatic Rollback Backup: Pre-change versioning status saved to JSON.
  - Cost Safeguard: When --add-lifecycle is specified, attaches a rule expiring
    noncurrent versions after N days (default: 90 days).

Usage:
  # 1. Preview candidates across all organizations:
  python scripts/remediations/remediate_04_enable_versioning.py --all

  # 2. Preview a specific bucket:
  python scripts/remediations/remediate_04_enable_versioning.py --bucket my-bucket --account-id 123456789012 --profile rus-ext

  # 3. Apply versioning only:
  python scripts/remediations/remediate_04_enable_versioning.py --bucket my-bucket --account-id 123456789012 --profile rus-ext --execute

  # 4. Apply versioning AND attach 90-day noncurrent version expiration lifecycle rule:
  python scripts/remediations/remediate_04_enable_versioning.py --all --add-lifecycle --expire-days 90 --execute
================================================================================
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aws_remediation_core import (
    get_session_for_profile, assume_cross_account_role,
    save_rollback_backup, log_remediation_action,
    DEFAULT_PROFILES, S3_CONFIG
)
from botocore.exceptions import ClientError

REMEDIATION_NAME = "enable_versioning"

def load_candidates_from_csv(csv_path):
    candidates = []
    if not os.path.exists(csv_path):
        return candidates
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("VersioningStatus") != "Enabled":
                candidates.append(row)
    return candidates

def remediate_bucket_versioning(s3_client, account_id, bucket_name, profile, add_lifecycle, expire_days, is_execute):
    previous_status = "Disabled"
    try:
        resp = s3_client.get_bucket_versioning(Bucket=bucket_name)
        previous_status = resp.get("Status", "Disabled")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return {
            "Bucket": bucket_name,
            "Status": "FAILED",
            "Details": f"GetVersioning error: {code}",
            "Backup": "N/A"
        }

    if previous_status == "Enabled" and not add_lifecycle:
        return {
            "Bucket": bucket_name,
            "Status": "SKIPPED",
            "Details": "Versioning Already Enabled",
            "Backup": "N/A"
        }

    if not is_execute:
        return {
            "Bucket": bucket_name,
            "Status": "DRY_RUN_ELIGIBLE",
            "Details": f"Would enable Versioning (Previous: {previous_status})" + (f" and add {expire_days}d noncurrent expiration" if add_lifecycle else ""),
            "Backup": "Simulated"
        }

    backup_file = save_rollback_backup(REMEDIATION_NAME, account_id, bucket_name, {"VersioningStatus": previous_status})

    try:
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"}
        )

        lifecycle_msg = ""
        if add_lifecycle:
            # Check existing lifecycle rules
            existing_rules = []
            try:
                l_resp = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                existing_rules = l_resp.get("Rules", [])
            except ClientError as le:
                if le.response["Error"]["Code"] not in ["NoSuchLifecycleConfiguration", "LifecycleConfigurationNotFoundError"]:
                    pass

            # Merge or add noncurrent version expiration rule
            new_rule = {
                "ID": "Enterprise-Auto-Expire-Noncurrent-Versions",
                "Status": "Enabled",
                "Filter": {"Prefix": ""},
                "NoncurrentVersionExpiration": {
                    "NoncurrentDays": int(expire_days)
                }
            }
            existing_rules = [r for r in existing_rules if r.get("ID") != new_rule["ID"]]
            existing_rules.append(new_rule)

            s3_client.put_bucket_lifecycle_configuration(
                Bucket=bucket_name,
                LifecycleConfiguration={"Rules": existing_rules}
            )
            lifecycle_msg = f" + Lifecycle rule added (expire noncurrent after {expire_days}d)"

        return {
            "Bucket": bucket_name,
            "Status": "REMEDIATED",
            "Details": f"Versioning successfully enabled{lifecycle_msg}",
            "Backup": backup_file
        }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return {
            "Bucket": bucket_name,
            "Status": "FAILED",
            "Details": f"PutVersioning error: {code}",
            "Backup": backup_file
        }

def rollback_bucket_versioning(s3_client, backup_json_path):
    with open(backup_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    bucket = data.get("BucketName")
    prev_status = data.get("BackupData", {}).get("VersioningStatus", "Suspended")
    if prev_status in ["Disabled", "Suspended"]:
        s3_client.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Suspended"}
        )
        print(f"  [+] Rollback: Suspended versioning on {bucket} (AWS does not allow reverting to pure Disabled once enabled).")

def main():
    parser = argparse.ArgumentParser(description="Enable S3 Bucket Versioning (S3-REM-04)")
    parser.add_argument("--bucket", help="Specific bucket name to remediate.")
    parser.add_argument("--account-id", help="Target AWS Account ID.")
    parser.add_argument("--profile", default="rus-ext", help="AWS Organizations profile (default: rus-ext).")
    parser.add_argument("--add-lifecycle", action="store_true", help="Also attach noncurrent version expiration lifecycle rule.")
    parser.add_argument("--expire-days", type=int, default=90, help="Days to retain noncurrent versions (default: 90).")
    parser.add_argument("--all", action="store_true", help="Process all candidate buckets from inventory CSV.")
    parser.add_argument("--input-csv", default=r"inputs\s3_organizations_discovery_and_recommendations.csv", help="Candidate CSV.")
    parser.add_argument("--execute", "--apply", dest="execute", action="store_true", help="Apply changes. Defaults to dry-run.")
    parser.add_argument("--rollback", help="Path to rollback JSON file to restore.")
    args = parser.parse_args()

    mode = "EXECUTE (LIVE)" if args.execute else "DRY-RUN (SIMULATION ONLY)"
    print(f"\n================================================================================")
    print(f"[*] S3 Remediation S3-REM-04: Enable S3 Versioning & Ransomware Safeguards")
    print(f"[*] Mode: {mode}")
    print(f"================================================================================\n")

    if args.rollback:
        if not os.path.exists(args.rollback):
            sys.exit(f"Error: Rollback file not found: {args.rollback}")
        with open(args.rollback, "r") as f:
            bdata = json.load(f)
        prof_session = get_session_for_profile(args.profile)
        if not prof_session:
            sys.exit(f"Could not authenticate profile: {args.profile}")
        acct_session, _ = assume_cross_account_role(prof_session, bdata["AccountId"])
        s3 = acct_session.client("s3", config=S3_CONFIG)
        rollback_bucket_versioning(s3, args.rollback)
        return

    targets = []
    if args.bucket:
        if not args.account_id:
            sys.exit("Error: --account-id is required when --bucket is specified.")
        targets.append({
            "BucketName": args.bucket,
            "AccountId": args.account_id,
            "OrganizationProfile": args.profile
        })
    elif args.all:
        csv_file = args.input_csv
        if not os.path.exists(csv_file):
            csv_file = r"inputs\s3_all_organizations_inventory.csv"
        print(f"[*] Loading versioning candidates from {csv_file}...")
        targets = load_candidates_from_csv(csv_file)
        print(f"[*] Identified {len(targets)} candidates needing versioning.")
    else:
        sys.exit("Error: Specify --bucket <name> --account-id <id> OR --all")

    if not targets:
        print("[+] No buckets require versioning remediation. All targets compliant.")
        return

    sessions = {}
    success_count = 0
    skipped_count = 0
    fail_count = 0

    for item in targets:
        b_name = item["BucketName"]
        a_id = item["AccountId"]
        org = item.get("OrganizationProfile", args.profile)

        if org not in sessions:
            s = get_session_for_profile(org)
            if not s:
                print(f"[!] Warning: Could not authenticate for profile {org}. Skipping {b_name}.")
                fail_count += 1
                continue
            sessions[org] = s
        mgmt_s = sessions[org]

        acct_s, role_used = assume_cross_account_role(mgmt_s, a_id)
        if not acct_s:
            print(f"[!] Warning: Could not assume role in account {a_id}. Skipping {b_name}.")
            fail_count += 1
            continue

        s3 = acct_s.client("s3", config=S3_CONFIG)
        res = remediate_bucket_versioning(s3, a_id, b_name, org, args.add_lifecycle, args.expire_days, args.execute)

        status = res["Status"]
        details = res["Details"]
        backup = res["Backup"]

        log_remediation_action(REMEDIATION_NAME, {
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "Remediation": REMEDIATION_NAME,
            "OrganizationProfile": org,
            "AccountId": a_id,
            "BucketName": b_name,
            "Action": "PUT_BUCKET_VERSIONING",
            "Status": status,
            "Details": details,
            "BackupFile": backup
        })

        if status in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]:
            symbol = "[DRY-RUN]" if not args.execute else "[REMEDIATED]"
            print(f"  {symbol} {b_name} ({a_id} | {org}) -> {details}")
            success_count += 1
        elif status == "SKIPPED":
            print(f"  [SKIPPED] {b_name} -> {details}")
            skipped_count += 1
        else:
            print(f"  [FAILED] {b_name} ({a_id}) -> {details}")
            fail_count += 1

    print(f"\n--------------------------------------------------------------------------------")
    print(f"[*] Summary: {success_count} Eligible/Remediated | {skipped_count} Skipped | {fail_count} Failed")
    if not args.execute:
        print(f"[*] Review above preview. To apply for real, re-run with: --execute")
    print(f"--------------------------------------------------------------------------------\n")

if __name__ == "__main__":
    main()
