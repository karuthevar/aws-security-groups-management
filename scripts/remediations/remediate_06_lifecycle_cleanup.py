#!/usr/bin/env python3
"""
remediate_06_lifecycle_cleanup.py
================================================================================
Remediation Item S3-REM-06: S3 Cost Optimization & Lifecycle Rules

Configures enterprise lifecycle rules to:
  1. Abort incomplete multipart uploads after 7 days (stops ghost storage charges).
  2. Transition dormant objects (>90 days) to Glacier Flexible Retrieval or Deep Archive.

Safety Design:
  - DRY-RUN BY DEFAULT: No changes applied unless --execute (or --apply) is passed.
  - Non-destructive Merge: Preserves existing lifecycle rules and appends/updates.
  - Automatic Rollback Backup: Pre-change lifecycle rules saved before modification.

Usage:
  # 1. Preview candidates across all organizations:
  python scripts/remediations/remediate_06_lifecycle_cleanup.py --all

  # 2. Preview for a specific bucket:
  python scripts/remediations/remediate_06_lifecycle_cleanup.py --bucket my-bucket --account-id 123456789012 --profile rus-ext

  # 3. Apply standard 7-day abort incomplete multipart uploads rule:
  python scripts/remediations/remediate_06_lifecycle_cleanup.py --bucket my-bucket --account-id 123456789012 --profile rus-ext --execute

  # 4. Apply 7-day abort multipart AND transition objects to Glacier after 90 days:
  python scripts/remediations/remediate_06_lifecycle_cleanup.py --all --transition-glacier-days 90 --execute
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

REMEDIATION_NAME = "lifecycle_cleanup"
ABORT_RULE_ID = "Enterprise-Abort-Incomplete-Multipart-Uploads"
GLACIER_RULE_ID = "Enterprise-Dormant-Transition-To-Glacier"

def load_candidates_from_csv(csv_path):
    candidates = []
    if not os.path.exists(csv_path):
        return candidates
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("HasLifecycleRules") != "True" or "DORMANT" in row.get("ActivityStatus", ""):
                candidates.append(row)
    return candidates

def remediate_bucket_lifecycle(s3_client, account_id, bucket_name, profile, abort_days, glacier_days, is_execute):
    existing_rules = []
    try:
        resp = s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        existing_rules = resp.get("Rules", [])
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ["NoSuchLifecycleConfiguration", "LifecycleConfigurationNotFoundError"]:
            return {
                "Bucket": bucket_name,
                "Status": "FAILED",
                "Details": f"GetLifecycle error: {code}",
                "Backup": "N/A"
            }

    # Filter out rules with our specific IDs so we can cleanly replace
    updated_rules = [r for r in existing_rules if r.get("ID") not in [ABORT_RULE_ID, GLACIER_RULE_ID]]

    # 1. Abort incomplete multipart rule
    abort_rule = {
        "ID": ABORT_RULE_ID,
        "Status": "Enabled",
        "Filter": {"Prefix": ""},
        "AbortIncompleteMultipartUpload": {
            "DaysAfterInitiation": int(abort_days)
        }
    }
    updated_rules.append(abort_rule)

    # 2. Optional Glacier transition
    if glacier_days and int(glacier_days) > 0:
        glacier_rule = {
            "ID": GLACIER_RULE_ID,
            "Status": "Enabled",
            "Filter": {"Prefix": ""},
            "Transitions": [
                {
                    "Days": int(glacier_days),
                    "StorageClass": "GLACIER"
                }
            ]
        }
        updated_rules.append(glacier_rule)

    if not is_execute:
        glacier_str = f", Glacier transition after {glacier_days}d" if glacier_days else ""
        return {
            "Bucket": bucket_name,
            "Status": "DRY_RUN_ELIGIBLE",
            "Details": f"Would attach abort multipart ({abort_days}d){glacier_str} (Existing rules: {len(existing_rules)})",
            "Backup": "Simulated"
        }

    backup_file = save_rollback_backup(REMEDIATION_NAME, account_id, bucket_name, existing_rules)

    try:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={"Rules": updated_rules}
        )
        return {
            "Bucket": bucket_name,
            "Status": "REMEDIATED",
            "Details": f"Lifecycle rules applied ({len(updated_rules)} total rules active)",
            "Backup": backup_file
        }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return {
            "Bucket": bucket_name,
            "Status": "FAILED",
            "Details": f"PutLifecycle error: {code}",
            "Backup": backup_file
        }

def rollback_bucket_lifecycle(s3_client, backup_json_path):
    with open(backup_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    bucket = data.get("BucketName")
    prev_rules = data.get("BackupData", [])
    if not prev_rules:
        s3_client.delete_bucket_lifecycle(Bucket=bucket)
        print(f"  [+] Rollback: Deleted lifecycle rules on {bucket} (restored to no rules).")
    else:
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket,
            LifecycleConfiguration={"Rules": prev_rules}
        )
        print(f"  [+] Rollback: Restored original lifecycle configuration on {bucket}.")

def main():
    parser = argparse.ArgumentParser(description="Configure S3 Lifecycle Rules (S3-REM-06)")
    parser.add_argument("--bucket", help="Specific bucket name to remediate.")
    parser.add_argument("--account-id", help="Target AWS Account ID.")
    parser.add_argument("--profile", default="rus-ext", help="AWS Organizations profile (default: rus-ext).")
    parser.add_argument("--abort-days", type=int, default=7, help="Days to abort incomplete multipart uploads (default: 7).")
    parser.add_argument("--transition-glacier-days", type=int, help="Optional days to transition objects to Glacier.")
    parser.add_argument("--all", action="store_true", help="Process all candidate buckets from inventory CSV.")
    parser.add_argument("--input-csv", default=r"inputs\s3_organizations_discovery_and_recommendations.csv", help="Candidate CSV.")
    parser.add_argument("--execute", "--apply", dest="execute", action="store_true", help="Apply changes. Defaults to dry-run.")
    parser.add_argument("--rollback", help="Path to rollback JSON file to restore.")
    args = parser.parse_args()

    mode = "EXECUTE (LIVE)" if args.execute else "DRY-RUN (SIMULATION ONLY)"
    print(f"\n================================================================================")
    print(f"[*] S3 Remediation S3-REM-06: S3 Cost Optimization & Lifecycle Rules")
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
        rollback_bucket_lifecycle(s3, args.rollback)
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
        print(f"[*] Loading lifecycle candidates from {csv_file}...")
        targets = load_candidates_from_csv(csv_file)
        print(f"[*] Identified {len(targets)} candidates needing lifecycle rules.")
    else:
        sys.exit("Error: Specify --bucket <name> --account-id <id> OR --all")

    if not targets:
        print("[+] No buckets require lifecycle remediation. All targets compliant.")
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
        res = remediate_bucket_lifecycle(s3, a_id, b_name, org, args.abort_days, args.transition_glacier_days, args.execute)

        status = res["Status"]
        details = res["Details"]
        backup = res["Backup"]

        log_remediation_action(REMEDIATION_NAME, {
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "Remediation": REMEDIATION_NAME,
            "OrganizationProfile": org,
            "AccountId": a_id,
            "BucketName": b_name,
            "Action": "PUT_BUCKET_LIFECYCLE",
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
