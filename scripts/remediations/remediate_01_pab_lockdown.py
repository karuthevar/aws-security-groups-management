#!/usr/bin/env python3
"""
remediate_01_pab_lockdown.py
================================================================================
Remediation Item S3-REM-01: Public Access Block (PAB) 4-Control Lockdown

Enforces the four Amazon S3 Public Access Block guardrails:
  - BlockPublicAcls: True
  - IgnorePublicAcls: True
  - BlockPublicPolicy: True
  - RestrictPublicBuckets: True

Safety Design:
  - DRY-RUN BY DEFAULT: No changes applied unless --execute (or --apply) is passed.
  - Automatic Rollback Backup: Pre-change configuration saved to JSON.
  - Supports Rollback: Pass --rollback <backup-file.json> to restore prior state.
  - Multi-Org Traversal: Works across rus-ext, rus-ioc, cccs.

Usage:
  # 1. Preview candidates across all organizations:
  python scripts/remediations/remediate_01_pab_lockdown.py --all

  # 2. Preview a specific critical bucket:
  python scripts/remediations/remediate_01_pab_lockdown.py --bucket appdevlab-migration-data --account-id 371016420106 --profile rus-ext

  # 3. Apply lockdown to specific bucket:
  python scripts/remediations/remediate_01_pab_lockdown.py --bucket appdevlab-migration-data --account-id 371016420106 --profile rus-ext --execute

  # 4. Apply lockdown across all unconfigured / partial buckets in inventory:
  python scripts/remediations/remediate_01_pab_lockdown.py --all --execute
================================================================================
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timezone

# Add parent directory for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aws_remediation_core import (
    get_session_for_profile, assume_cross_account_role,
    save_rollback_backup, log_remediation_action,
    DEFAULT_PROFILES, S3_CONFIG
)
from botocore.exceptions import ClientError

REMEDIATION_NAME = "pab_lockdown"

PAB_FULL_CONFIG = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

def load_candidates_from_csv(csv_path):
    candidates = []
    if not os.path.exists(csv_path):
        return candidates
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            pab_status = row.get("PAB_Status", "")
            if pab_status != "Fully Blocked (Compliant)":
                candidates.append(row)
    return candidates

def remediate_bucket_pab(s3_client, account_id, bucket_name, profile, is_execute):
    """
    Inspects, backs up, and applies full Public Access Block to a single bucket.
    """
    previous_config = None
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket_name)
        previous_config = resp.get("PublicAccessBlockConfiguration", {})
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"]:
            previous_config = "None Configured"
        else:
            return {
                "Bucket": bucket_name,
                "Status": "FAILED",
                "Details": f"GetPAB error: {code}",
                "Backup": "N/A"
            }

    # Check if already fully blocked
    if isinstance(previous_config, dict):
        if (previous_config.get("BlockPublicAcls") and
            previous_config.get("IgnorePublicAcls") and
            previous_config.get("BlockPublicPolicy") and
            previous_config.get("RestrictPublicBuckets")):
            return {
                "Bucket": bucket_name,
                "Status": "SKIPPED",
                "Details": "Already Fully Blocked",
                "Backup": "N/A"
            }

    if not is_execute:
        return {
            "Bucket": bucket_name,
            "Status": "DRY_RUN_ELIGIBLE",
            "Details": f"Would apply full 4-control PAB (Previous: {previous_config})",
            "Backup": "Simulated"
        }

    # Capture rollback backup
    backup_file = save_rollback_backup(REMEDIATION_NAME, account_id, bucket_name, previous_config)

    # Apply Full PAB
    try:
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration=PAB_FULL_CONFIG
        )
        return {
            "Bucket": bucket_name,
            "Status": "REMEDIATED",
            "Details": "Full 4-control PAB successfully applied",
            "Backup": backup_file
        }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return {
            "Bucket": bucket_name,
            "Status": "FAILED",
            "Details": f"PutPAB error: {code}",
            "Backup": backup_file
        }

def rollback_bucket_pab(s3_client, backup_json_path):
    with open(backup_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    bucket = data.get("BucketName")
    prev = data.get("BackupData")
    if prev == "None Configured":
        s3_client.delete_public_access_block(Bucket=bucket)
        print(f"  [+] Rollback: Deleted PAB for {bucket} (restored to unconfigured).")
    elif isinstance(prev, dict):
        s3_client.put_public_access_block(
            Bucket=bucket,
            PublicAccessBlockConfiguration=prev
        )
        print(f"  [+] Rollback: Restored original PAB config for {bucket}.")

def main():
    parser = argparse.ArgumentParser(description="Remediate S3 Public Access Block (S3-REM-01)")
    parser.add_argument("--bucket", help="Specific bucket name to remediate.")
    parser.add_argument("--account-id", help="Target AWS Account ID.")
    parser.add_argument("--profile", default="rus-ext", help="AWS Organizations profile (default: rus-ext).")
    parser.add_argument("--all", action="store_true", help="Process all candidate buckets from inventory CSV.")
    parser.add_argument("--input-csv", default=r"inputs\s3_organizations_discovery_and_recommendations.csv", help="Candidate CSV.")
    parser.add_argument("--execute", "--apply", dest="execute", action="store_true", help="Apply changes. Defaults to dry-run.")
    parser.add_argument("--rollback", help="Path to rollback JSON file to restore.")
    args = parser.parse_args()

    mode = "EXECUTE (LIVE)" if args.execute else "DRY-RUN (SIMULATION ONLY)"
    print(f"\n================================================================================")
    print(f"[*] S3 Remediation S3-REM-01: Public Access Block Lockdown")
    print(f"[*] Mode: {mode}")
    print(f"================================================================================\n")

    # Handle Rollback
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
        rollback_bucket_pab(s3, args.rollback)
        return

    # Determine Targets
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
        print(f"[*] Loading PAB candidates from {csv_file}...")
        targets = load_candidates_from_csv(csv_file)
        print(f"[*] Identified {len(targets)} candidates needing PAB lockdown.")
    else:
        sys.exit("Error: Specify --bucket <name> --account-id <id> OR --all")

    if not targets:
        print("[+] No buckets require PAB lockdown. All targets compliant.")
        return

    # Execute / Dry Run
    sessions = {}
    success_count = 0
    skipped_count = 0
    fail_count = 0

    for item in targets:
        b_name = item["BucketName"]
        a_id = item["AccountId"]
        org = item.get("OrganizationProfile", args.profile)

        # Authenticate org session
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
        res = remediate_bucket_pab(s3, a_id, b_name, org, args.execute)

        status = res["Status"]
        details = res["Details"]
        backup = res["Backup"]

        log_remediation_action(REMEDIATION_NAME, {
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "Remediation": REMEDIATION_NAME,
            "OrganizationProfile": org,
            "AccountId": a_id,
            "BucketName": b_name,
            "Action": "PUT_PUBLIC_ACCESS_BLOCK",
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
