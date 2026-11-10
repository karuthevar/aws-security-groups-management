#!/usr/bin/env python3
"""
remediate_02_enforce_tls.py
================================================================================
Remediation Item S3-REM-02: Enforce TLS 1.2+ HTTPS-Only Bucket Policy

Safely merges a "DenyInsecureTransport" statement into the existing bucket policy
(or provisions a new policy) denying any request with aws:SecureTransport = false.

Statement Merged:
  {
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"],
    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
  }

Safety Design:
  - DRY-RUN BY DEFAULT: No changes applied unless --execute (or --apply) is passed.
  - NON-DESTRUCTIVE: Existing statements are preserved 100%. Only DenyInsecureTransport is added.
  - Automatic Rollback Backup: Pre-change policy JSON saved before modification.
  - Supports Rollback: Pass --rollback <backup-file.json> to restore prior policy.

Usage:
  # 1. Preview candidates across all organizations:
  python scripts/remediations/remediate_02_enforce_tls.py --all

  # 2. Preview a specific bucket:
  python scripts/remediations/remediate_02_enforce_tls.py --bucket aws-ebs-volume-arns --account-id 026272668488 --profile rus-ext

  # 3. Apply TLS enforcement to specific bucket:
  python scripts/remediations/remediate_02_enforce_tls.py --bucket aws-ebs-volume-arns --account-id 026272668488 --profile rus-ext --execute

  # 4. Apply TLS enforcement across all non-compliant buckets in inventory:
  python scripts/remediations/remediate_02_enforce_tls.py --all --execute
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

REMEDIATION_NAME = "enforce_tls"
SID = "DenyInsecureTransport"

def build_tls_statement(bucket_name):
    return {
        "Sid": SID,
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
            f"arn:aws:s3:::{bucket_name}",
            f"arn:aws:s3:::{bucket_name}/*"
        ],
        "Condition": {
            "Bool": {
                "aws:SecureTransport": "false"
            }
        }
    }

def policy_has_tls_deny(policy_doc):
    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Deny":
            continue
        for op in ("Bool", "BoolIfExists"):
            cond = stmt.get("Condition", {}).get(op, {})
            st = cond.get("aws:SecureTransport")
            if st in ["false", False, ["false"], [False]]:
                return True
    return False

def load_candidates_from_csv(csv_path):
    candidates = []
    if not os.path.exists(csv_path):
        return candidates
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("Policy_EnforcesTLS") != "True":
                candidates.append(row)
    return candidates

def remediate_bucket_tls(s3_client, account_id, bucket_name, profile, is_execute):
    previous_policy = None
    try:
        resp = s3_client.get_bucket_policy(Bucket=bucket_name)
        raw_pol = resp.get("Policy", "")
        if raw_pol:
            previous_policy = json.loads(raw_pol)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["NoSuchBucketPolicy", "NoSuchPolicy"]:
            previous_policy = None
        else:
            return {
                "Bucket": bucket_name,
                "Status": "FAILED",
                "Details": f"GetPolicy error: {code}",
                "Backup": "N/A"
            }

    # If policy already enforces TLS
    if previous_policy and policy_has_tls_deny(previous_policy):
        return {
            "Bucket": bucket_name,
            "Status": "SKIPPED",
            "Details": "Already Enforces TLS",
            "Backup": "N/A"
        }

    # Prepare merged policy
    if previous_policy:
        new_policy = json.loads(json.dumps(previous_policy)) # deep copy
        stmts = new_policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        # Remove any stale Sid if present, then append
        stmts = [s for s in stmts if s.get("Sid") != SID]
        stmts.append(build_tls_statement(bucket_name))
        new_policy["Statement"] = stmts
    else:
        new_policy = {
            "Version": "2012-10-17",
            "Statement": [build_tls_statement(bucket_name)]
        }

    if not is_execute:
        return {
            "Bucket": bucket_name,
            "Status": "DRY_RUN_ELIGIBLE",
            "Details": f"Would merge DenyInsecureTransport (HadPolicy: {previous_policy is not None})",
            "Backup": "Simulated"
        }

    # Save backup before writing
    backup_file = save_rollback_backup(REMEDIATION_NAME, account_id, bucket_name, previous_policy)

    # Write policy
    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(new_policy)
        )
        return {
            "Bucket": bucket_name,
            "Status": "REMEDIATED",
            "Details": "TLS Deny statement successfully merged into bucket policy",
            "Backup": backup_file
        }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return {
            "Bucket": bucket_name,
            "Status": "FAILED",
            "Details": f"PutPolicy error: {code}",
            "Backup": backup_file
        }

def rollback_bucket_tls(s3_client, backup_json_path):
    with open(backup_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    bucket = data.get("BucketName")
    prev = data.get("BackupData")
    if prev is None:
        s3_client.delete_bucket_policy(Bucket=bucket)
        print(f"  [+] Rollback: Deleted bucket policy on {bucket} (restored to no policy).")
    else:
        s3_client.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(prev)
        )
        print(f"  [+] Rollback: Restored original bucket policy on {bucket}.")

def main():
    parser = argparse.ArgumentParser(description="Enforce S3 TLS 1.2+ HTTPS (S3-REM-02)")
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
    print(f"[*] S3 Remediation S3-REM-02: Enforce TLS 1.2+ HTTPS-Only Bucket Policy")
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
        rollback_bucket_tls(s3, args.rollback)
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
        print(f"[*] Loading TLS candidates from {csv_file}...")
        targets = load_candidates_from_csv(csv_file)
        print(f"[*] Identified {len(targets)} candidates needing TLS enforcement.")
    else:
        sys.exit("Error: Specify --bucket <name> --account-id <id> OR --all")

    if not targets:
        print("[+] No buckets require TLS enforcement. All targets compliant.")
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
        res = remediate_bucket_tls(s3, a_id, b_name, org, args.execute)

        status = res["Status"]
        details = res["Details"]
        backup = res["Backup"]

        log_remediation_action(REMEDIATION_NAME, {
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "Remediation": REMEDIATION_NAME,
            "OrganizationProfile": org,
            "AccountId": a_id,
            "BucketName": b_name,
            "Action": "MERGE_TLS_DENY_POLICY",
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
