#!/usr/bin/env python3
"""
remediate_03_enforce_encryption.py
================================================================================
Remediation Item S3-REM-03: Enforce Default Server-Side Encryption (SSE)

Configures default server-side encryption for S3 buckets using AES256 or AWS KMS,
and enables S3 Bucket Keys to minimize KMS operational costs.

Safety Design:
  - DRY-RUN BY DEFAULT: No changes applied unless --execute (or --apply) is passed.
  - Automatic Rollback Backup: Pre-change encryption JSON saved before modification.
  - Transparent: Encryption configuration does not alter or re-encrypt existing objects;
    it guarantees all subsequent object writes are encrypted automatically.

Usage:
  # 1. Preview candidates across all organizations:
  python scripts/remediations/remediate_03_enforce_encryption.py --all

  # 2. Preview a specific bucket:
  python scripts/remediations/remediate_03_enforce_encryption.py --bucket my-bucket --account-id 123456789012 --profile rus-ext

  # 3. Apply AES256 default encryption:
  python scripts/remediations/remediate_03_enforce_encryption.py --bucket my-bucket --account-id 123456789012 --profile rus-ext --execute

  # 4. Apply custom KMS key:
  python scripts/remediations/remediate_03_enforce_encryption.py --bucket my-bucket --account-id 123456789012 --profile rus-ext --kms-key-id arn:aws:kms:... --execute
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

REMEDIATION_NAME = "enforce_encryption"

def build_sse_configuration(kms_key_id=None):
    if kms_key_id:
        rule = {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "aws:kms",
                "KMSMasterKeyId": kms_key_id
            },
            "BucketKeyEnabled": True
        }
    else:
        rule = {
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            },
            "BucketKeyEnabled": True
        }
    return {"Rules": [rule]}

def load_candidates_from_csv(csv_path):
    candidates = []
    if not os.path.exists(csv_path):
        return candidates
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            is_enc = row.get("IsEncrypted", "")
            enc_type = row.get("EncryptionType", "")
            if is_enc != "True" or enc_type in ["None", "AccessDenied"] or "Error" in enc_type:
                candidates.append(row)
    return candidates

def remediate_bucket_encryption(s3_client, account_id, bucket_name, profile, kms_key_id, is_execute):
    previous_config = None
    try:
        resp = s3_client.get_bucket_encryption(Bucket=bucket_name)
        previous_config = resp.get("ServerSideEncryptionConfiguration", {})
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            previous_config = "None Configured"
        else:
            return {
                "Bucket": bucket_name,
                "Status": "FAILED",
                "Details": f"GetEncryption error: {code}",
                "Backup": "N/A"
            }

    sse_conf = build_sse_configuration(kms_key_id)

    if not is_execute:
        alg = "aws:kms" if kms_key_id else "AES256"
        return {
            "Bucket": bucket_name,
            "Status": "DRY_RUN_ELIGIBLE",
            "Details": f"Would apply {alg} encryption with BucketKeyEnabled=True (Previous: {previous_config})",
            "Backup": "Simulated"
        }

    backup_file = save_rollback_backup(REMEDIATION_NAME, account_id, bucket_name, previous_config)

    try:
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=sse_conf
        )
        return {
            "Bucket": bucket_name,
            "Status": "REMEDIATED",
            "Details": f"Default encryption successfully configured (Algorithm: {'aws:kms' if kms_key_id else 'AES256'})",
            "Backup": backup_file
        }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return {
            "Bucket": bucket_name,
            "Status": "FAILED",
            "Details": f"PutEncryption error: {code}",
            "Backup": backup_file
        }

def rollback_bucket_encryption(s3_client, backup_json_path):
    with open(backup_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    bucket = data.get("BucketName")
    prev = data.get("BackupData")
    if prev == "None Configured":
        s3_client.delete_bucket_encryption(Bucket=bucket)
        print(f"  [+] Rollback: Deleted custom encryption configuration on {bucket}.")
    elif isinstance(prev, dict):
        s3_client.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration=prev
        )
        print(f"  [+] Rollback: Restored original encryption configuration on {bucket}.")

def main():
    parser = argparse.ArgumentParser(description="Enforce S3 Default Server-Side Encryption (S3-REM-03)")
    parser.add_argument("--bucket", help="Specific bucket name to remediate.")
    parser.add_argument("--account-id", help="Target AWS Account ID.")
    parser.add_argument("--profile", default="rus-ext", help="AWS Organizations profile (default: rus-ext).")
    parser.add_argument("--kms-key-id", help="Optional KMS Master Key ARN/ID. Defaults to AES256.")
    parser.add_argument("--all", action="store_true", help="Process all candidate buckets from inventory CSV.")
    parser.add_argument("--input-csv", default=r"inputs\s3_organizations_discovery_and_recommendations.csv", help="Candidate CSV.")
    parser.add_argument("--execute", "--apply", dest="execute", action="store_true", help="Apply changes. Defaults to dry-run.")
    parser.add_argument("--rollback", help="Path to rollback JSON file to restore.")
    args = parser.parse_args()

    mode = "EXECUTE (LIVE)" if args.execute else "DRY-RUN (SIMULATION ONLY)"
    print(f"\n================================================================================")
    print(f"[*] S3 Remediation S3-REM-03: Enforce Default Server-Side Encryption")
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
        rollback_bucket_encryption(s3, args.rollback)
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
        print(f"[*] Loading encryption candidates from {csv_file}...")
        targets = load_candidates_from_csv(csv_file)
        print(f"[*] Identified {len(targets)} candidates needing default encryption.")
    else:
        sys.exit("Error: Specify --bucket <name> --account-id <id> OR --all")

    if not targets:
        print("[+] No buckets require encryption remediation. All targets compliant.")
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
        res = remediate_bucket_encryption(s3, a_id, b_name, org, args.kms_key_id, args.execute)

        status = res["Status"]
        details = res["Details"]
        backup = res["Backup"]

        log_remediation_action(REMEDIATION_NAME, {
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "Remediation": REMEDIATION_NAME,
            "OrganizationProfile": org,
            "AccountId": a_id,
            "BucketName": b_name,
            "Action": "PUT_BUCKET_ENCRYPTION",
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
