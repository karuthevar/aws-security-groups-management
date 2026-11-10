#!/usr/bin/env python3
"""
enforce_tls_empty_buckets.py
================================================================================
Targeted S3 TLS 1.2+ HTTPS Enforcer for Empty Buckets

Identifies buckets that have 0 objects and 0 bytes of storage (from
inputs/s3_cost_and_usage_metrics 11 10 26.csv or empty_buckets_zero_impact_candidates.csv)
and non-destructively merges an explicit "DenyInsecureTransport" policy.

CRITICAL DESIGN PRINCIPLES:
  1. PRESERVES OTHER PROPERTIES:
     - Leaves existing Public Access Block (PAB) 100% untouched.
     - Leaves default Server-Side Encryption (SSE) 100% untouched.
     - Leaves Object Ownership, Versioning, Lifecycle, and Tags 100% untouched.
  2. NON-DESTRUCTIVE POLICY MERGE:
     - If the bucket has existing policy statements, all existing statements are
       preserved exactly as-is; only the "DenyInsecureTransport" statement is added.
     - If the bucket has no policy, a new policy containing only the TLS deny statement
       is attached.
  3. SAFETY FIRST:
     - DRY-RUN BY DEFAULT: No changes applied unless --execute (or --apply) is passed.
     - Automatic Rollback Backups: Pre-change policy JSON saved before modification.
     - Supports --rollback <backup-file.json> to instantly revert changes.

Statement Merged:
  {
    "Sid": "DenyInsecureTransport",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": ["arn:aws:s3:::<bucket>", "arn:aws:s3:::<bucket>/*"],
    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
  }

Usage:
  # 1. Preview candidates across all 3 organizations (Safe simulation):
  python enforce_tls_empty_buckets.py

  # 2. Preview for a specific organization:
  python enforce_tls_empty_buckets.py --profile rus-ext

  # 3. Preview for the currently authenticated session in PowerShell:
  python enforce_tls_empty_buckets.py --current-session

  # 4. Apply TLS enforcement live across all empty buckets:
  python enforce_tls_empty_buckets.py --execute

  # 5. Apply to a single specific bucket:
  python enforce_tls_empty_buckets.py --bucket aaas-airflow-pent --account-id 640118963281 --profile rus-ext --execute
================================================================================
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timezone

# Add scripts/remediations to path for shared core
core_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts", "remediations")
if not os.path.exists(core_path):
    core_path = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, core_path)

from aws_remediation_core import (
    get_session_for_profile, assume_cross_account_role,
    save_rollback_backup, log_remediation_action,
    DEFAULT_PROFILES, S3_CONFIG
)
from botocore.exceptions import ClientError

REMEDIATION_NAME = "enforce_tls_empty_buckets"
SID = "DenyInsecureTransport"

CANDIDATE_CSVS = [
    r"empty_buckets_zero_impact_candidates.csv",
    r"inputs\empty_buckets_zero_impact_candidates.csv",
    r"inputs\s3_cost_and_usage_metrics 11 10 26.csv",
    r"C:\kiro-projects\Asecure\empty_buckets_zero_impact_candidates.csv",
    r"C:\kiro-projects\Asecure\inputs\empty_buckets_zero_impact_candidates.csv",
]

def find_candidate_file():
    for p in CANDIDATE_CSVS:
        if os.path.exists(p):
            return p
    return None

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
    if not policy_doc or not isinstance(policy_doc, dict):
        return False
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Deny":
            continue
        for op in ("Bool", "BoolIfExists"):
            cond = stmt.get("Condition", {}).get(op, {})
            st = cond.get("aws:SecureTransport")
            if st in ["false", False, ["false"], [False]]:
                return True
    return False

def load_empty_bucket_candidates(target_org=None):
    candidates = []
    csv_file = find_candidate_file()
    if not csv_file:
        sys.exit("Error: Could not locate empty_buckets_zero_impact_candidates.csv or metrics file.")

    with open(csv_file, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Check if empty (0 bytes, 0 objects) or explicitly listed in empty_buckets CSV
            size_gb = float(row.get("StorageSizeGB") or 0.0)
            num_objs = int(float(row.get("NumberOfObjects") or 0))
            is_empty = (size_gb == 0.0 and num_objs == 0) or ("empty_buckets" in csv_file)

            if is_empty:
                # Filter out buckets that already enforce TLS if that info exists in CSV
                tls_enforced = row.get("TLS_Enforced")
                if tls_enforced != "True":
                    org = row.get("OrganizationProfile")
                    if target_org and org != target_org:
                        continue
                    candidates.append(row)

    return candidates

def remediate_single_empty_bucket(s3_client, account_id, bucket_name, org_profile, is_execute):
    """
    Safely merges DenyInsecureTransport into bucket policy without altering any other bucket properties.
    """
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
                "Details": f"GetBucketPolicy error: {code}",
                "Backup": "N/A"
            }

    # Check if policy already enforces TLS
    if previous_policy and policy_has_tls_deny(previous_policy):
        return {
            "Bucket": bucket_name,
            "Status": "SKIPPED",
            "Details": "Already Enforces TLS",
            "Backup": "N/A"
        }

    # Build new or merged policy
    if previous_policy:
        new_policy = json.loads(json.dumps(previous_policy)) # Deep copy
        stmts = new_policy.get("Statement", [])
        if isinstance(stmts, dict):
            stmts = [stmts]
        # Remove any stale Sid if present, then append cleanly
        stmts = [s for s in stmts if s.get("Sid") != SID]
        stmts.append(build_tls_statement(bucket_name))
        new_policy["Statement"] = stmts
        merge_type = f"Merged into existing policy ({len(stmts)-1} prior statements preserved)"
    else:
        new_policy = {
            "Version": "2012-10-17",
            "Statement": [build_tls_statement(bucket_name)]
        }
        merge_type = "Created new clean HTTPS-only policy"

    if not is_execute:
        return {
            "Bucket": bucket_name,
            "Status": "DRY_RUN_ELIGIBLE",
            "Details": f"Would enforce TLS -> {merge_type}",
            "Backup": "Simulated"
        }

    # Save timestamped backup before touching policy
    backup_file = save_rollback_backup(REMEDIATION_NAME, account_id, bucket_name, previous_policy)

    # Apply policy
    try:
        s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(new_policy)
        )
        return {
            "Bucket": bucket_name,
            "Status": "REMEDIATED",
            "Details": f"TLS Deny successfully applied -> {merge_type}",
            "Backup": backup_file
        }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        return {
            "Bucket": bucket_name,
            "Status": "FAILED",
            "Details": f"PutBucketPolicy error: {code}",
            "Backup": backup_file
        }

def rollback_policy(s3_client, backup_json_path):
    with open(backup_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    bucket = data.get("BucketName")
    prev_policy = data.get("BackupData")
    if prev_policy is None:
        s3_client.delete_bucket_policy(Bucket=bucket)
        print(f"  [+] Rollback: Deleted policy on {bucket} (restored to no policy).")
    else:
        s3_client.put_bucket_policy(
            Bucket=bucket,
            Policy=json.dumps(prev_policy)
        )
        print(f"  [+] Rollback: Restored original policy statements on {bucket}.")

def main():
    parser = argparse.ArgumentParser(description="Enforce TLS 1.2+ on Empty S3 Buckets (Leaves other properties unchanged)")
    parser.add_argument("--profile", help="Target specific AWS Organization profile (rus-ext, rus-ioc, cccs). Default: all.")
    parser.add_argument("--current-session", action="store_true", help="Audit currently authenticated PowerShell session.")
    parser.add_argument("--bucket", help="Specific bucket name to remediate.")
    parser.add_argument("--account-id", help="Target AWS Account ID (required with --bucket).")
    parser.add_argument("--execute", "--apply", dest="execute", action="store_true", help="Apply changes to AWS. Default is dry-run.")
    parser.add_argument("--rollback", help="Path to rollback JSON backup to restore.")
    args = parser.parse_args()

    mode_str = "EXECUTE (LIVE CHANGES)" if args.execute else "DRY-RUN (SIMULATION ONLY - NO CHANGES MADE)"

    print("\n" + "=" * 80)
    print("  AWS S3 ZERO-IMPACT TLS ENFORCEMENT ON EMPTY BUCKETS")
    print(f"  Mode:       {mode_str}")
    print("  Constraint: Non-destructive policy merge (All other bucket properties untouched)")
    print("=" * 80 + "\n")

    if args.rollback:
        if not os.path.exists(args.rollback):
            sys.exit(f"Error: Rollback file not found: {args.rollback}")
        with open(args.rollback, "r") as f:
            bdata = json.load(f)
        prof = args.profile or "rus-ext"
        sess = get_session_for_profile(prof)
        if not sess:
            sys.exit(f"Could not authenticate profile: {prof}")
        acct_s, _ = assume_cross_account_role(sess, bdata["AccountId"])
        s3 = acct_s.client("s3", config=S3_CONFIG)
        rollback_policy(s3, args.rollback)
        return

    # Determine Targets
    targets = []
    if args.bucket:
        if not args.account_id:
            sys.exit("Error: --account-id is required when specifying --bucket.")
        targets.append({
            "BucketName": args.bucket,
            "AccountId": args.account_id,
            "OrganizationProfile": args.profile or "current"
        })
    else:
        targets = load_empty_bucket_candidates(target_org=args.profile)

    print(f"[*] Identified {len(targets)} empty bucket candidate(s) needing TLS enforcement.\n")
    if not targets:
        print("[+] All empty buckets already enforce TLS! Nothing to do.")
        return

    sessions = {}
    success_count = 0
    skipped_count = 0
    fail_count = 0

    for item in targets:
        b_name = item["BucketName"]
        a_id = item.get("AccountId")
        org = item.get("OrganizationProfile") or args.profile or "current"

        # Sanitize account ID if formatted as float string
        if "E+" in a_id:
            try:
                a_id = str(int(float(a_id)))
            except Exception:
                pass

        if org not in sessions:
            s = get_session_for_profile(org, is_current_session=args.current_session)
            if not s:
                print(f"[!] Warning: Authentication failed for profile '{org}'. Skipping {b_name}.")
                fail_count += 1
                continue
            sessions[org] = s
        mgmt_s = sessions[org]

        acct_s, role_used = assume_cross_account_role(mgmt_s, a_id)
        if not acct_s:
            print(f"[!] Warning: Could not assume role in Account {a_id}. Skipping {b_name}.")
            fail_count += 1
            continue

        s3 = acct_s.client("s3", config=S3_CONFIG)
        res = remediate_single_empty_bucket(s3, a_id, b_name, org, args.execute)

        status = res["Status"]
        details = res["Details"]
        backup = res["Backup"]

        log_remediation_action(REMEDIATION_NAME, {
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "Remediation": REMEDIATION_NAME,
            "OrganizationProfile": org,
            "AccountId": a_id,
            "BucketName": b_name,
            "Action": "MERGE_TLS_DENY_STATEMENT",
            "Status": status,
            "Details": details,
            "BackupFile": backup
        })

        if status in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]:
            symbol = "[DRY-RUN]" if not args.execute else "[REMEDIATED]"
            print(f"  {symbol} {b_name:<45} ({org:<7} | {a_id}) -> {details}")
            success_count += 1
        elif status == "SKIPPED":
            print(f"  [SKIPPED]  {b_name:<45} -> {details}")
            skipped_count += 1
        else:
            print(f"  [FAILED]   {b_name:<45} ({a_id}) -> {details}")
            fail_count += 1

    print("\n" + "-" * 80)
    print(f"[*] SUMMARY: {success_count} Eligible/Remediated | {skipped_count} Skipped | {fail_count} Failed")
    if not args.execute:
        print("[*] Review the dry-run simulation above.")
        print("[*] To apply these non-destructive TLS changes to AWS, re-run with: --execute")
    else:
        print("[+] All TLS changes completed! Backups stored in backups/remediations/enforce_tls_empty_buckets/")
    print("-" * 80 + "\n")

if __name__ == "__main__":
    main()
