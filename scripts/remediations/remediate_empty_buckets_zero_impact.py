#!/usr/bin/env python3
"""
remediate_empty_buckets_zero_impact.py
================================================================================
Zero-Impact S3 Security & Governance Enforcer for Empty & Near-Empty Buckets

Targets buckets that have 0 objects / 0 bytes (or <100 MB) identified from
inputs/s3_cost_and_usage_metrics 11 10 26.csv.

Because these buckets contain no active workload data:
  1. Enforcing TLS 1.2+ HTTPS Deny Policies has ZERO downtime risk.
  2. Enabling full 4-Control Public Access Block (PAB) has ZERO user impact.
  3. Attaching 7-day Multipart Upload Abort rules has ZERO data risk.
  4. Enabling Versioning + 90-day expiration costs $0.00 while hardening resilience.

Usage:
  # 1. Preview zero-impact guardrails on all 123 empty buckets:
  python scripts/remediations/remediate_empty_buckets_zero_impact.py --empty-only --all-guardrails --dry-run

  # 2. Preview on near-empty buckets (<= 100 MB):
  python scripts/remediations/remediate_empty_buckets_zero_impact.py --max-mb 100 --all-guardrails --dry-run

  # 3. Apply TLS + PAB + Lifecycle live on empty buckets:
  python scripts/remediations/remediate_empty_buckets_zero_impact.py --empty-only --all-guardrails --execute
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

# Import individual remediation functions
from remediate_01_pab_lockdown import remediate_bucket_pab
from remediate_02_enforce_tls import remediate_bucket_tls
from remediate_04_enable_versioning import remediate_bucket_versioning
from remediate_06_lifecycle_cleanup import remediate_bucket_lifecycle

METRICS_CSV = r"inputs\s3_cost_and_usage_metrics 11 10 26.csv"
if not os.path.exists(METRICS_CSV):
    METRICS_CSV = r"C:\kiro-projects\Asecure\inputs\s3_cost_and_usage_metrics 11 10 26.csv"

def load_empty_candidates(max_mb=0.0):
    candidates = []
    if not os.path.exists(METRICS_CSV):
        return candidates

    with open(METRICS_CSV, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            size_gb = float(row.get("StorageSizeGB") or 0.0)
            num_objects = int(float(row.get("NumberOfObjects") or 0))
            size_mb = size_gb * 1024.0

            if max_mb == 0.0:
                if size_gb == 0.0 and num_objects == 0:
                    candidates.append(row)
            else:
                if size_mb <= max_mb:
                    candidates.append(row)

    return candidates

def main():
    parser = argparse.ArgumentParser(description="Zero-Impact Remediations on Empty / Near-Empty Buckets")
    parser.add_argument("--empty-only", action="store_true", default=True, help="Target strictly 0-byte, 0-object buckets (123 buckets).")
    parser.add_argument("--max-mb", type=float, default=0.0, help="Target buckets with storage <= max MB (e.g. --max-mb 100).")
    parser.add_argument("--all-guardrails", action="store_true", default=True, help="Apply TLS, PAB, and 7-day Multipart Abort rules.")
    parser.add_argument("--include-versioning", action="store_true", help="Also enable Versioning + 90-day noncurrent expiration.")
    parser.add_argument("--execute", "--apply", dest="execute", action="store_true", help="Apply changes live. Default: dry-run.")
    args = parser.parse_args()

    max_mb = args.max_mb if args.max_mb > 0 else (0.0 if args.empty_only else 0.0)
    candidates = load_empty_candidates(max_mb)

    scope_name = "STRICTLY EMPTY (0 Bytes, 0 Objects)" if max_mb == 0 else f"NEAR-EMPTY (<= {max_mb} MB)"
    mode_name = "EXECUTE (LIVE)" if args.execute else "DRY-RUN (SIMULATION ONLY)"

    print("\n" + "=" * 80)
    print("  AWS S3 ZERO-IMPACT REMEDIATION ENFORCER FOR EMPTY BUCKETS")
    print(f"  Scope: {scope_name} -> {len(candidates)} Candidate Buckets")
    print(f"  Mode:  {mode_name}")
    print("=" * 80 + "\n")

    if not candidates:
        print("[-] No candidate buckets matched criteria.")
        return

    sessions = {}
    pab_count = 0
    tls_count = 0
    life_count = 0
    ver_count = 0

    for item in candidates:
        b_name = item["BucketName"]
        a_id = item.get("AccountId")
        org = item.get("OrganizationProfile", "rus-ext")

        # Format account id if exponential notation exists
        if "E+" in a_id:
            try:
                a_id = str(int(float(a_id)))
            except Exception:
                pass

        if org not in sessions:
            s, _ = get_session_for_profile(org)
            if not s:
                continue
            sessions[org] = s
        mgmt_s = sessions[org]

        acct_s, role_used = assume_cross_account_role(mgmt_s, a_id)
        if not acct_s:
            continue

        s3 = acct_s.client("s3", config=S3_CONFIG)

        # 1. PAB Lockdown
        res_pab = remediate_bucket_pab(s3, a_id, b_name, org, args.execute)
        if res_pab["Status"] in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]:
            pab_count += 1

        # 2. TLS Enforce
        res_tls = remediate_bucket_tls(s3, a_id, b_name, org, args.execute)
        if res_tls["Status"] in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]:
            tls_count += 1

        # 3. 7-Day Multipart Abort
        res_life = remediate_bucket_lifecycle(s3, a_id, b_name, org, abort_days=7, glacier_days=None, is_execute=args.execute)
        if res_life["Status"] in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]:
            life_count += 1

        # 4. Optional Versioning
        if args.include_versioning:
            res_ver = remediate_bucket_versioning(s3, a_id, b_name, org, add_lifecycle=True, expire_days=90, is_execute=args.execute)
            if res_ver["Status"] in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]:
                ver_count += 1

        action_flags = []
        if res_pab["Status"] in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]: action_flags.append("PAB")
        if res_tls["Status"] in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]: action_flags.append("TLS")
        if res_life["Status"] in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]: action_flags.append("Lifecycle")
        if args.include_versioning and res_ver["Status"] in ["REMEDIATED", "DRY_RUN_ELIGIBLE"]: action_flags.append("Versioning")

        flag_str = "+".join(action_flags) if action_flags else "Already Fully Compliant"
        symbol = "[DRY-RUN]" if not args.execute else "[REMEDIATED]"
        safe_print(f"  {symbol} {b_name} ({org} | {a_id}) -> {flag_str}")

    print("\n--------------------------------------------------------------------------------")
    print(f"[*] SUMMARY FOR {len(candidates)} EMPTY BUCKETS:")
    print(f"  - PAB Lockdowns Eligible/Applied:      {pab_count}")
    print(f"  - TLS Enforcements Eligible/Applied:  {tls_count}")
    print(f"  - Multipart Lifecycle Rules Added:    {life_count}")
    if args.include_versioning:
        print(f"  - Versioning + 90d Expirations:       {ver_count}")
    if not args.execute:
        print("\n[*] All operations above have ZERO production downtime risk on empty buckets.")
        print("[*] To execute live changes, re-run with: --execute")
    print("--------------------------------------------------------------------------------\n")

if __name__ == "__main__":
    main()
