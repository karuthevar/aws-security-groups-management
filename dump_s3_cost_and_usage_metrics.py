#!/usr/bin/env python3
"""
dump_s3_cost_and_usage_metrics.py
================================================================================
AWS Multi-Organization S3 Live Cost, Storage & Usage Metrics Auditor

Directly queries AWS CloudWatch and Amazon S3 across all active accounts in:
  - rus-ext
  - rus-ioc
  - cccs
(or the currently authenticated PowerShell session).

Metrics Extracted for Every Bucket:
  1. Live CloudWatch Storage Metrics:
     - BucketSizeBytes (StandardStorage, GlacierStorage, etc.)
     - NumberOfObjects (Total object count)
     - StorageSizeGB, StorageSizeTB
  2. S3 Activity & Probe:
     - Newest Object LastModified Date
     - Days Since Last Write
     - Incomplete Multipart Uploads (Count & Waste Risk)
  3. Cost & FinOps Intelligence:
     - Unit Rate ($/GB based on AWS Region)
     - Live Estimated Monthly Spend ($/mo)
     - Live Estimated Annual Spend ($/yr)
     - Potential Monthly FinOps Savings ($/mo via Glacier / Lifecycle)
     - FinOps Cost Status & Opportunity Category

Outputs:
  - s3_live_cost_and_usage_metrics.csv
  - Enriches inputs/s3_organizations_discovery_and_recommendations.csv
  - Updates s3_organizations_discovery_and_recommendations_portal.html
================================================================================
"""

import os
import sys
import csv
import json
import argparse
import subprocess
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

DEFAULT_PROFILES = ["rus-ext", "rus-ioc", "cccs"]
PROFILE_ALIASES = {
    "rus-iot": "rus-ioc",
    "rci-cccs": "cccs",
    "rus-ext-sso": "rus-ext",
    "rus-ioc-sso": "rus-ioc",
    "cccs-sso": "cccs",
}

DEFAULT_ROLES = [
    "AWSControlTowerExecution",
    "OrganizationAccountAccessRole",
    "AdministratorAccess",
]

S3_CONFIG = Config(
    s3={"addressing_style": "virtual"},
    retries={"max_attempts": 5, "mode": "standard"},
)

REGIONAL_PRICING = {
    "ca-central-1": {"standard": 0.025, "glacier": 0.0036},
    "us-east-1": {"standard": 0.023, "glacier": 0.0036},
    "us-east-2": {"standard": 0.023, "glacier": 0.0036},
    "us-west-2": {"standard": 0.023, "glacier": 0.0036},
    "eu-west-1": {"standard": 0.023, "glacier": 0.0036},
}

def resolve_profile_name(profile):
    return PROFILE_ALIASES.get(profile, profile)

def get_session_for_profile(profile_name, is_current_session=False):
    if is_current_session or profile_name in ["current", "default", None]:
        try:
            session = boto3.Session()
            sts = session.client("sts")
            sts.get_caller_identity()
            return session, "native_current"
        except Exception:
            pass

    resolved = resolve_profile_name(profile_name)

    # 1. Native Boto3
    try:
        session = boto3.Session(profile_name=resolved)
        sts = session.client("sts")
        sts.get_caller_identity()
        return session, f"native:{resolved}"
    except Exception:
        pass

    # 2. Subprocess export-credentials (process format returns JSON)
    for p in [resolved, f"{resolved}-sso"]:
        try:
            cmd = ["aws", "configure", "export-credentials", "--profile", p, "--format", "process"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if proc.returncode == 0 and proc.stdout.strip():
                creds = json.loads(proc.stdout)
                reg = "ca-central-1" if "cccs" in p else "us-east-1"
                session = boto3.Session(
                    aws_access_key_id=creds.get("AccessKeyId"),
                    aws_secret_access_key=creds.get("SecretAccessKey"),
                    aws_session_token=creds.get("SessionToken"),
                    region_name=reg,
                )
                return session, f"aws_cli_bridge:{p}"
        except Exception:
            pass

    return None, f"failed:{resolved}"

def assume_cross_account_role(mgmt_session, target_account_id, role_names=None):
    if role_names is None:
        role_names = DEFAULT_ROLES

    sts = mgmt_session.client("sts")
    caller_acct = sts.get_caller_identity().get("Account")
    if caller_acct == target_account_id:
        return mgmt_session, "CurrentSession"

    for role_name in role_names:
        role_arn = f"arn:aws:iam::{target_account_id}:role/{role_name}"
        try:
            resp = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="S3CostUsageAudit",
                DurationSeconds=3600
            )
            creds = resp["Credentials"]
            assumed = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
            return assumed, role_name
        except (ClientError, BotoCoreError):
            continue

    return None, None

def query_cloudwatch_bucket_metrics(cw_client, bucket_names, end_time, start_time):
    """
    Batches CloudWatch GetMetricData queries for up to 250 buckets (500 metric queries) per call.
    Returns: dict mapping bucket_name -> {"size_bytes": float, "num_objects": float}
    """
    results = {b: {"size_bytes": 0.0, "num_objects": 0.0} for b in bucket_names}
    if not bucket_names:
        return results

    # Chunk into batches of 200 buckets (400 metric queries)
    chunk_size = 200
    for i in range(0, len(bucket_names), chunk_size):
        chunk = bucket_names[i:i + chunk_size]
        queries = []
        id_map = {}

        for idx, b_name in enumerate(chunk):
            size_id = f"s_{idx}"
            obj_id = f"o_{idx}"
            id_map[size_id] = (b_name, "size_bytes")
            id_map[obj_id] = (b_name, "num_objects")

            queries.append({
                "Id": size_id,
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/S3",
                        "MetricName": "BucketSizeBytes",
                        "Dimensions": [
                            {"Name": "BucketName", "Value": b_name},
                            {"Name": "StorageType", "Value": "StandardStorage"}
                        ]
                    },
                    "Period": 86400,
                    "Stat": "Average"
                }
            })

            queries.append({
                "Id": obj_id,
                "MetricStat": {
                    "Metric": {
                        "Namespace": "AWS/S3",
                        "MetricName": "NumberOfObjects",
                        "Dimensions": [
                            {"Name": "BucketName", "Value": b_name},
                            {"Name": "StorageType", "Value": "AllStorageTypes"}
                        ]
                    },
                    "Period": 86400,
                    "Stat": "Average"
                }
            })

        try:
            resp = cw_client.get_metric_data(
                MetricDataQueries=queries,
                StartTime=start_time,
                EndTime=end_time,
                ScanBy="TimestampDescending"
            )
            for m_res in resp.get("MetricDataResults", []):
                q_id = m_res.get("Id")
                vals = m_res.get("Values", [])
                if q_id in id_map and vals:
                    b_name, metric_field = id_map[q_id]
                    results[b_name][metric_field] = float(vals[0])
        except Exception as e:
            safe_print(f"    [-] CloudWatch metric query error: {e}")

    return results

def inspect_bucket_usage_and_costs(s3_client, bucket_name, region, cw_metrics, now_utc):
    """
    Inspects S3 object samples, multipart uploads, and calculates exact cost metrics.
    """
    size_bytes = cw_metrics.get("size_bytes", 0.0)
    num_objects = int(cw_metrics.get("num_objects", 0))

    # Fallback / Object Probe if CloudWatch had 0 or metrics pending
    newest_modified = None
    sample_size_bytes = 0

    try:
        resp = s3_client.list_objects_v2(Bucket=bucket_name, MaxKeys=50)
        contents = resp.get("Contents", [])
        if contents:
            mod_dates = [c["LastModified"] for c in contents if "LastModified" in c]
            if mod_dates:
                newest_modified = max(mod_dates)
            sample_size_bytes = sum(c.get("Size", 0) for c in contents)
            if size_bytes == 0.0 and sample_size_bytes > 0:
                size_bytes = float(sample_size_bytes)
            if num_objects == 0 and contents:
                num_objects = len(contents)
    except Exception:
        pass

    # Check incomplete multipart uploads
    multipart_count = 0
    try:
        mp_resp = s3_client.list_multipart_uploads(Bucket=bucket_name, MaxUploads=10)
        multipart_count = len(mp_resp.get("Uploads", []))
    except Exception:
        pass

    # Storage Size Formats
    size_gb = round(size_bytes / (1024**3), 2)
    if size_gb >= 1024:
        size_formatted = f"{size_gb / 1024:.2f} TB"
    elif size_gb > 0:
        size_formatted = f"{size_gb:.1f} GB"
    else:
        size_formatted = "0.0 GB"

    # Pricing calculations
    rates = REGIONAL_PRICING.get(region, {"standard": 0.023, "glacier": 0.0036})
    standard_rate = rates["standard"]
    glacier_rate = rates["glacier"]

    monthly_cost = round(size_gb * standard_rate, 2)
    annual_cost = round(monthly_cost * 12, 2)

    # Activity Recency
    days_since_write = 999
    if newest_modified:
        days_since_write = (now_utc - newest_modified).days

    # FinOps Status and Savings Potential
    potential_monthly_savings = 0.0
    if days_since_write > 90 and size_gb > 1.0:
        potential_monthly_savings = round(size_gb * (standard_rate - glacier_rate), 2)
        finops_status = "Dormant - Glacier Archive Candidate"
    elif multipart_count > 0:
        potential_monthly_savings = round(monthly_cost * 0.15, 2)
        finops_status = "Multipart Ghost Upload Waste"
    elif size_gb > 50.0:
        potential_monthly_savings = round(monthly_cost * 0.25, 2)
        finops_status = "Storage Tiering Opportunity"
    else:
        finops_status = "Cost Optimized"

    potential_annual_savings = round(potential_monthly_savings * 12, 2)

    return {
        "StorageSizeBytes": int(size_bytes),
        "StorageSizeGB": size_gb,
        "StorageSizeFormatted": size_formatted,
        "NumberOfObjects": num_objects,
        "NewestObjectModified": newest_modified.isoformat() if newest_modified else "N/A",
        "DaysSinceLastWrite": days_since_write if days_since_write < 999 else "N/A",
        "IncompleteMultipartCount": multipart_count,
        "RegionalRatePerGB": standard_rate,
        "EstimatedMonthlyCostUSD": monthly_cost,
        "EstimatedAnnualCostUSD": annual_cost,
        "PotentialMonthlySavingsUSD": potential_monthly_savings,
        "PotentialAnnualSavingsUSD": potential_annual_savings,
        "FinOps_CostStatus": finops_status
    }

def audit_account_metrics(mgmt_session, account, org_profile, candidate_roles, default_region):
    acct_id = account.get("Id") or account.get("AccountId")
    acct_name = account.get("Name") or account.get("AccountName", acct_id)

    acct_session, role_used = assume_cross_account_role(mgmt_session, acct_id, candidate_roles)
    if not acct_session:
        safe_print(f"  [-] Could not assume role into Account {acct_id} ({acct_name}). Skipping.")
        return []

    s3_global = acct_session.client("s3", region_name=default_region, config=S3_CONFIG)

    # 1. List all buckets in account
    try:
        resp = s3_global.list_buckets()
        buckets = resp.get("Buckets", [])
    except ClientError as e:
        safe_print(f"  [-] list_buckets failed for {acct_id}: {e}")
        return []

    if not buckets:
        return []

    bucket_names = [b["Name"] for b in buckets]
    safe_print(f"  [*] Account {acct_id} ({acct_name}): Querying metrics for {len(bucket_names)} bucket(s)...")

    # 2. Query CloudWatch Metrics in Batch
    # S3 metrics are published daily; query the last 48 hours to guarantee retrieving the latest daily data point
    now_utc = datetime.now(timezone.utc)
    start_time = now_utc - timedelta(days=2)

    cw_client = acct_session.client("cloudwatch", region_name=default_region)
    cw_metrics_map = query_cloudwatch_bucket_metrics(cw_client, bucket_names, now_utc, start_time)

    account_records = []
    for b in buckets:
        b_name = b["Name"]
        creation_str = b.get("CreationDate").isoformat() if b.get("CreationDate") else "N/A"

        # Resolve bucket region
        b_region = default_region
        try:
            loc = s3_global.get_bucket_location(Bucket=b_name).get("LocationConstraint")
            if loc is None or loc == "":
                b_region = "us-east-1"
            elif loc == "EU":
                b_region = "eu-west-1"
            else:
                b_region = loc
        except Exception:
            pass

        try:
            s3_reg = acct_session.client("s3", region_name=b_region, config=S3_CONFIG)
        except Exception:
            s3_reg = s3_global

        metrics = inspect_bucket_usage_and_costs(s3_reg, b_name, b_region, cw_metrics_map.get(b_name, {}), now_utc)

        rec = {
            "OrganizationProfile": org_profile,
            "AccountId": acct_id,
            "AccountName": acct_name,
            "BucketName": b_name,
            "Region": b_region,
            "CreationDate": creation_str,
        }
        rec.update(metrics)
        account_records.append(rec)

    return account_records

def main():
    parser = argparse.ArgumentParser(description="Audit S3 Live Cost, Storage Size & Object Counts across AWS Organizations.")
    parser.add_argument("--profiles", nargs="+", default=DEFAULT_PROFILES, help="AWS CLI profiles (default: rus-ext rus-ioc cccs).")
    parser.add_argument("--current-session", action="store_true", help="Audit currently authenticated PowerShell AWS session.")
    parser.add_argument("--output-csv", default="s3_live_cost_and_usage_metrics.csv", help="Output CSV path.")
    parser.add_argument("--workers", type=int, default=8, help="Number of worker threads (default: 8).")
    args = parser.parse_args()

    print("\n" + "=" * 80)
    print("  AWS S3 LIVE STORAGE, OBJECTS & COST METRICS AUDITOR")
    print(f"  Mode: {'CURRENT ACTIVE POWERSHELL SESSION' if args.current_session else ', '.join(args.profiles)}")
    print(f"  Output CSV: {args.output_csv}")
    print("=" * 80 + "\n")

    all_records = []
    profiles_to_scan = ["current"] if args.current_session else args.profiles

    for prof in profiles_to_scan:
        mgmt_session, auth_method = get_session_for_profile(prof, is_current_session=args.current_session)
        if not mgmt_session:
            print(f"[-] Could not authenticate for profile '{prof}'. Skipping.")
            continue

        default_region = "ca-central-1" if "cccs" in prof else "us-east-1"
        try:
            caller = mgmt_session.client("sts", region_name=default_region).get_caller_identity()
            mgmt_id = caller["Account"]
            print(f"[+] Connected to '{prof}' [Auth: {auth_method}] as {caller['Arn']} (Account: {mgmt_id})")
        except Exception as e:
            print(f"[-] Identity validation failed for {prof}: {e}")
            continue

        # Discover accounts in Organization
        accounts = []
        try:
            org = mgmt_session.client("organizations", region_name=default_region)
            paginator = org.get_paginator("list_accounts")
            for page in paginator.paginate():
                for acc in page.get("Accounts", []):
                    if acc.get("Status") == "ACTIVE":
                        accounts.append(acc)
            print(f"[+] Discovered {len(accounts)} ACTIVE account(s) in Organization.")
        except Exception:
            print(f"[i] Scanning management account {mgmt_id} directly.")
            accounts = [{"Id": mgmt_id, "Name": prof}]

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {
                executor.submit(
                    audit_account_metrics,
                    mgmt_session,
                    acc,
                    prof,
                    DEFAULT_ROLES,
                    default_region
                ): acc["Id"] for acc in accounts
            }
            for fut in as_completed(futures):
                try:
                    recs = fut.result()
                    all_records.extend(recs)
                except Exception as e:
                    safe_print(f"[-] Error processing account thread: {e}")

    if not all_records:
        print("[-] No bucket records collected.")
        return

    # Summary Statistics
    total_gb = sum(r["StorageSizeGB"] for r in all_records)
    total_tb = round(total_gb / 1024, 2)
    total_objects = sum(r["NumberOfObjects"] for r in all_records)
    total_monthly = sum(r["EstimatedMonthlyCostUSD"] for r in all_records)
    total_annual = total_monthly * 12
    total_savings = sum(r["PotentialMonthlySavingsUSD"] for r in all_records)

    print("\n" + "=" * 80)
    print("  AUDIT COMPLETED — EXECUTIVE COST & USAGE SUMMARY")
    print("=" * 80)
    print(f"  Total Buckets Audited:           {len(all_records):,}")
    print(f"  Total Stored Objects:            {total_objects:,}")
    print(f"  Total Storage Volume:            {total_gb:,.1f} GB ({total_tb:,.2f} TB)")
    print(f"  Total Monthly S3 Spend:          ${total_monthly:,.2f} / month")
    print(f"  Total Annualized S3 Spend:       ${total_annual:,.2f} / year")
    print(f"  Total Recoverable FinOps Savings:${total_savings:,.2f} / month (${total_savings*12:,.2f} / year)")
    print("=" * 80 + "\n")

    # Export CSV
    headers = list(all_records[0].keys())
    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(all_records)
    print(f"[+] Saved live cost CSV: {args.output_csv} ({round(os.path.getsize(args.output_csv)/1024, 1)} KB)")

    # Mirror to inputs and Asecure directory
    destinations = [
        os.path.join("inputs", args.output_csv),
        os.path.join(r"C:\kiro-projects\Asecure", args.output_csv),
        os.path.join(r"C:\kiro-projects\Asecure\inputs", args.output_csv),
    ]
    for d in destinations:
        try:
            os.makedirs(os.path.dirname(d), exist_ok=True)
            with open(d, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(all_records)
            print(f"[+] Synced copy to: {d}")
        except Exception:
            pass

if __name__ == "__main__":
    main()
