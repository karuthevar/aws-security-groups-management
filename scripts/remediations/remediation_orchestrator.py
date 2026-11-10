#!/usr/bin/env python3
"""
remediation_orchestrator.py
================================================================================
Interactive S3 Multi-Organization Remediation Console & Orchestrator

Allows operators and cloud security engineers to itemize, preview (dry-run),
and safely execute the 6 S3 security remediations across all active AWS accounts.
================================================================================
"""

import os
import sys
import csv
import subprocess

CSV_PATH = r"inputs\s3_organizations_discovery_and_recommendations.csv"
if not os.path.exists(CSV_PATH):
    CSV_PATH = r"inputs\s3_all_organizations_inventory.csv"

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))

def get_summary_counts():
    counts = {
        "total": 0,
        "REM_PAB_LOCKDOWN": 0,
        "REM_ENFORCE_TLS": 0,
        "REM_ENFORCE_ENCRYPTION": 0,
        "REM_ENABLE_VERSIONING": 0,
        "REM_ENABLE_LOGGING": 0,
        "REM_ATTACH_LIFECYCLE": 0,
        "CRITICAL_PUBLIC": 0,
    }
    if not os.path.exists(CSV_PATH):
        return counts

    with open(CSV_PATH, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            counts["total"] += 1
            if row.get("PAB_Status") != "Fully Blocked (Compliant)":
                counts["REM_PAB_LOCKDOWN"] += 1
            if row.get("Policy_EnforcesTLS") != "True":
                counts["REM_ENFORCE_TLS"] += 1
            if row.get("IsEncrypted") != "True" or row.get("EncryptionType") in ["None", "AccessDenied"]:
                counts["REM_ENFORCE_ENCRYPTION"] += 1
            if row.get("VersioningStatus") != "Enabled":
                counts["REM_ENABLE_VERSIONING"] += 1
            if row.get("LoggingEnabled") != "True":
                counts["REM_ENABLE_LOGGING"] += 1
            if row.get("HasLifecycleRules") != "True":
                counts["REM_ATTACH_LIFECYCLE"] += 1
            if row.get("IsPublic") == "True" or row.get("PublicExposureRisk") == "PUBLIC_BY_POLICY":
                counts["CRITICAL_PUBLIC"] += 1

    return counts

def print_header(counts):
    print("\n" + "=" * 80)
    print("  AWS S3 MULTI-ORGANIZATION DISCOVERY & REMEDIATION ORCHESTRATOR")
    print(f"  Active Monitored Inventory: {counts['total']} Buckets across 42 Accounts")
    if counts['CRITICAL_PUBLIC'] > 0:
        print(f"  [!] ALERT: {counts['CRITICAL_PUBLIC']} BUCKET(S) CURRENTLY EXPOSED DIRECTLY TO PUBLIC INTERNET")
    print("=" * 80)
    print("  ITEMIZED REMEDIATION PLAYBOOKS:")
    print(f"  [1] S3-REM-01: Public Access Block (PAB) Lockdown        [{counts['REM_PAB_LOCKDOWN']:>3} Buckets Needing Fix]")
    print(f"  [2] S3-REM-02: Enforce TLS 1.2+ HTTPS-Only Policy         [{counts['REM_ENFORCE_TLS']:>3} Buckets Needing Fix]")
    print(f"  [3] S3-REM-03: Enforce Default SSE Encryption (AES256)    [{counts['REM_ENFORCE_ENCRYPTION']:>3} Buckets Needing Fix]")
    print(f"  [4] S3-REM-04: Enable S3 Versioning & Ransomware Guard    [{counts['REM_ENABLE_VERSIONING']:>3} Buckets Needing Fix]")
    print(f"  [5] S3-REM-05: Enable Server Access Logging Target        [{counts['REM_ENABLE_LOGGING']:>3} Buckets Needing Fix]")
    print(f"  [6] S3-REM-06: S3 Cost Optimization & Lifecycle Rules     [{counts['REM_ATTACH_LIFECYCLE']:>3} Buckets Needing Fix]")
    print("  ------------------------------------------------------------------------------")
    print("  [7] Refresh Discovery Data, Generate CSV & HTML Portal")
    print("  [8] Open Interactive HTML Report in Default Browser")
    print("  [Q] Quit")
    print("=" * 80 + "\n")

def run_script(script_name, args_list):
    full_path = os.path.join(SCRIPTS_DIR, script_name)
    cmd = [sys.executable, full_path] + args_list
    print(f"\n[RUNNING] {' '.join(cmd)}\n")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by operator.")

def main():
    while True:
        counts = get_summary_counts()
        print_header(counts)
        choice = input("Select an option (1-8 or Q): ").strip().upper()

        if choice in ["Q", "QUIT", "EXIT"]:
            print("Exiting S3 Remediation Orchestrator. Stay secure!")
            break

        if choice == "7":
            cmd = [sys.executable, os.path.join(os.path.dirname(SCRIPTS_DIR), "generate_s3_discovery_and_recommendations.py")]
            subprocess.run(cmd)
            continue

        if choice == "8":
            portal_path = r"s3_organizations_discovery_and_recommendations_portal.html"
            if not os.path.exists(portal_path):
                portal_path = r"s3_organizations_security_inventory_portal.html"
            os.system(f'start "" "{portal_path}"')
            continue

        script_map = {
            "1": "remediate_01_pab_lockdown.py",
            "2": "remediate_02_enforce_tls.py",
            "3": "remediate_03_enforce_encryption.py",
            "4": "remediate_04_enable_versioning.py",
            "5": "remediate_05_enable_access_logging.py",
            "6": "remediate_06_lifecycle_cleanup.py",
        }

        if choice not in script_map:
            print("[!] Invalid selection. Please choose 1-8 or Q.")
            continue

        script_to_run = script_map[choice]

        print(f"\nConfiguring options for: {script_to_run}")
        mode_input = input("Choose Mode: [D]ry-run simulation (Safe) or [E]xecute live changes (D/E, default: D): ").strip().upper()
        is_execute = (mode_input == "E")

        target_input = input("Choose Scope: [A]ll candidates in inventory or [S]ingle specific bucket (A/S, default: A): ").strip().upper()

        args = []
        if is_execute:
            confirm = input("Are you SURE you want to execute live changes to AWS? (yes/no): ").strip().lower()
            if confirm not in ["y", "yes"]:
                print("Aborting live execution. Running in dry-run mode instead.")
            else:
                args.append("--execute")

        if target_input == "S":
            b_name = input("Enter Bucket Name: ").strip()
            a_id = input("Enter Account ID: ").strip()
            prof = input("Enter Organization Profile (rus-ext, rus-ioc, cccs): ").strip()
            args.extend(["--bucket", b_name, "--account-id", a_id, "--profile", prof])
        else:
            args.append("--all")

        # Specific option for logging
        if choice == "5":
            target_bucket = input("Enter central logging target bucket name (required): ").strip()
            if not target_bucket:
                print("[!] Target bucket is required for access logging. Aborting.")
                continue
            args.extend(["--target-bucket", target_bucket])

        # Specific option for versioning lifecycle
        if choice == "4":
            add_life = input("Also attach 90-day noncurrent version expiration lifecycle rule? (y/n, default: y): ").strip().lower()
            if add_life in ["", "y", "yes"]:
                args.extend(["--add-lifecycle", "--expire-days", "90"])

        run_script(script_to_run, args)
        input("\nPress Enter to return to main menu...")

if __name__ == "__main__":
    main()
