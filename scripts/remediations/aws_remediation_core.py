#!/usr/bin/env python3
"""
aws_remediation_core.py
================================================================================
Shared core module for AWS S3 individual remediation scripts.
Provides robust multi-org SSO authentication cascade, cross-account role assumption,
automatic rollback backups, audit logging, and CLI argument parsing.
================================================================================
"""

import os
import sys
import json
import csv
import subprocess
from datetime import datetime, timezone
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, BotoCoreError

S3_CONFIG = Config(
    s3={"addressing_style": "virtual"},
    retries={"max_attempts": 5, "mode": "standard"},
)

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
    "AdministratorAccess"
]

def resolve_profile(profile):
    return PROFILE_ALIASES.get(profile, profile)

def get_session_for_profile(profile_name, is_current_session=False):
    """
    4-tier authentication cascade:
    1. Direct boto3 session
    2. AWS CLI v2 Credential Bridge ('aws configure export-credentials --profile <profile> --format process')
    3. Profile alias fallback
    4. Active session fallback
    """
    if is_current_session or profile_name in ["current", "default", None]:
        try:
            session = boto3.Session()
            sts = session.client("sts")
            sts.get_caller_identity()
            return session
        except Exception:
            pass

    profile = resolve_profile(profile_name)
    try:
        session = boto3.Session(profile_name=profile)
        # Test credentials
        sts = session.client("sts")
        sts.get_caller_identity()
        return session
    except Exception:
        pass

    # Tier 2: Subprocess export-credentials (process format returns JSON)
    for p in [profile, f"{profile}-sso"]:
        try:
            cmd = ["aws", "configure", "export-credentials", "--profile", p, "--format", "process"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=15)
            if proc.returncode == 0 and proc.stdout.strip():
                creds = json.loads(proc.stdout)
                reg = "ca-central-1" if "cccs" in p else "us-east-1"
                return boto3.Session(
                    aws_access_key_id=creds.get("AccessKeyId"),
                    aws_secret_access_key=creds.get("SecretAccessKey"),
                    aws_session_token=creds.get("SessionToken"),
                    region_name=reg,
                )
        except Exception:
            pass

    # Fallback to default session
    try:
        session = boto3.Session()
        sts = session.client("sts")
        sts.get_caller_identity()
        return session
    except Exception:
        pass

    return None

def assume_cross_account_role(mgmt_session, target_account_id, role_names=None):
    """
    Assumes cross-account role in target member account.
    If target_account_id matches caller account, returns mgmt_session directly.
    """
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
                RoleSessionName="S3SecurityRemediation",
                DurationSeconds=3600
            )
            creds = resp["Credentials"]
            assumed_session = boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"]
            )
            return assumed_session, role_name
        except (ClientError, BotoCoreError):
            continue

    return None, None

def save_rollback_backup(remediation_name, account_id, bucket_name, backup_data):
    """
    Saves state to timestamped JSON file for safe rollback.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    backup_dir = os.path.join("backups", "remediations", remediation_name)
    os.makedirs(backup_dir, exist_ok=True)
    backup_file = os.path.join(backup_dir, f"{timestamp}_{account_id}_{bucket_name}.json")
    with open(backup_file, "w", encoding="utf-8") as f:
        json.dump({
            "Remediation": remediation_name,
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "AccountId": account_id,
            "BucketName": bucket_name,
            "BackupData": backup_data
        }, f, indent=2, default=str)
    return backup_file

def log_remediation_action(remediation_name, record):
    """
    Appends audit trail entry to CSV log.
    """
    log_dir = os.path.join("reports", "remediation_logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, f"{remediation_name}_log.csv")
    file_exists = os.path.exists(log_file)
    headers = [
        "Timestamp", "Remediation", "OrganizationProfile", "AccountId",
        "BucketName", "Action", "Status", "Details", "BackupFile"
    ]
    with open(log_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerow(record)
