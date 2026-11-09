#!/usr/bin/env python3
"""
AWS Multi-Organization S3 Bucket Audit & Inventory Tool
================================================================================
Comprehensive dump of ALL S3 buckets across multiple AWS Organizations
(e.g., rus-ext, rus-ioc / rus-iot, and cccs / rci-cccs) or the currently
authenticated AWS session in PowerShell.

Audits & Extracts for EVERY S3 Bucket:
- Organization & Account: OrganizationProfile, OrganizationId, AccountId, AccountName
- Bucket Core: BucketName, BucketArn, Region, CreationDate
- Encryption Details:
    * IsEncrypted (True/False)
    * EncryptionType (AES256, aws:kms, aws:kms:dsse, None)
    * KMSMasterKeyId (Key ARN / ID / alias)
    * BucketKeyEnabled (True/False/None - reduces KMS costs)
    * ServerSideEncryptionConfiguration (Raw JSON details)
- Public Access & Perimeter Controls:
    * PublicAccessBlock (BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets)
    * PAB Status (Fully Blocked, Partially Blocked, None Configured)
    * Bucket Policy Status (IsPublic, PolicyStatementsCount)
    * Bucket ACL Analysis (Owner, Public Grants to AllUsers or AuthenticatedUsers)
    * Object Ownership (BucketOwnerEnforced, BucketOwnerPreferred, ObjectWriter)
    * Overall Public Exposure Verdict (SECURE, POTENTIALLY_PUBLIC, PUBLIC_BY_POLICY, PUBLIC_BY_ACL)
- Transport Security (TLS / HTTPS):
    * HasBucketPolicy (True/False)
    * EnforcesTLS (True/False - validates deny policy on aws:SecureTransport = false)
- Versioning & Object Lock:
    * VersioningStatus (Enabled, Suspended, Disabled)
    * MFADelete (Enabled, Disabled)
    * ObjectLockEnabled, ObjectLockMode (COMPLIANCE/GOVERNANCE), RetentionPeriod
- Storage Management & Lifecycle:
    * HasLifecycleRules, LifecycleRuleCount, LifecycleSummary
    * ReplicationEnabled, ReplicationDestinations
- Logging & Monitoring:
    * ServerAccessLogging (Enabled, TargetBucket, TargetPrefix)
    * EventNotifications (EventBridge, SNS, SQS, Lambda)
- Tags & Governance:
    * Tags_Formatted (Key=Value; Key=Value)
    * Tags_JSON (Machine-readable JSON dictionary)
    * Tags_Count
- Audit Summary & Compliance Rating:
    * AuditVerdict (COMPLIANT, LOW_RISK, MEDIUM_RISK, HIGH_RISK)
    * AuditFlags (Semicolon-delimited list of detected risks)

Outputs:
- CSV:  s3_all_organizations_inventory.csv (Excel-friendly consolidated sheet)
- JSON: s3_all_organizations_inventory.json (Complete hierarchical data dump)
- Executive console table with security distributions and compliance percentages.
================================================================================
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import boto3
from botocore.config import Config
from botocore.exceptions import ClientError, ProfileNotFound, NoCredentialsError

# Thread-safe console printing
print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)

# Default organizations and profile aliases
DEFAULT_PROFILES = ["rus-ext", "rus-ioc", "cccs"]
PROFILE_ALIASES = {
    "rus-iot": "rus-ioc",
    "rci-cccs": "cccs",
    "rus-ext-sso": "rus-ext",
    "rus-ioc-sso": "rus-ioc",
    "cccs-sso": "cccs",
}

DEFAULT_ROLES = [
    "AWSControlTowerExecution",       # AWS Control Tower cross-account role
    "OrganizationAccountAccessRole",  # AWS Organizations standard role
    "AWSControlTowerAdmin",           # Control Tower admin fallback
    "AdministratorAccess",            # General admin fallback
]

# Standard S3 client config with virtual host addressing
S3_CONFIG = Config(
    s3={"addressing_style": "virtual"},
    retries={"max_attempts": 5, "mode": "standard"},
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Dump and audit all S3 buckets, metadata, settings, tags, and encryption across multiple AWS Organizations."
    )
    parser.add_argument(
        "--profiles",
        "-p",
        nargs="+",
        default=DEFAULT_PROFILES,
        help="One or more AWS CLI profiles to audit (default: rus-ext rus-ioc cccs). Use 'current' for active session.",
    )
    parser.add_argument(
        "--current-session",
        "-c",
        action="store_true",
        default=False,
        help="Audit the currently authenticated AWS session in PowerShell directly (bypasses profile lookup).",
    )
    parser.add_argument(
        "--role",
        "-r",
        default=os.environ.get("ROLE_NAME"),
        help="Custom IAM role name to assume in member accounts (default: AWSControlTowerExecution, OrganizationAccountAccessRole).",
    )
    parser.add_argument(
        "--output-csv",
        "-o",
        default="s3_all_organizations_inventory.csv",
        help="Output CSV file path (default: s3_all_organizations_inventory.csv).",
    )
    parser.add_argument(
        "--output-json",
        "-j",
        default="s3_all_organizations_inventory.json",
        help="Output JSON file path (default: s3_all_organizations_inventory.json).",
    )
    parser.add_argument(
        "--workers",
        "-w",
        type=int,
        default=8,
        help="Number of concurrent worker threads for account scanning (default: 8).",
    )
    parser.add_argument(
        "--bucket-workers",
        "-bw",
        type=int,
        default=5,
        help="Number of concurrent threads per account for bucket property inspection (default: 5).",
    )
    return parser.parse_args()


def get_candidate_roles(custom_role):
    roles = []
    if custom_role:
        roles.append(custom_role)
    for r in DEFAULT_ROLES:
        if r not in roles:
            roles.append(r)
    return roles


def resolve_profile_name(profile):
    """Resolve aliases (e.g. rus-iot -> rus-ioc, rci-cccs -> cccs)."""
    return PROFILE_ALIASES.get(profile, profile)


def check_tls_enforced_in_policy(policy_doc):
    """
    Analyzes bucket policy JSON document to check if HTTPS/TLS is strictly enforced.
    Typically enforced via a Statement with:
      Effect: Deny
      Condition: {"Bool": {"aws:SecureTransport": "false"}}
    """
    if not policy_doc:
        return False

    try:
        if isinstance(policy_doc, str):
            policy_doc = json.loads(policy_doc)

        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect", "")
            condition = stmt.get("Condition", {})

            if effect == "Deny":
                # Look for Bool condition on aws:SecureTransport = false
                bool_cond = condition.get("Bool", {})
                sec_transport = bool_cond.get("aws:SecureTransport")
                if sec_transport in ["false", False, ["false"], [False]]:
                    return True
                # Inverted condition check (e.g. StringNotEquals / BoolIfExists)
                for cond_type, cond_rules in condition.items():
                    if isinstance(cond_rules, dict):
                        st = cond_rules.get("aws:SecureTransport")
                        if st in ["false", False, ["false"], [False]]:
                            return True

            elif effect == "Allow":
                # Some policies use Allow with aws:SecureTransport = true
                bool_cond = condition.get("Bool", {})
                sec_transport = bool_cond.get("aws:SecureTransport")
                if sec_transport in ["true", True, ["true"], [True]] and stmt.get("Principal") == "*":
                    return True

    except Exception:
        pass

    return False


def inspect_single_bucket(s3_global, bucket_info, account_id, account_name, profile_name, org_id, session):
    """
    Deep inspection of a single S3 bucket collecting all metadata, security settings,
    encryption, tags, and lifecycle policies.
    """
    bucket_name = bucket_info["Name"]
    creation_date = bucket_info.get("CreationDate")
    creation_date_str = creation_date.isoformat() if creation_date else "N/A"
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    # 1. Resolve Bucket Region (handles us-east-1 None quirk & EU -> eu-west-1)
    region = "us-east-1"
    try:
        loc_resp = s3_global.get_bucket_location(Bucket=bucket_name)
        constraint = loc_resp.get("LocationConstraint")
        if constraint is None or constraint == "":
            region = "us-east-1"
        elif constraint == "EU":
            region = "eu-west-1"
        else:
            region = constraint
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["AccessDenied", "AllAccessDisabled"]:
            region = "Unknown (AccessDenied)"
    except Exception:
        pass

    # Create regional S3 client to avoid 301 PermanentRedirect errors on sub-resource calls
    try:
        s3_regional = session.client("s3", region_name=region if "Unknown" not in region else "us-east-1", config=S3_CONFIG)
    except Exception:
        s3_regional = s3_global

    # 2. Server-Side Encryption (SSE)
    is_encrypted = False
    encryption_type = "None"
    kms_key_id = "N/A"
    bucket_key_enabled = "N/A"
    raw_sse_config = None

    try:
        enc_resp = s3_regional.get_bucket_encryption(Bucket=bucket_name)
        rules = enc_resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
        if rules:
            is_encrypted = True
            raw_sse_config = rules
            apply_rule = rules[0].get("ApplyServerSideEncryptionByDefault", {})
            encryption_type = apply_rule.get("SSEAlgorithm", "Default")
            kms_key_id = apply_rule.get("KMSMasterKeyId", "Default (aws/s3)" if encryption_type == "aws:kms" else "N/A")
            bucket_key_enabled = rules[0].get("BucketKeyEnabled", False)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "ServerSideEncryptionConfigurationNotFoundError":
            # Note: AWS default encryption applies AES256 for all new buckets since Jan 2023 even if no custom SSE config exists
            is_encrypted = True
            encryption_type = "AES256 (AWS Default Managed)"
        elif code == "AccessDenied":
            encryption_type = "AccessDenied"
        else:
            encryption_type = f"Error: {code}"
    except Exception as ex:
        encryption_type = f"Error: {type(ex).__name__}"

    # 3. Public Access Block (PAB)
    pab_block_acls = False
    pab_ignore_acls = False
    pab_block_policy = False
    pab_restrict_buckets = False
    pab_status = "None Configured"

    try:
        pab_resp = s3_regional.get_public_access_block(Bucket=bucket_name)
        pab_conf = pab_resp.get("PublicAccessBlockConfiguration", {})
        pab_block_acls = pab_conf.get("BlockPublicAcls", False)
        pab_ignore_acls = pab_conf.get("IgnorePublicAcls", False)
        pab_block_policy = pab_conf.get("BlockPublicPolicy", False)
        pab_restrict_buckets = pab_conf.get("RestrictPublicBuckets", False)

        if pab_block_acls and pab_ignore_acls and pab_block_policy and pab_restrict_buckets:
            pab_status = "Fully Blocked (Compliant)"
        elif any([pab_block_acls, pab_ignore_acls, pab_block_policy, pab_restrict_buckets]):
            pab_status = "Partially Blocked"
        else:
            pab_status = "None Configured"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchPublicAccessBlockConfiguration":
            pab_status = "None Configured"
        elif code == "AccessDenied":
            pab_status = "AccessDenied"
        else:
            pab_status = f"Error: {code}"
    except Exception:
        pab_status = "Unknown"

    # 4. Bucket Policy & Policy Status
    has_policy = False
    policy_is_public = "NoPolicy"
    policy_enforces_tls = False
    policy_statements_count = 0
    raw_policy = None

    try:
        pol_stat_resp = s3_regional.get_bucket_policy_status(Bucket=bucket_name)
        policy_is_public = pol_stat_resp.get("PolicyStatus", {}).get("IsPublic", False)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["NoSuchBucketPolicy", "NoSuchPolicy"]:
            policy_is_public = "NoPolicy"
        elif code == "AccessDenied":
            policy_is_public = "AccessDenied"
        else:
            policy_is_public = f"Error: {code}"
    except Exception:
        pass

    try:
        pol_resp = s3_regional.get_bucket_policy(Bucket=bucket_name)
        raw_policy_str = pol_resp.get("Policy", "")
        if raw_policy_str:
            has_policy = True
            raw_policy = json.loads(raw_policy_str)
            stmts = raw_policy.get("Statement", [])
            policy_statements_count = len(stmts) if isinstance(stmts, list) else 1
            policy_enforces_tls = check_tls_enforced_in_policy(raw_policy)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["NoSuchBucketPolicy", "NoSuchPolicy"]:
            has_policy = False
        elif code == "AccessDenied":
            has_policy = "AccessDenied"
    except Exception:
        pass

    # 5. Bucket ACL Analysis
    acl_owner_name = "N/A"
    acl_owner_id = "N/A"
    acl_grants_public = False
    acl_public_details = []

    try:
        acl_resp = s3_regional.get_bucket_acl(Bucket=bucket_name)
        owner = acl_resp.get("Owner", {})
        acl_owner_name = owner.get("DisplayName", "N/A")
        acl_owner_id = owner.get("ID", "N/A")

        for grant in acl_resp.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            perm = grant.get("Permission", "")
            if "AllUsers" in uri:
                acl_grants_public = True
                acl_public_details.append(f"AllUsers:{perm}")
            elif "AuthenticatedUsers" in uri:
                acl_grants_public = True
                acl_public_details.append(f"AuthUsers:{perm}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDenied":
            acl_owner_name = "AccessDenied"
    except Exception:
        pass

    # 6. Object Ownership Controls
    object_ownership = "ACLsEnabled (Default)"
    try:
        own_resp = s3_regional.get_bucket_ownership_controls(Bucket=bucket_name)
        rules = own_resp.get("OwnershipControls", {}).get("Rules", [])
        if rules:
            object_ownership = rules[0].get("ObjectOwnership", "ACLsEnabled")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "OwnershipControlsNotFoundError":
            object_ownership = "ACLsEnabled (Default)"
        elif code == "AccessDenied":
            object_ownership = "AccessDenied"
    except Exception:
        pass

    # 7. Versioning & MFA Delete
    versioning_status = "Disabled"
    mfa_delete = "Disabled"
    try:
        ver_resp = s3_regional.get_bucket_versioning(Bucket=bucket_name)
        versioning_status = ver_resp.get("Status", "Disabled")
        mfa_delete = ver_resp.get("MFADelete", "Disabled")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDenied":
            versioning_status = "AccessDenied"
    except Exception:
        pass

    # 8. Object Lock Configuration
    object_lock_enabled = False
    object_lock_mode = "None"
    object_lock_days = "N/A"
    try:
        lock_resp = s3_regional.get_object_lock_configuration(Bucket=bucket_name)
        lock_conf = lock_resp.get("ObjectLockConfiguration", {})
        object_lock_enabled = (lock_conf.get("ObjectLockEnabled") == "Enabled")
        rule = lock_conf.get("Rule", {}).get("DefaultRetention", {})
        object_lock_mode = rule.get("Mode", "None")
        if "Days" in rule:
            object_lock_days = f"{rule['Days']} days"
        elif "Years" in rule:
            object_lock_days = f"{rule['Years']} years"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["ObjectLockConfigurationNotFoundError", "NoSuchObjectLockConfiguration"]:
            object_lock_enabled = False
        elif code == "AccessDenied":
            object_lock_mode = "AccessDenied"
    except Exception:
        pass

    # 9. Server Access Logging
    logging_enabled = False
    logging_target_bucket = "N/A"
    logging_target_prefix = "N/A"
    try:
        log_resp = s3_regional.get_bucket_logging(Bucket=bucket_name)
        log_conf = log_resp.get("LoggingEnabled")
        if log_conf:
            logging_enabled = True
            logging_target_bucket = log_conf.get("TargetBucket", "N/A")
            logging_target_prefix = log_conf.get("TargetPrefix", "N/A")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "AccessDenied":
            logging_target_bucket = "AccessDenied"
    except Exception:
        pass

    # 10. Lifecycle Configuration
    has_lifecycle = False
    lifecycle_rule_count = 0
    lifecycle_summary = "None"
    try:
        life_resp = s3_regional.get_bucket_lifecycle_configuration(Bucket=bucket_name)
        rules = life_resp.get("Rules", [])
        if rules:
            has_lifecycle = True
            lifecycle_rule_count = len(rules)
            actions = []
            for r in rules[:3]:
                r_id = r.get("ID", "Rule")
                status = r.get("Status", "Enabled")
                if status == "Enabled":
                    actions.append(r_id)
            lifecycle_summary = f"{lifecycle_rule_count} rules ({', '.join(actions[:2])})"
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["NoSuchLifecycleConfiguration", "LifecycleConfigurationNotFoundError"]:
            has_lifecycle = False
        elif code == "AccessDenied":
            lifecycle_summary = "AccessDenied"
    except Exception:
        pass

    # 11. Replication Configuration
    replication_enabled = False
    replication_destinations = "N/A"
    try:
        rep_resp = s3_regional.get_bucket_replication(Bucket=bucket_name)
        rules = rep_resp.get("ReplicationConfiguration", {}).get("Rules", [])
        if rules:
            replication_enabled = True
            dests = [r.get("Destination", {}).get("Bucket", "") for r in rules if r.get("Destination", {}).get("Bucket")]
            replication_destinations = ", ".join(list(set(dests)))
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["ReplicationConfigurationNotFoundError", "NoSuchReplicationConfiguration"]:
            replication_enabled = False
        elif code == "AccessDenied":
            replication_destinations = "AccessDenied"
    except Exception:
        pass

    # 12. Notification Configuration
    has_notifications = False
    notification_targets = []
    try:
        notif_resp = s3_regional.get_bucket_notification_configuration(Bucket=bucket_name)
        if notif_resp.get("TopicConfigurations"):
            notification_targets.append(f"SNS({len(notif_resp['TopicConfigurations'])})")
        if notif_resp.get("QueueConfigurations"):
            notification_targets.append(f"SQS({len(notif_resp['QueueConfigurations'])})")
        if notif_resp.get("LambdaFunctionConfigurations"):
            notification_targets.append(f"Lambda({len(notif_resp['LambdaFunctionConfigurations'])})")
        if notif_resp.get("EventBridgeConfiguration"):
            notification_targets.append("EventBridge")
        if notification_targets:
            has_notifications = True
    except Exception:
        pass

    # 13. Tags
    tags_formatted = ""
    tags_json = {}
    tags_count = 0
    try:
        tag_resp = s3_regional.get_bucket_tagging(Bucket=bucket_name)
        tag_set = tag_resp.get("TagSet", [])
        tags_count = len(tag_set)
        tag_pairs = []
        for t in tag_set:
            k = t.get("Key", "")
            v = t.get("Value", "")
            tag_pairs.append(f"{k}={v}")
            tags_json[k] = v
        tags_formatted = "; ".join(tag_pairs)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["NoSuchTagSet", "NoSuchTagSetError"]:
            tags_formatted = ""
        elif code == "AccessDenied":
            tags_formatted = "AccessDenied"
    except Exception:
        pass

    # 14. Audit Findings & Overall Security Posture Rating
    audit_flags = []
    verdict = "COMPLIANT"

    # Check Public Exposure
    is_public = False
    public_exposure_risk = "SECURE"

    if policy_is_public is True:
        is_public = True
        public_exposure_risk = "PUBLIC_BY_POLICY"
        audit_flags.append("PUBLIC_BUCKET_POLICY")

    if acl_grants_public:
        is_public = True
        public_exposure_risk = "PUBLIC_BY_ACL"
        audit_flags.append(f"PUBLIC_ACL_GRANTS({','.join(acl_public_details)})")

    if pab_status != "Fully Blocked (Compliant)":
        audit_flags.append("PAB_NOT_FULLY_BLOCKED")
        if is_public:
            verdict = "HIGH_RISK"
        elif verdict != "HIGH_RISK":
            verdict = "MEDIUM_RISK"

    if not policy_enforces_tls:
        audit_flags.append("NO_TLS_ENFORCE_POLICY")
        if verdict != "HIGH_RISK":
            verdict = "MEDIUM_RISK"

    if not is_encrypted:
        audit_flags.append("UNENCRYPTED")
        if verdict != "HIGH_RISK":
            verdict = "MEDIUM_RISK"

    if versioning_status != "Enabled":
        audit_flags.append("VERSIONING_DISABLED")
        if verdict == "COMPLIANT":
            verdict = "LOW_RISK"

    if not logging_enabled:
        audit_flags.append("ACCESS_LOGGING_DISABLED")
        if verdict == "COMPLIANT":
            verdict = "LOW_RISK"

    if not has_lifecycle:
        audit_flags.append("NO_LIFECYCLE_RULES")

    if object_ownership != "BucketOwnerEnforced":
        audit_flags.append("ACLS_NOT_DISABLED")

    if is_public:
        verdict = "HIGH_RISK"

    # Assemble comprehensive record
    record = {
        # Organization & Account
        "OrganizationProfile": profile_name,
        "OrganizationId": org_id,
        "AccountId": account_id,
        "AccountName": account_name,

        # Bucket Core
        "BucketName": bucket_name,
        "BucketArn": bucket_arn,
        "Region": region,
        "CreationDate": creation_date_str,

        # Audit Verdict
        "AuditVerdict": verdict,
        "AuditFlags": "; ".join(audit_flags) if audit_flags else "NONE",
        "PublicExposureRisk": public_exposure_risk,
        "IsPublic": is_public,

        # Public Access Block
        "PAB_Status": pab_status,
        "PAB_BlockPublicAcls": pab_block_acls,
        "PAB_IgnorePublicAcls": pab_ignore_acls,
        "PAB_BlockPublicPolicy": pab_block_policy,
        "PAB_RestrictPublicBuckets": pab_restrict_buckets,

        # Transport & Policy
        "HasBucketPolicy": has_policy,
        "Policy_IsPublic": policy_is_public,
        "Policy_EnforcesTLS": policy_enforces_tls,
        "Policy_StatementsCount": policy_statements_count,

        # ACL & Ownership
        "Acl_GrantsPublicAccess": acl_grants_public,
        "Acl_OwnerName": acl_owner_name,
        "Acl_OwnerId": acl_owner_id,
        "ObjectOwnership": object_ownership,

        # Encryption Details
        "IsEncrypted": is_encrypted,
        "EncryptionType": encryption_type,
        "KmsMasterKeyId": kms_key_id,
        "BucketKeyEnabled": bucket_key_enabled,

        # Versioning & Object Lock
        "VersioningStatus": versioning_status,
        "MfaDelete": mfa_delete,
        "ObjectLockEnabled": object_lock_enabled,
        "ObjectLockMode": object_lock_mode,
        "ObjectLockRetentionDays": object_lock_days,

        # Logging & Events
        "LoggingEnabled": logging_enabled,
        "LoggingTargetBucket": logging_target_bucket,
        "LoggingTargetPrefix": logging_target_prefix,
        "HasEventNotifications": has_notifications,
        "NotificationTargets": ", ".join(notification_targets) if notification_targets else "None",

        # Lifecycle & Replication
        "HasLifecycleRules": has_lifecycle,
        "LifecycleRuleCount": lifecycle_rule_count,
        "LifecycleSummary": lifecycle_summary,
        "ReplicationEnabled": replication_enabled,
        "ReplicationDestinations": replication_destinations,

        # Tags
        "Tags_Count": tags_count,
        "Tags_Formatted": tags_formatted,
        "Tags_JSON": json.dumps(tags_json) if tags_json else "{}",

        # Raw Configuration Objects (for JSON export)
        "_raw": {
            "ServerSideEncryptionConfiguration": raw_sse_config,
            "Policy": raw_policy,
            "Tags": tags_json,
        }
    }

    return record


def process_account_buckets(acc, management_account_id, candidate_roles, default_region, session, profile_name, org_id, bucket_workers):
    acc_id = acc["Id"]
    acc_name = acc.get("Name", "Unknown")
    is_management = (acc_id == management_account_id)

    safe_print(f"  [>] Scanning Account: {acc_name} ({acc_id}){' [Management Root]' if is_management else ''}...")

    # Determine credentials / session for this account
    account_session = None
    role_used = None

    if is_management:
        account_session = session
        role_used = "DirectProfileCredentials"
    else:
        sts = session.client("sts", region_name=default_region)
        for role_name in candidate_roles:
            role_arn = f"arn:aws:iam::{acc_id}:role/{role_name}"
            try:
                assumed = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="S3MultiOrgAuditSession",
                    DurationSeconds=3600,
                )
                creds = assumed["Credentials"]
                account_session = boto3.Session(
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                )
                role_used = role_name
                break
            except ClientError:
                continue

    if not account_session:
        safe_print(f"    [-] Could not assume role into {acc_id} ({acc_name}). Candidate roles failed. Skipping.")
        return []

    # Initialize S3 client in target account
    try:
        s3_global = account_session.client("s3", region_name=default_region, config=S3_CONFIG)
        resp = s3_global.list_buckets()
        buckets = resp.get("Buckets", [])
    except ClientError as e:
        safe_print(f"    [-] s3:ListBuckets failed in {acc_id} ({acc_name}): {e.response['Error']['Code']}")
        return []
    except Exception as ex:
        safe_print(f"    [-] s3:ListBuckets failed in {acc_id} ({acc_name}): {ex}")
        return []

    if not buckets:
        safe_print(f"    [i] Account {acc_id} ({acc_name}): 0 buckets found.")
        return []

    safe_print(f"    [+] Found {len(buckets)} bucket(s) in {acc_id} ({acc_name}) [Role: {role_used}]. Inspecting...")

    # Concurrently inspect buckets within this account
    account_records = []
    with ThreadPoolExecutor(max_workers=bucket_workers) as bucket_executor:
        futures = {
            bucket_executor.submit(
                inspect_single_bucket,
                s3_global,
                b,
                acc_id,
                acc_name,
                profile_name,
                org_id,
                account_session,
            ): b["Name"] for b in buckets
        }

        for future in as_completed(futures):
            b_name = futures[future]
            try:
                rec = future.result()
                account_records.append(rec)
            except Exception as e:
                safe_print(f"    [-] Error inspecting bucket {b_name}: {e}")

    safe_print(f"    [v] Completed inspection of {len(account_records)} bucket(s) in {acc_id}.")
    return account_records


def scan_single_organization(profile_or_session, args, candidate_roles, is_current_session=False):
    profile_name = "current" if is_current_session else profile_or_session
    safe_print("\n" + "=" * 80)
    if is_current_session:
        safe_print("Connecting to CURRENT Active AWS Session in PowerShell...")
        session = boto3.Session()
    else:
        resolved_profile = resolve_profile_name(profile_name)
        safe_print(f"Connecting to AWS Profile: '{profile_name}'" + (f" (alias: {resolved_profile})" if resolved_profile != profile_name else "") + "...")
        try:
            session = boto3.Session(profile_name=resolved_profile)
        except ProfileNotFound:
            safe_print(f"[-] Profile '{profile_name}' not found in ~/.aws/config or ~/.aws/credentials. Skipping.")
            return []
        except Exception as e:
            safe_print(f"[-] Failed to initialize session for profile '{profile_name}': {e}. Skipping.")
            return []

    # Verify caller identity
    default_region = session.region_name or "us-east-1"
    try:
        sts = session.client("sts", region_name=default_region)
        identity = sts.get_caller_identity()
        mgmt_id = identity["Account"]
        caller_arn = identity["Arn"]
        safe_print(f"  [+] Authenticated as: {caller_arn} (Account: {mgmt_id})")
    except (ClientError, NoCredentialsError) as e:
        safe_print(f"  [-] Authentication error for profile '{profile_name}': {e}")
        safe_print(f"      Hint: Run 'aws login --profile {profile_name}' or 'aws sso login --profile {profile_name}'")
        return []
    except Exception as ex:
        safe_print(f"  [-] Unexpected error validating identity for profile '{profile_name}': {ex}")
        return []

    # Discover AWS Organization
    org_id = "Standalone"
    accounts = []
    try:
        org = session.client("organizations", region_name=default_region)
        org_desc = org.describe_organization()
        org_id = org_desc.get("Organization", {}).get("Id", "Unknown")
        org_master = org_desc.get("Organization", {}).get("MasterAccountId", mgmt_id)
        safe_print(f"  [+] AWS Organization ID: {org_id} (Master Account: {org_master})")

        paginator = org.get_paginator("list_accounts")
        for page in paginator.paginate():
            for acc in page.get("Accounts", []):
                if acc.get("Status") == "ACTIVE":
                    accounts.append(acc)

        safe_print(f"  [+] Discovered {len(accounts)} ACTIVE account(s) in Organization.")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ["AWSOrganizationsNotInUseException", "AccessDeniedException"]:
            safe_print(f"  [i] organizations:DescribeOrganization ({code}). Scanning account {mgmt_id} directly as standalone account.")
            accounts = [{"Id": mgmt_id, "Name": profile_name}]
        else:
            safe_print(f"  [-] Organizations error ({code}). Scanning management account {mgmt_id} only.")
            accounts = [{"Id": mgmt_id, "Name": profile_name}]
    except Exception as ex:
        safe_print(f"  [-] Could not query Organizations: {ex}. Scanning management account {mgmt_id} only.")
        accounts = [{"Id": mgmt_id, "Name": profile_name}]

    # Concurrently scan all discovered accounts
    safe_print(f"  [*] Scanning {len(accounts)} account(s) using {args.workers} worker threads...")
    org_buckets = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                process_account_buckets,
                acc,
                mgmt_id,
                candidate_roles,
                default_region,
                session,
                profile_name,
                org_id,
                args.bucket_workers,
            ): acc["Id"] for acc in accounts
        }

        for future in as_completed(futures):
            acc_id = futures[future]
            try:
                records = future.result()
                org_buckets.extend(records)
            except Exception as e:
                safe_print(f"  [-] Account {acc_id} thread error: {e}")

    safe_print(f"  [=] Finished Profile '{profile_name}': {len(org_buckets)} total S3 bucket(s) audited.")
    return org_buckets


def main():
    args = parse_args()
    start_time = datetime.now()

    print("=" * 85)
    print("  AWS Multi-Organization S3 Bucket Audit & Inventory Tool")
    print(f"  Run Time:         {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if args.current_session:
        print("  Mode:             CURRENT Active Session (PowerShell)")
    else:
        print(f"  Target Profiles:  {', '.join(args.profiles)}")
    print(f"  Output CSV:       {args.output_csv}")
    print(f"  Output JSON:      {args.output_json}")
    print(f"  Workers:          {args.workers} accounts concurrent, {args.bucket_workers} buckets concurrent")
    print("=" * 85)

    candidate_roles = get_candidate_roles(args.role)
    all_buckets = []
    profile_stats = {}

    if args.current_session or (len(args.profiles) == 1 and args.profiles[0].lower() == "current"):
        buckets = scan_single_organization("current", args, candidate_roles, is_current_session=True)
        all_buckets.extend(buckets)
        profile_stats["current"] = len(buckets)
    else:
        for profile in args.profiles:
            if profile.lower() == "current":
                buckets = scan_single_organization("current", args, candidate_roles, is_current_session=True)
            else:
                buckets = scan_single_organization(profile, args, candidate_roles, is_current_session=False)
            all_buckets.extend(buckets)
            profile_stats[profile] = len(buckets)

    # Clean raw internal fields for CSV export
    csv_fieldnames = [
        "OrganizationProfile", "OrganizationId", "AccountId", "AccountName",
        "BucketName", "BucketArn", "Region", "CreationDate",
        "AuditVerdict", "AuditFlags", "PublicExposureRisk", "IsPublic",
        "PAB_Status", "PAB_BlockPublicAcls", "PAB_IgnorePublicAcls", "PAB_BlockPublicPolicy", "PAB_RestrictPublicBuckets",
        "HasBucketPolicy", "Policy_IsPublic", "Policy_EnforcesTLS", "Policy_StatementsCount",
        "Acl_GrantsPublicAccess", "Acl_OwnerName", "Acl_OwnerId", "ObjectOwnership",
        "IsEncrypted", "EncryptionType", "KmsMasterKeyId", "BucketKeyEnabled",
        "VersioningStatus", "MfaDelete", "ObjectLockEnabled", "ObjectLockMode", "ObjectLockRetentionDays",
        "LoggingEnabled", "LoggingTargetBucket", "LoggingTargetPrefix",
        "HasLifecycleRules", "LifecycleRuleCount", "LifecycleSummary",
        "ReplicationEnabled", "ReplicationDestinations",
        "HasEventNotifications", "NotificationTargets",
        "Tags_Count", "Tags_Formatted", "Tags_JSON",
    ]

    # Write Consolidated CSV
    safe_print(f"\nWriting consolidated CSV report: {args.output_csv}...")
    with open(args.output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=csv_fieldnames, extrasaction="ignore")
        writer.writeheader()
        for b in all_buckets:
            writer.writerow(b)

    # Write Consolidated JSON
    safe_print(f"Writing complete JSON report: {args.output_json}...")
    # Calculate posture statistics
    total_b = len(all_buckets)
    encrypted_count = sum(1 for b in all_buckets if b.get("IsEncrypted") is True)
    pab_full_count = sum(1 for b in all_buckets if b.get("PAB_Status") == "Fully Blocked (Compliant)")
    tls_enforced_count = sum(1 for b in all_buckets if b.get("Policy_EnforcesTLS") is True)
    versioning_count = sum(1 for b in all_buckets if b.get("VersioningStatus") == "Enabled")
    logging_count = sum(1 for b in all_buckets if b.get("LoggingEnabled") is True)
    public_count = sum(1 for b in all_buckets if b.get("IsPublic") is True)
    high_risk_count = sum(1 for b in all_buckets if b.get("AuditVerdict") == "HIGH_RISK")
    med_risk_count = sum(1 for b in all_buckets if b.get("AuditVerdict") == "MEDIUM_RISK")
    low_risk_count = sum(1 for b in all_buckets if b.get("AuditVerdict") == "LOW_RISK")
    compliant_count = sum(1 for b in all_buckets if b.get("AuditVerdict") == "COMPLIANT")

    with open(args.output_json, "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "profiles_scanned": args.profiles if not args.current_session else ["current"],
            "total_buckets": total_b,
            "stats_per_profile": profile_stats,
            "security_posture_summary": {
                "total_buckets": total_b,
                "compliant_buckets": compliant_count,
                "low_risk_buckets": low_risk_count,
                "medium_risk_buckets": med_risk_count,
                "high_risk_buckets": high_risk_count,
                "public_buckets_detected": public_count,
                "encrypted_percentage": f"{(encrypted_count / total_b * 100):.1f}%" if total_b else "0%",
                "pab_fully_blocked_percentage": f"{(pab_full_count / total_b * 100):.1f}%" if total_b else "0%",
                "tls_enforced_percentage": f"{(tls_enforced_count / total_b * 100):.1f}%" if total_b else "0%",
                "versioning_enabled_percentage": f"{(versioning_count / total_b * 100):.1f}%" if total_b else "0%",
                "access_logging_percentage": f"{(logging_count / total_b * 100):.1f}%" if total_b else "0%",
            },
            "buckets": all_buckets,
        }, f, indent=2)

    elapsed = (datetime.now() - start_time).total_seconds()

    # Executive Console Summary Table
    print("\n" + "=" * 85)
    print("  AWS MULTI-ORGANIZATION S3 AUDIT COMPLETE")
    print("=" * 85)
    print(f"  Elapsed Execution Time:   {elapsed:.1f} seconds")
    print(f"  Total S3 Buckets Scanned: {total_b}")
    print("\n  Buckets Per Organization:")
    for prof, cnt in profile_stats.items():
        print(f"    - {prof:<12} : {cnt:>4} bucket(s)")

    if total_b > 0:
        print("\n  Security & Compliance Posture Summary:")
        print(f"    {'Compliant (Zero Deviations)':<36} : {compliant_count:>4} ({(compliant_count/total_b*100):.1f}%)")
        print(f"    {'Low Risk (Missing Logging/Versioning)':<36} : {low_risk_count:>4} ({(low_risk_count/total_b*100):.1f}%)")
        print(f"    {'Medium Risk (Missing PAB or TLS)':<36} : {med_risk_count:>4} ({(med_risk_count/total_b*100):.1f}%)")
        print(f"    {'High Risk (Public Exposure Detected)':<36} : {high_risk_count:>4} ({(high_risk_count/total_b*100):.1f}%)")
        print("-" * 85)
        print(f"    {'Server-Side Encrypted':<36} : {encrypted_count:>4} ({(encrypted_count/total_b*100):.1f}%)")
        print(f"    {'Public Access Block (Fully Enabled)':<36} : {pab_full_count:>4} ({(pab_full_count/total_b*100):.1f}%)")
        print(f"    {'TLS / HTTPS Enforced by Policy':<36} : {tls_enforced_count:>4} ({(tls_enforced_count/total_b*100):.1f}%)")
        print(f"    {'Versioning Enabled':<36} : {versioning_count:>4} ({(versioning_count/total_b*100):.1f}%)")
        print(f"    {'Server Access Logging Active':<36} : {logging_count:>4} ({(logging_count/total_b*100):.1f}%)")
        print(f"    {'Public Buckets Detected':<36} : {public_count:>4}")

    print("=" * 85)
    print(f"  CSV Report Saved:   {os.path.abspath(args.output_csv)}")
    print(f"  JSON Report Saved:  {os.path.abspath(args.output_json)}")
    print("=" * 85 + "\n")


if __name__ == "__main__":
    main()
