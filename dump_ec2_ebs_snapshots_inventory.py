#!/usr/bin/env python3
"""
AWS Multi-Organization EC2, EBS Volumes & Snapshots Lineage Auditor
================================================================================
Comprehensive discovery and audit across AWS Organizations (e.g. rus-ext, rus-ioc, cccs)
or the active AWS session in PowerShell.

SNAPSHOT IS CENTRAL TO THIS REPORT:
Maps every EBS Snapshot to its source EBS Volume and originating EC2 Instance,
identifying active lineages as well as orphaned volumes and snapshots where the
underlying EC2 instances or EBS volumes no longer exist.

Key Capabilities:
  1. Snapshot-Centric Lineage Mapping:
     - Snapshot -> Source EBS Volume (Exists / In-Use / Available / Deleted)
     - Source Volume -> EC2 Instance (Exists / Running / Stopped / Terminated / Missing)
     - Inferred Instance IDs from snapshot descriptions and tags when volumes are deleted.
  2. Orphan & Waste Quantification:
     - Unattached EBS Volumes (status: available) paying idle storage fees.
     - Orphaned Snapshots whose source volumes have been deleted.
     - Dangling Snapshots whose original EC2 instances have been terminated.
     - Complete Orphans (both volume and instance no longer exist).
     - Financial waste quantified per month ($0.05/GB-mo snapshots, $0.08-$0.10/GB-mo EBS).
  3. EC2 Storage Hierarchy:
     - Instance -> Attached Volumes -> Associated Snapshots.
     - Data protection audit: Identifies instances running with ZERO snapshot backups.
  4. Multi-Organization Traversal:
     - Supports rus-ext, rus-ioc, cccs with SSO credential bridge & cross-account roles.
     - Connects directly to the Management / Root account of each organization.
     - Scans all enabled regions in parallel per account.
  5. Outputs:
     - CSV 1: snapshots_all_organizations_inventory.csv (Snapshot-centric central report)
     - CSV 2: orphaned_ebs_and_snapshots_waste.csv (Focus on unattached & orphaned waste)
     - CSV 3: ec2_instances_storage_inventory.csv (EC2 storage hierarchy & backup posture)
     - JSON:  ec2_ebs_snapshots_all_organizations.json (Hierarchical master data)
     - HTML:  ec2_ebs_snapshots_inventory_portal.html (Interactive offline dashboard)

Usage:
  # 1. Audit all 3 organizations (rus-ext, rus-ioc, cccs):
  python dump_ec2_ebs_snapshots_inventory.py

  # 2. Audit currently authenticated AWS session in PowerShell:
  python dump_ec2_ebs_snapshots_inventory.py --current-session

  # 3. Target specific profiles:
  python dump_ec2_ebs_snapshots_inventory.py --profiles rus-ext cccs

  # 4. Run offline from an existing JSON dump:
  python dump_ec2_ebs_snapshots_inventory.py --input-json ec2_ebs_snapshots_all_organizations.json
================================================================================
"""

import os
import sys
import re
import csv
import json
import shutil
import argparse
import subprocess
from datetime import datetime, timezone
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import boto3
from botocore.exceptions import ClientError, ProfileNotFound, NoCredentialsError

# Default AWS Organizations profiles and alias mapping
DEFAULT_PROFILES = ["rus-ext", "rus-ioc", "cccs"]
PROFILE_ALIASES = {
    "rus-iot": "rus-ioc",
    "rci-cccs": "cccs",
    "rus-ext-sso": "rus-ext",
    "rus-ioc-sso": "rus-ioc",
    "cccs-sso": "cccs",
}

DEFAULT_ROLES = [
    "AWSControlTowerExecution",       # Standard AWS Control Tower role
    "OrganizationAccountAccessRole",  # Standard AWS Organizations role
    "AdministratorAccess",
]

# Baseline AWS Pricing (USD / GB-Month)
PRICE_SNAPSHOT_GB_MONTH = 0.05
PRICE_EBS_RATES = {
    "gp3": 0.08,
    "gp2": 0.10,
    "io1": 0.125,
    "io2": 0.125,
    "st1": 0.045,
    "sc1": 0.015,
    "standard": 0.05,
}

def safe_print(*a, **k):
    try:
        print(*a, **k)
    except UnicodeEncodeError:
        text = " ".join(str(arg) for arg in a)
        clean = text.encode("ascii", errors="backslashreplace").decode("ascii")
        print(clean, **k)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Audit EC2, EBS Volumes & Snapshots Lineage across AWS Organizations."
    )
    parser.add_argument(
        "--profiles", "-p",
        nargs="+",
        default=DEFAULT_PROFILES,
        help="One or more AWS CLI profiles to audit (default: rus-ext rus-ioc cccs). Use 'current' for active session."
    )
    parser.add_argument(
        "--current-session", "-c",
        action="store_true",
        default=False,
        help="Audit the currently authenticated AWS session in PowerShell directly."
    )
    parser.add_argument(
        "--role", "-r",
        default=os.environ.get("ROLE_NAME"),
        help="Custom IAM role name to assume in member accounts."
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=None,
        help="Specific AWS regions to scan (default: all enabled regions per account)."
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=6,
        help="Number of concurrent worker threads for account scanning (default: 6)."
    )
    parser.add_argument(
        "--region-workers", "-rw",
        type=int,
        default=4,
        help="Number of concurrent threads per account for region scanning (default: 4)."
    )
    parser.add_argument(
        "--output-snapshots-csv", "-os",
        default="snapshots_all_organizations_inventory.csv",
        help="Output path for Snapshot-Centric CSV report."
    )
    parser.add_argument(
        "--output-orphans-csv", "-oo",
        default="orphaned_ebs_and_snapshots_waste.csv",
        help="Output path for Orphaned EBS & Snapshots Waste CSV."
    )
    parser.add_argument(
        "--output-ec2-csv", "-oe",
        default="ec2_instances_storage_inventory.csv",
        help="Output path for EC2 Storage Hierarchy CSV."
    )
    parser.add_argument(
        "--output-volumes-csv", "-ov",
        default="ebs_volumes_all_organizations_inventory.csv",
        help="Output path for EBS Volumes Inventory CSV."
    )
    parser.add_argument(
        "--output-ec2-fleet-csv", "-of",
        default="ec2_all_organizations_inventory.csv",
        help="Output path for EC2 Fleet Inventory CSV."
    )
    parser.add_argument(
        "--output-json", "-j",
        default="ec2_ebs_snapshots_all_organizations.json",
        help="Output path for complete hierarchical JSON."
    )
    parser.add_argument(
        "--output-html", "-html",
        default="ec2_ebs_snapshots_inventory_portal.html",
        help="Output path for interactive offline HTML portal."
    )
    parser.add_argument(
        "--input-json",
        default=None,
        help="Generate reports offline from a previously exported JSON dump."
    )
    parser.add_argument(
        "--stale-snapshot-days",
        type=int,
        default=180,
        help="Age threshold in days to flag snapshots as stale (default: 180)."
    )
    return parser.parse_args()

def resolve_profile_name(profile):
    return PROFILE_ALIASES.get(profile, profile)

def get_candidate_roles(custom_role):
    roles = []
    if custom_role:
        roles.append(custom_role)
    for r in DEFAULT_ROLES:
        if r not in roles:
            roles.append(r)
    return roles

def format_tags(tag_list):
    if not tag_list or not isinstance(tag_list, list):
        return "", {}, 0
    formatted_pairs = []
    tag_dict = {}
    for t in tag_list:
        k = t.get("Key", "")
        v = t.get("Value", "")
        formatted_pairs.append(f"{k}={v}")
        tag_dict[k] = v
    return "; ".join(formatted_pairs), tag_dict, len(tag_list)

def get_name_tag(tag_list):
    if not tag_list or not isinstance(tag_list, list):
        return "N/A"
    for t in tag_list:
        if t.get("Key", "").lower() == "name":
            return t.get("Value", "") or "N/A"
    return "N/A"

def extract_instance_id_from_text(text):
    if not text:
        return None
    match = re.search(r"\b(i-[0-9a-f]{8,17})\b", text, re.IGNORECASE)
    return match.group(1).lower() if match else None

def get_session_for_profile(profile_name, is_current_session=False):
    """
    Robust 4-tier authentication cascade:
    1. Direct boto3 Session
    2. AWS CLI v2 process export-credentials
    3. SSO profile alias
    4. Active session fallback
    """
    if is_current_session or profile_name in ["current", "default", None]:
        try:
            sess = boto3.Session()
            sts = sess.client("sts")
            sts.get_caller_identity()
            return sess, "active_environment_session"
        except Exception:
            pass

        for env_profile in ["AWS_PROFILE", "AWS_DEFAULT_PROFILE"]:
            p = os.environ.get(env_profile)
            if p:
                try:
                    sess = boto3.Session(profile_name=p)
                    sts = sess.client("sts")
                    sts.get_caller_identity()
                    return sess, f"env_profile:{p}"
                except Exception:
                    pass
        return None, "no_active_current_credentials"

    resolved = resolve_profile_name(profile_name)

    # Tier 1: Native boto3
    try:
        sess = boto3.Session(profile_name=resolved)
        sts = sess.client("sts")
        sts.get_caller_identity()
        return sess, f"native_profile:{resolved}"
    except Exception:
        pass

    # Tier 2: AWS CLI v2 Credential Bridge (process format returns JSON)
    for p in [resolved, f"{resolved}-sso"]:
        try:
            cmd = ["aws", "configure", "export-credentials", "--profile", p, "--format", "process"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if proc.returncode == 0 and proc.stdout.strip():
                creds = json.loads(proc.stdout)
                reg = "ca-central-1" if "cccs" in p else "us-east-1"
                sess = boto3.Session(
                    aws_access_key_id=creds.get("AccessKeyId"),
                    aws_secret_access_key=creds.get("SecretAccessKey"),
                    aws_session_token=creds.get("SessionToken"),
                    region_name=reg,
                )
                return sess, f"aws_cli_bridge:{p}"
        except Exception:
            pass

    return None, f"failed_all_methods:{resolved}"

def scan_account_region(account_session, region, account_info, profile_name, org_id, stale_days=180):
    """
    Scans a single AWS Region within a specific Account for:
      - EC2 Instances & their BlockDeviceMappings
      - EBS Volumes & their attachment states
      - EBS Snapshots (OwnerIds=['self'])
    Maps relationships and determines orphan / waste classification.
    """
    acc_id = account_info["Id"]
    acc_name = account_info.get("Name", "Unknown")
    ec2 = account_session.client("ec2", region_name=region)
    now = datetime.now(timezone.utc)

    # 1. Collect EC2 Instances
    instances_map = {}
    volume_to_instance = {}
    try:
        inst_paginator = ec2.get_paginator("describe_instances")
        for page in inst_paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    inst_id = inst.get("InstanceId")
                    inst_name = get_name_tag(inst.get("Tags", []))
                    state = inst.get("State", {}).get("Name", "unknown")
                    inst_type = inst.get("InstanceType", "unknown")
                    vpc_id = inst.get("VpcId", "N/A")
                    subnet_id = inst.get("SubnetId", "N/A")
                    priv_ip = inst.get("PrivateIpAddress", "N/A")
                    pub_ip = inst.get("PublicIpAddress", "N/A")
                    launch_time = inst.get("LaunchTime")
                    launch_str = launch_time.isoformat() if launch_time else "N/A"
                    tags_fmt, tags_dict, tags_count = format_tags(inst.get("Tags", []))

                    attached_vols = []
                    for bdm in inst.get("BlockDeviceMappings", []):
                        ebs = bdm.get("Ebs", {})
                        vol_id = ebs.get("VolumeId")
                        dev_name = bdm.get("DeviceName", "N/A")
                        del_on_term = ebs.get("DeleteOnTermination", False)
                        attach_status = ebs.get("Status", "attached")
                        if vol_id:
                            attached_vols.append({
                                "VolumeId": vol_id,
                                "Device": dev_name,
                                "DeleteOnTermination": del_on_term,
                                "Status": attach_status,
                            })
                            volume_to_instance[vol_id] = {
                                "InstanceId": inst_id,
                                "InstanceName": inst_name,
                                "InstanceState": state,
                                "InstanceType": inst_type,
                                "Device": dev_name,
                                "DeleteOnTermination": del_on_term,
                                "Tags_Formatted": tags_fmt,
                                "Tags_JSON": tags_dict,
                            }

                    instances_map[inst_id] = {
                        "OrganizationProfile": profile_name,
                        "OrganizationId": org_id,
                        "AccountId": acc_id,
                        "AccountName": acc_name,
                        "Region": region,
                        "InstanceId": inst_id,
                        "InstanceName": inst_name,
                        "InstanceState": state,
                        "InstanceType": inst_type,
                        "VpcId": vpc_id,
                        "SubnetId": subnet_id,
                        "PrivateIpAddress": priv_ip,
                        "PublicIpAddress": pub_ip,
                        "LaunchTime": launch_str,
                        "AttachedVolumesCount": len(attached_vols),
                        "AttachedVolumes": attached_vols,
                        "TotalAttachedStorageGB": 0,
                        "AttachedVolumeIds": "; ".join(v["VolumeId"] for v in attached_vols),
                        "AssociatedSnapshotsCount": 0,
                        "TotalSnapshotsStorageGB": 0,
                        "AssociatedSnapshotIds": "",
                        "BackupProtectionStatus": "NO_SNAPSHOTS_UNPROTECTED",
                        "Tags_Count": tags_count,
                        "Tags_Formatted": tags_fmt,
                        "Tags_JSON": tags_dict,
                    }
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ["UnauthorizedOperation", "AccessDenied", "AuthFailure"]:
            safe_print(f"    [!] Error describing instances in {acc_id} {region}: {code}")

    # 2. Collect EBS Volumes
    volumes_map = {}
    unattached_volumes = []
    try:
        vol_paginator = ec2.get_paginator("describe_volumes")
        for page in vol_paginator.paginate():
            for vol in page.get("Volumes", []):
                vol_id = vol.get("VolumeId")
                vol_name = get_name_tag(vol.get("Tags", []))
                vol_size = int(vol.get("Size", 0))
                vol_type = vol.get("VolumeType", "gp3")
                vol_state = vol.get("State", "unknown") # in-use, available, etc.
                az = vol.get("AvailabilityZone", "N/A")
                enc = vol.get("Encrypted", False)
                kms_key = vol.get("KmsKeyId", "N/A")
                iops = vol.get("Iops", 0)
                throughput = vol.get("Throughput", 0)
                created_dt = vol.get("CreateTime")
                created_str = created_dt.isoformat() if created_dt else "N/A"
                age_days = (now - created_dt).days if created_dt else 0
                tags_fmt, tags_dict, tags_count = format_tags(vol.get("Tags", []))

                rate = PRICE_EBS_RATES.get(vol_type, 0.08)
                monthly_cost = round(vol_size * rate, 2)

                attachments = vol.get("Attachments", [])
                is_attached = len(attachments) > 0 and vol_state == "in-use"
                attached_inst_id = "None"
                attached_inst_name = "None"
                attached_inst_state = "N/A"
                dev_name = "N/A"
                del_on_term = False

                if is_attached:
                    att = attachments[0]
                    attached_inst_id = att.get("InstanceId", "None")
                    dev_name = att.get("Device", "N/A")
                    del_on_term = att.get("DeleteOnTermination", False)
                    if attached_inst_id in instances_map:
                        attached_inst_name = instances_map[attached_inst_id]["InstanceName"]
                        attached_inst_state = instances_map[attached_inst_id]["InstanceState"]
                        instances_map[attached_inst_id]["TotalAttachedStorageGB"] += vol_size
                    else:
                        attached_inst_state = "INSTANCE_TERMINATED/MISSING"

                vol_record = {
                    "OrganizationProfile": profile_name,
                    "OrganizationId": org_id,
                    "AccountId": acc_id,
                    "AccountName": acc_name,
                    "Region": region,
                    "VolumeId": vol_id,
                    "VolumeName": vol_name,
                    "SizeGB": vol_size,
                    "VolumeType": vol_type,
                    "State": vol_state,
                    "AvailabilityZone": az,
                    "CreateTime": created_str,
                    "AgeDays": age_days,
                    "Encrypted": enc,
                    "KmsKeyId": kms_key,
                    "Iops": iops,
                    "Throughput": throughput,
                    "IsAttached": is_attached,
                    "AttachedInstanceId": attached_inst_id,
                    "AttachedInstanceName": attached_inst_name,
                    "AttachedInstanceState": attached_inst_state,
                    "AttachmentDevice": dev_name,
                    "DeleteOnTermination": del_on_term,
                    "EstimatedMonthlyCostUSD": monthly_cost,
                    "EstimatedAnnualCostUSD": round(monthly_cost * 12, 2),
                    "Tags_Count": tags_count,
                    "Tags_Formatted": tags_fmt,
                    "Tags_JSON": tags_dict,
                }
                volumes_map[vol_id] = vol_record

                if not is_attached:
                    unattached_volumes.append(vol_record)

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ["UnauthorizedOperation", "AccessDenied", "AuthFailure"]:
            safe_print(f"    [!] Error describing volumes in {acc_id} {region}: {code}")

    # 3. Collect EBS Snapshots (OwnerIds=['self'] is MANDATORY)
    snapshots_list = []
    volume_to_snapshots = defaultdict(list)
    try:
        snap_paginator = ec2.get_paginator("describe_snapshots")
        for page in snap_paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                snap_id = snap.get("SnapshotId")
                snap_name = get_name_tag(snap.get("Tags", []))
                source_vol_id = snap.get("VolumeId", "N/A")
                snap_size = int(snap.get("VolumeSize", 0))
                snap_state = snap.get("State", "unknown")
                desc = snap.get("Description", "") or ""
                start_dt = snap.get("StartTime")
                start_str = start_dt.isoformat() if start_dt else "N/A"
                age_days = (now - start_dt).days if start_dt else 0
                enc = snap.get("Encrypted", False)
                kms_key = snap.get("KmsKeyId", "N/A")
                tier = snap.get("StorageTier", "standard")
                tags_fmt, tags_dict, tags_count = format_tags(snap.get("Tags", []))

                snap_cost = round(snap_size * PRICE_SNAPSHOT_GB_MONTH, 2)

                # Link to EBS Volume
                vol_exists = (source_vol_id in volumes_map)
                vol_name = "N/A"
                vol_state = "VOLUME_DELETED"
                vol_type = "N/A"
                vol_size = snap_size
                vol_created = "N/A"
                vol_enc = False
                vol_del_on_term = False
                vol_tags_fmt = ""

                # Link to EC2 Instance
                inst_id = "N/A"
                inst_name = "N/A"
                inst_state = "INSTANCE_NOT_FOUND"
                inst_type = "N/A"
                inst_priv_ip = "N/A"
                inst_launch = "N/A"
                inst_tags_fmt = ""
                inst_exists = False

                if vol_exists:
                    v = volumes_map[source_vol_id]
                    vol_name = v["VolumeName"]
                    vol_state = v["State"]
                    vol_type = v["VolumeType"]
                    vol_size = v["SizeGB"]
                    vol_created = v["CreateTime"]
                    vol_enc = v["Encrypted"]
                    vol_del_on_term = v["DeleteOnTermination"]
                    vol_tags_fmt = v["Tags_Formatted"]

                    if v["IsAttached"] and v["AttachedInstanceId"] != "None":
                        inst_id = v["AttachedInstanceId"]
                        if inst_id in instances_map:
                            i = instances_map[inst_id]
                            inst_exists = True
                            inst_name = i["InstanceName"]
                            inst_state = i["InstanceState"]
                            inst_type = i["InstanceType"]
                            inst_priv_ip = i["PrivateIpAddress"]
                            inst_launch = i["LaunchTime"]
                            inst_tags_fmt = i["Tags_Formatted"]
                        else:
                            inst_state = "INSTANCE_TERMINATED/MISSING"
                    else:
                        inst_id = "None (Volume Unattached)"
                        inst_state = "N/A (Unattached Volume)"
                else:
                    # Volume is deleted. Try to infer instance from snapshot description or tags!
                    inferred_inst = extract_instance_id_from_text(desc) or extract_instance_id_from_text(snap_name)
                    if not inferred_inst:
                        for k, val in tags_dict.items():
                            inferred = extract_instance_id_from_text(val)
                            if inferred:
                                inferred_inst = inferred
                                break
                    if inferred_inst:
                        inst_id = f"{inferred_inst} (Inferred)"
                        if inferred_inst in instances_map:
                            i = instances_map[inferred_inst]
                            inst_exists = True
                            inst_name = i["InstanceName"]
                            inst_state = i["InstanceState"]
                            inst_type = i["InstanceType"]
                            inst_priv_ip = i["PrivateIpAddress"]
                            inst_launch = i["LaunchTime"]
                            inst_tags_fmt = i["Tags_Formatted"]
                        else:
                            inst_state = "INSTANCE_TERMINATED"
                    else:
                        inst_id = "Unknown (Volume Deleted)"
                        inst_state = "INSTANCE_NOT_FOUND"

                # Determine Association Status and Orphan Status
                is_orphan = False
                if vol_exists and inst_exists:
                    if inst_state == "running":
                        assoc_status = "ATTACHED_RUNNING"
                        finops_finding = "Active Workload Backup (Retain)"
                        rec_action = "Retain - Active Production Volume Backup"
                    else:
                        assoc_status = "ATTACHED_STOPPED"
                        finops_finding = f"Attached to Stopped EC2 ({inst_state})"
                        rec_action = "Review - EC2 Instance is Stopped"
                elif vol_exists and not inst_exists:
                    if vol_state == "available":
                        assoc_status = "UNATTACHED_VOLUME"
                        is_orphan = True
                        finops_finding = "Source Volume is Unattached (Idle Waste)"
                        rec_action = "Review - Volume Unattached, Stale Backup Candidate"
                    else:
                        assoc_status = "ATTACHED_TO_TERMINATED_INSTANCE"
                        is_orphan = True
                        finops_finding = "Volume Attached to Terminated Instance"
                        rec_action = "Investigate - Clean up dangling attachment or snapshot"
                elif not vol_exists:
                    is_orphan = True
                    if inst_exists:
                        assoc_status = "ORPHAN_VOLUME_DELETED_ACTIVE_INSTANCE"
                        finops_finding = "Source Volume Deleted (Historic AMI/Backup)"
                        rec_action = "Review - Historic Snapshot for Active Instance"
                    elif "INSTANCE_TERMINATED" in inst_state:
                        assoc_status = "ORPHAN_VOLUME_DELETED_INSTANCE_TERMINATED"
                        if age_days > stale_days:
                            finops_finding = f"Stale Snapshot of Terminated Instance ({age_days}d old)"
                            rec_action = f"Delete Candidate - Save ${snap_cost}/mo"
                        else:
                            finops_finding = "Recent Snapshot of Terminated Instance"
                            rec_action = "Review retention policy"
                    else:
                        assoc_status = "COMPLETE_ORPHAN"
                        if age_days > stale_days:
                            finops_finding = f"Complete Orphan Stale Snapshot ({age_days}d old, No Vol/EC2)"
                            rec_action = f"Delete Candidate - Save ${snap_cost}/mo"
                        else:
                            finops_finding = "Complete Orphan (Source Volume Deleted)"
                            rec_action = "Evaluate for deletion or archive tier"

                snap_record = {
                    "OrganizationProfile": profile_name,
                    "OrganizationId": org_id,
                    "AccountId": acc_id,
                    "AccountName": acc_name,
                    "Region": region,
                    "SnapshotId": snap_id,
                    "SnapshotName": snap_name,
                    "SnapshotState": snap_state,
                    "SnapshotStartTime": start_str,
                    "SnapshotAgeDays": age_days,
                    "SnapshotSizeGB": snap_size,
                    "SnapshotEstimatedMonthlyCostUSD": snap_cost,
                    "SnapshotEstimatedAnnualCostUSD": round(snap_cost * 12, 2),
                    "SnapshotEncrypted": enc,
                    "SnapshotKmsKeyId": kms_key,
                    "SnapshotStorageTier": tier,
                    "SnapshotDescription": desc,
                    "SnapshotTags_Count": tags_count,
                    "SnapshotTags_Formatted": tags_fmt,
                    "SnapshotTags_JSON": tags_dict,
                    "VolumeId": source_vol_id,
                    "VolumeExists": vol_exists,
                    "VolumeName": vol_name,
                    "VolumeState": vol_state,
                    "VolumeType": vol_type,
                    "VolumeSizeGB": vol_size,
                    "VolumeCreateTime": vol_created,
                    "VolumeEncrypted": vol_enc,
                    "VolumeDeleteOnTermination": vol_del_on_term,
                    "VolumeTags_Formatted": vol_tags_fmt,
                    "InstanceId": inst_id,
                    "InstanceExists": inst_exists,
                    "InstanceName": inst_name,
                    "InstanceState": inst_state,
                    "InstanceType": inst_type,
                    "InstancePrivateIp": inst_priv_ip,
                    "InstanceLaunchTime": inst_launch,
                    "InstanceTags_Formatted": inst_tags_fmt,
                    "AssociationStatus": assoc_status,
                    "IsOrphan": is_orphan,
                    "FinOps_Finding": finops_finding,
                    "Recommended_Action": rec_action,
                }
                snapshots_list.append(snap_record)
                volume_to_snapshots[source_vol_id].append(snap_record)

                # Link snapshot to instance record for EC2 hierarchy view
                clean_inst_id = inst_id.split()[0]
                if clean_inst_id in instances_map:
                    instances_map[clean_inst_id]["AssociatedSnapshotsCount"] += 1
                    instances_map[clean_inst_id]["TotalSnapshotsStorageGB"] += snap_size
                    curr_ids = instances_map[clean_inst_id]["AssociatedSnapshotIds"]
                    instances_map[clean_inst_id]["AssociatedSnapshotIds"] = f"{curr_ids}; {snap_id}" if curr_ids else snap_id

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code not in ["UnauthorizedOperation", "AccessDenied", "AuthFailure"]:
            safe_print(f"    [!] Error describing snapshots in {acc_id} {region}: {code}")

    # Finalize EC2 instance backup status
    for inst in instances_map.values():
        if inst["AssociatedSnapshotsCount"] > 0:
            inst["BackupProtectionStatus"] = f"PROTECTED ({inst['AssociatedSnapshotsCount']} Snaps, {inst['TotalSnapshotsStorageGB']} GB)"
        else:
            inst["BackupProtectionStatus"] = "UNPROTECTED (0 Snapshots)"

    # Identify Orphan Waste Items (combines unattached volumes + orphaned snapshots)
    orphans_waste_list = []

    # 1. Add Unattached EBS Volumes
    for uv in unattached_volumes:
        associated_snaps = volume_to_snapshots.get(uv["VolumeId"], [])
        orphans_waste_list.append({
            "OrganizationProfile": profile_name,
            "OrganizationId": org_id,
            "AccountId": acc_id,
            "AccountName": acc_name,
            "Region": region,
            "ResourceType": "EBS_VOLUME",
            "ResourceId": uv["VolumeId"],
            "ResourceName": uv["VolumeName"],
            "CreationTime": uv["CreateTime"],
            "AgeDays": uv["AgeDays"],
            "SizeGB": uv["SizeGB"],
            "VolumeType": uv["VolumeType"],
            "EstimatedMonthlyWasteUSD": uv["EstimatedMonthlyCostUSD"],
            "EstimatedAnnualWasteUSD": uv["EstimatedAnnualCostUSD"],
            "OrphanReason": f"Unattached EBS Volume ({uv['State']}) - Paying idle storage fees",
            "SourceVolumeId": uv["VolumeId"],
            "SourceVolumeState": uv["State"],
            "AssociatedInstanceId": "None (Unattached)",
            "AssociatedInstanceState": "N/A",
            "AssociatedSnapshotsCount": len(associated_snaps),
            "Encrypted": uv["Encrypted"],
            "Tags_Formatted": uv["Tags_Formatted"],
            "RecommendedAction": "Create final snapshot and delete unattached volume" if uv["AgeDays"] > 14 else "Review idle attachment",
        })

    # 2. Add Orphaned Snapshots
    for s in snapshots_list:
        if s["IsOrphan"]:
            orphans_waste_list.append({
                "OrganizationProfile": profile_name,
                "OrganizationId": org_id,
                "AccountId": acc_id,
                "AccountName": acc_name,
                "Region": region,
                "ResourceType": "EBS_SNAPSHOT",
                "ResourceId": s["SnapshotId"],
                "ResourceName": s["SnapshotName"],
                "CreationTime": s["SnapshotStartTime"],
                "AgeDays": s["SnapshotAgeDays"],
                "SizeGB": s["SnapshotSizeGB"],
                "VolumeType": s["VolumeType"],
                "EstimatedMonthlyWasteUSD": s["SnapshotEstimatedMonthlyCostUSD"],
                "EstimatedAnnualWasteUSD": s["SnapshotEstimatedAnnualCostUSD"],
                "OrphanReason": s["FinOps_Finding"],
                "SourceVolumeId": s["VolumeId"],
                "SourceVolumeState": s["VolumeState"],
                "AssociatedInstanceId": s["InstanceId"],
                "AssociatedInstanceState": s["InstanceState"],
                "AssociatedSnapshotsCount": 1,
                "Encrypted": s["SnapshotEncrypted"],
                "Tags_Formatted": s["SnapshotTags_Formatted"],
                "RecommendedAction": s["Recommended_Action"],
            })

    return {
        "snapshots": snapshots_list,
        "instances": list(instances_map.values()),
        "volumes": list(volumes_map.values()),
        "unattached_volumes": unattached_volumes,
        "orphans_waste": orphans_waste_list,
    }

def process_account(account_info, mgmt_account_id, candidate_roles, default_region, session, profile_name, org_id, target_regions, region_workers, stale_days=180):
    acc_id = account_info["Id"]
    acc_name = account_info.get("Name", "Unknown")
    is_management = (acc_id == mgmt_account_id)

    safe_print(f"  [>] Auditing Account: {acc_name} ({acc_id}){' [Management Root]' if is_management else ''}...")

    # Establish account session
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
                resp = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="EC2SnapshotsAuditSession",
                    DurationSeconds=3600,
                )
                creds = resp["Credentials"]
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
        safe_print(f"    [-] Could not assume cross-account role in {acc_id} ({acc_name}). Skipping.")
        return {"snapshots": [], "instances": [], "volumes": [], "unattached_volumes": [], "orphans_waste": []}

    # Discover enabled regions in account
    regions_to_scan = target_regions
    if not regions_to_scan:
        try:
            ec2_default = account_session.client("ec2", region_name=default_region)
            reg_resp = ec2_default.describe_regions(AllRegions=False)
            regions_to_scan = [r["RegionName"] for r in reg_resp.get("Regions", [])]
        except Exception:
            regions_to_scan = ["us-east-1", "us-east-2", "us-west-2", "ca-central-1"]

    account_data = {
        "snapshots": [],
        "instances": [],
        "volumes": [],
        "unattached_volumes": [],
        "orphans_waste": [],
    }

    # Parallel scan across enabled regions
    with ThreadPoolExecutor(max_workers=region_workers) as reg_executor:
        futures = {
            reg_executor.submit(
                scan_account_region,
                account_session,
                reg,
                account_info,
                profile_name,
                org_id,
                stale_days
            ): reg for reg in regions_to_scan
        }

        for fut in as_completed(futures):
            reg = futures[fut]
            try:
                reg_res = fut.result()
                account_data["snapshots"].extend(reg_res["snapshots"])
                account_data["instances"].extend(reg_res["instances"])
                account_data["volumes"].extend(reg_res["volumes"])
                account_data["unattached_volumes"].extend(reg_res["unattached_volumes"])
                account_data["orphans_waste"].extend(reg_res["orphans_waste"])
            except Exception as e:
                safe_print(f"    [-] Region {reg} thread error in {acc_id}: {e}")

    snap_count = len(account_data["snapshots"])
    inst_count = len(account_data["instances"])
    vol_count = len(account_data["volumes"])
    unat_count = len(account_data["unattached_volumes"])
    orph_count = len(account_data["orphans_waste"])
    safe_print(f"    [+] {acc_name} ({acc_id}): {snap_count} Snapshots, {vol_count} Volumes ({unat_count} unattached), {inst_count} EC2s | {orph_count} Waste Items.")
    return account_data

def scan_single_organization(profile_or_session, args, candidate_roles, is_current_session=False, session=None):
    profile_name = "current" if is_current_session else profile_or_session
    safe_print("\n" + "=" * 80)

    auth_method = "pre_authenticated"
    if session is None:
        session, auth_method = get_session_for_profile(profile_name, is_current_session=is_current_session)

    if session is None:
        safe_print(f"[-] Authentication error for profile '{profile_name}': Unable to locate active credentials.")
        safe_print(f"    Hint: Run 'aws login --profile {profile_name}' or 'aws sso login --profile {profile_name}'")
        return {"snapshots": [], "instances": [], "volumes": [], "unattached_volumes": [], "orphans_waste": []}

    if is_current_session:
        safe_print(f"Connecting to CURRENT Active AWS Session in PowerShell [Auth: {auth_method}]...")
    else:
        resolved = resolve_profile_name(profile_name)
        safe_print(f"Connecting to AWS Profile: '{profile_name}'" + (f" (alias: {resolved})" if resolved != profile_name else "") + f" [Auth: {auth_method}]...")

    default_region = session.region_name or ("ca-central-1" if "cccs" in profile_name else "us-east-1")

    # Verify caller identity
    try:
        sts = session.client("sts", region_name=default_region)
        identity = sts.get_caller_identity()
        mgmt_id = identity["Account"]
        caller_arn = identity["Arn"]
        safe_print(f"  [+] Authenticated as: {caller_arn} (Account: {mgmt_id})")
    except Exception as ex:
        safe_print(f"  [-] Identity verification error for profile '{profile_name}': {ex}")
        return {"snapshots": [], "instances": [], "volumes": [], "unattached_volumes": [], "orphans_waste": []}

    # Discover AWS Organization Accounts
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
        safe_print(f"  [i] organizations:DescribeOrganization ({code}). Scanning account {mgmt_id} directly as standalone.")
        accounts = [{"Id": mgmt_id, "Name": profile_name}]
    except Exception as ex:
        safe_print(f"  [-] Could not query Organizations: {ex}. Scanning management account {mgmt_id} only.")
        accounts = [{"Id": mgmt_id, "Name": profile_name}]

    # Parallel scan across accounts
    org_results = {
        "snapshots": [],
        "instances": [],
        "volumes": [],
        "unattached_volumes": [],
        "orphans_waste": [],
    }

    safe_print(f"  [*] Scanning {len(accounts)} account(s) using {args.workers} worker threads...")
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                process_account,
                acc,
                mgmt_id,
                candidate_roles,
                default_region,
                session,
                profile_name,
                org_id,
                args.regions,
                args.region_workers,
                args.stale_snapshot_days
            ): acc["Id"] for acc in accounts
        }

        for fut in as_completed(futures):
            acc_id = futures[fut]
            try:
                acc_res = fut.result()
                org_results["snapshots"].extend(acc_res["snapshots"])
                org_results["instances"].extend(acc_res["instances"])
                org_results["volumes"].extend(acc_res["volumes"])
                org_results["unattached_volumes"].extend(acc_res["unattached_volumes"])
                org_results["orphans_waste"].extend(acc_res["orphans_waste"])
            except Exception as e:
                safe_print(f"  [-] Account {acc_id} thread error: {e}")

    safe_print(f"  [=] Finished Profile '{profile_name}': {len(org_results['snapshots'])} Snapshots, {len(org_results['volumes'])} Volumes, {len(org_results['instances'])} EC2s.")
    return org_results

def export_csv(records, filepath, headers=None, exclude_keys=None):
    if not records:
        safe_print(f"  [!] No records to write for {filepath}")
        return filepath
    if exclude_keys is None:
        exclude_keys = {"AttachedVolumes", "Tags_JSON", "SnapshotTags_JSON"}
    if headers is None:
        headers = [k for k in records[0].keys() if k not in exclude_keys]

    os.makedirs(os.path.dirname(os.path.abspath(filepath)), exist_ok=True)
    target_path = filepath
    try:
        with open(target_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for row in records:
                clean_row = {}
                for k in headers:
                    v = row.get(k, "")
                    if v is None:
                        clean_row[k] = ""
                    elif isinstance(v, (list, dict)):
                        clean_row[k] = json.dumps(v)
                    else:
                        clean_row[k] = v
                writer.writerow(clean_row)
    except PermissionError:
        # File is locked by Excel or another process! Save fallback copy
        base, ext = os.path.splitext(filepath)
        target_path = f"{base}_latest{ext}"
        safe_print(f"  [!] Lock Warning: '{filepath}' is currently locked (open in Microsoft Excel).")
        safe_print(f"  [>] Writing fallback to: '{target_path}'")
        with open(target_path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=headers, extrasaction="ignore")
            writer.writeheader()
            for row in records:
                clean_row = {}
                for k in headers:
                    v = row.get(k, "")
                    if v is None:
                        clean_row[k] = ""
                    elif isinstance(v, (list, dict)):
                        clean_row[k] = json.dumps(v)
                    else:
                        clean_row[k] = v
                writer.writerow(clean_row)

    size_kb = round(os.path.getsize(target_path) / 1024, 1)
    safe_print(f"  [+] Saved CSV: {target_path} ({size_kb} KB, {len(records)} rows)")
    return target_path

def compute_portal_statistics(all_data):
    snapshots = all_data.get("snapshots", [])
    volumes = all_data.get("volumes", [])
    instances = all_data.get("instances", [])
    orphans = all_data.get("orphans_waste", [])
    unattached_vols = all_data.get("unattached_volumes", [])

    total_snaps = len(snapshots)
    total_snap_gb = sum(s.get("SnapshotSizeGB", 0) for s in snapshots)
    total_snap_cost = sum(s.get("SnapshotEstimatedMonthlyCostUSD", 0) for s in snapshots)

    total_vols = len(volumes)
    total_vol_gb = sum(v.get("SizeGB", 0) for v in volumes)
    total_vol_cost = sum(v.get("EstimatedMonthlyCostUSD", 0) for v in volumes)

    total_instances = len(instances)
    running_instances = sum(1 for i in instances if i.get("InstanceState") == "running")
    stopped_instances = sum(1 for i in instances if i.get("InstanceState") == "stopped")
    unprotected_instances = sum(1 for i in instances if i.get("AssociatedSnapshotsCount", 0) == 0)

    total_unattached_vols = len(unattached_vols)
    unattached_vol_gb = sum(v.get("SizeGB", 0) for v in unattached_vols)
    unattached_vol_cost = sum(v.get("EstimatedMonthlyCostUSD", 0) for v in unattached_vols)

    orphaned_snaps = [s for s in snapshots if s.get("IsOrphan")]
    orphaned_snap_count = len(orphaned_snaps)
    orphaned_snap_gb = sum(s.get("SnapshotSizeGB", 0) for s in orphaned_snaps)
    orphaned_snap_cost = sum(s.get("SnapshotEstimatedMonthlyCostUSD", 0) for s in orphaned_snaps)

    total_monthly_waste = round(unattached_vol_cost + orphaned_snap_cost, 2)
    total_annual_waste = round(total_monthly_waste * 12, 2)

    # Rollup by Account
    account_map = {}

    def get_or_create_account(acc_id, acc_name, org):
        if not acc_id:
            return None
        if acc_id not in account_map:
            account_map[acc_id] = {
                "AccountId": acc_id,
                "AccountName": acc_name or "Unknown",
                "Org": org or "",
                "SnapshotsCount": 0,
                "SnapshotsGB": 0,
                "SnapshotsCost": 0.0,
                "OrphanedSnapshots": 0,
                "OrphanedSnapshotsWasteUSD": 0.0,
                "VolumesCount": 0,
                "UnattachedVolumes": 0,
                "UnattachedWasteUSD": 0.0,
                "EC2Count": 0,
                "TotalMonthlyWaste": 0.0,
            }
        return account_map[acc_id]

    for s in snapshots:
        acc = get_or_create_account(s.get("AccountId"), s.get("AccountName"), s.get("OrganizationProfile"))
        if acc:
            acc["SnapshotsCount"] += 1
            acc["SnapshotsGB"] += s.get("SnapshotSizeGB", 0)
            acc["SnapshotsCost"] += s.get("SnapshotEstimatedMonthlyCostUSD", 0.0)
            if s.get("IsOrphan"):
                acc["OrphanedSnapshots"] += 1
                acc["OrphanedSnapshotsWasteUSD"] += s.get("SnapshotEstimatedMonthlyCostUSD", 0.0)

    for v in volumes:
        acc = get_or_create_account(v.get("AccountId"), v.get("AccountName"), v.get("OrganizationProfile"))
        if acc:
            acc["VolumesCount"] += 1
            if not v.get("IsAttached"):
                acc["UnattachedVolumes"] += 1
                acc["UnattachedWasteUSD"] += v.get("EstimatedMonthlyCostUSD", 0.0)

    for i in instances:
        acc = get_or_create_account(i.get("AccountId"), i.get("AccountName"), i.get("OrganizationProfile"))
        if acc:
            acc["EC2Count"] += 1

    for a in account_map.values():
        a["SnapshotsCost"] = round(a["SnapshotsCost"], 2)
        a["UnattachedWasteUSD"] = round(a["UnattachedWasteUSD"], 2)
        a["OrphanedSnapshotsWasteUSD"] = round(a["OrphanedSnapshotsWasteUSD"], 2)
        a["TotalMonthlyWaste"] = round(a["UnattachedWasteUSD"] + a["OrphanedSnapshotsWasteUSD"], 2)

    return {
        "total_snapshots": total_snaps,
        "total_snapshot_gb": total_snap_gb,
        "total_snapshot_tb": round(total_snap_gb / 1024, 2),
        "total_snapshot_cost_monthly": round(total_snap_cost, 2),
        "total_volumes": total_vols,
        "total_volume_gb": total_vol_gb,
        "total_volume_cost_monthly": round(total_vol_cost, 2),
        "total_instances": total_instances,
        "running_instances": running_instances,
        "stopped_instances": stopped_instances,
        "unprotected_instances": unprotected_instances,
        "unattached_volumes_count": total_unattached_vols,
        "unattached_volume_gb": unattached_vol_gb,
        "unattached_volume_monthly_cost": round(unattached_vol_cost, 2),
        "orphaned_snapshots_count": orphaned_snap_count,
        "orphaned_snapshots_gb": orphaned_snap_gb,
        "orphaned_snapshots_monthly_cost": round(orphaned_snap_cost, 2),
        "total_monthly_waste": total_monthly_waste,
        "total_annual_waste": total_annual_waste,
        "accounts": sorted(account_map.values(), key=lambda x: x["SnapshotsCount"], reverse=True),
    }

def generate_html_portal(all_data, stats, output_path):
    snapshots_json = json.dumps(all_data.get("snapshots", []))
    orphans_json = json.dumps(all_data.get("orphans_waste", []))
    instances_json = json.dumps(all_data.get("instances", []))
    stats_json = json.dumps(stats)

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AWS Multi-Organization EBS Snapshots, Volumes & EC2 Lineage Portal</title>
  <style>
    :root {{
      --bg-dark: #0a0f1d;
      --bg-card: #131b2e;
      --bg-card-hover: #1a243d;
      --bg-input: #1a253c;
      --border: #23314e;
      --border-focus: #3b82f6;
      --text-main: #f1f5f9;
      --text-muted: #94a3b8;
      --text-dim: #64748b;
      --accent: #38bdf8;
      --danger: #ef4444;
      --danger-bg: rgba(239, 68, 68, 0.15);
      --warning: #f59e0b;
      --warning-bg: rgba(245, 158, 11, 0.15);
      --success: #10b981;
      --success-bg: rgba(16, 185, 129, 0.15);
      --info: #3b82f6;
      --info-bg: rgba(59, 130, 246, 0.15);
      --purple: #a855f7;
      --purple-bg: rgba(168, 85, 247, 0.15);
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; }}
    body {{ background: var(--bg-dark); color: var(--text-main); min-height: 100vh; padding: 24px; }}
    .header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }}
    .title-area h1 {{ font-size: 24px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 10px; }}
    .title-area p {{ color: var(--text-muted); font-size: 13px; margin-top: 6px; }}
    .badge-bar {{ display: flex; gap: 10px; margin-top: 10px; }}
    .tag-badge {{ background: var(--bg-card); border: 1px solid var(--border); padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 600; color: var(--accent); }}
    
    /* KPI Cards */
    .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; margin-bottom: 24px; }}
    .kpi-card {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; position: relative; overflow: hidden; }}
    .kpi-card::before {{ content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%; background: var(--accent); }}
    .kpi-card.danger::before {{ background: var(--danger); }}
    .kpi-card.warning::before {{ background: var(--warning); }}
    .kpi-card.success::before {{ background: var(--success); }}
    .kpi-card.purple::before {{ background: var(--purple); }}
    .kpi-title {{ font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }}
    .kpi-value {{ font-size: 26px; font-weight: 700; color: #fff; font-family: 'JetBrains Mono', monospace; }}
    .kpi-sub {{ font-size: 12px; color: var(--text-dim); margin-top: 6px; display: flex; justify-content: space-between; }}

    /* Tabs Navigation */
    .tab-bar {{ display: flex; gap: 8px; border-bottom: 1px solid var(--border); margin-bottom: 18px; padding-bottom: 8px; }}
    .tab-btn {{ background: transparent; border: 1px solid transparent; color: var(--text-muted); padding: 8px 18px; border-radius: 8px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }}
    .tab-btn:hover {{ background: var(--bg-card); color: #fff; }}
    .tab-btn.active {{ background: var(--border); color: #fff; border-color: var(--border-focus); }}
    .tab-btn .badge {{ margin-left: 6px; background: rgba(255,255,255,0.1); padding: 2px 7px; border-radius: 10px; font-size: 11px; }}

    /* Filters Bar */
    .filter-section {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 14px 18px; margin-bottom: 18px; display: flex; flex-wrap: wrap; gap: 12px; align-items: center; justify-content: space-between; }}
    .filter-group {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
    .search-input {{ background: var(--bg-input); border: 1px solid var(--border); color: #fff; padding: 8px 14px; border-radius: 6px; font-size: 13px; width: 280px; outline: none; }}
    .search-input:focus {{ border-color: var(--border-focus); }}
    .filter-select {{ background: var(--bg-input); border: 1px solid var(--border); color: #fff; padding: 8px 12px; border-radius: 6px; font-size: 13px; outline: none; }}
    .btn-export {{ background: #1e293b; border: 1px solid var(--border); color: var(--accent); padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; display: inline-flex; align-items: center; gap: 6px; }}
    .btn-export:hover {{ background: #334155; }}

    /* Data Tables */
    .table-container {{ background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; overflow-x: auto; box-shadow: 0 4px 20px rgba(0,0,0,0.3); }}
    table {{ width: 100%; border-collapse: collapse; text-align: left; font-size: 12px; }}
    thead th {{ background: #0f1628; color: var(--text-muted); padding: 12px 14px; font-weight: 600; border-bottom: 1px solid var(--border); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; white-space: nowrap; }}
    tbody td {{ padding: 12px 14px; border-bottom: 1px solid #1a243c; color: #e2e8f0; }}
    tbody tr:hover {{ background: var(--bg-card-hover); cursor: pointer; }}
    
    /* Badges & Tags */
    .pill {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; text-align: center; }}
    .pill-danger {{ background: var(--danger-bg); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }}
    .pill-warning {{ background: var(--warning-bg); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }}
    .pill-success {{ background: var(--success-bg); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }}
    .pill-info {{ background: var(--info-bg); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }}
    .pill-purple {{ background: var(--purple-bg); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }}
    .pill-muted {{ background: rgba(148, 163, 184, 0.1); color: var(--text-muted); border: 1px solid var(--border); }}

    /* Drawer / Modal */
    .drawer {{ position: fixed; top: 0; right: -600px; width: 600px; height: 100vh; background: #0f172a; border-left: 1px solid var(--border); box-shadow: -10px 0 30px rgba(0,0,0,0.5); padding: 24px; overflow-y: auto; transition: right 0.3s ease; z-index: 1000; }}
    .drawer.open {{ right: 0; }}
    .drawer-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 14px; border-bottom: 1px solid var(--border); }}
    .drawer-title {{ font-size: 18px; font-weight: 700; color: #fff; }}
    .close-btn {{ background: transparent; border: none; color: var(--text-muted); font-size: 20px; cursor: pointer; }}
    .close-btn:hover {{ color: #fff; }}
    .drawer-section {{ margin-bottom: 18px; background: var(--bg-card); border: 1px solid var(--border); border-radius: 8px; padding: 14px; }}
    .drawer-section h4 {{ font-size: 13px; color: var(--accent); margin-bottom: 10px; text-transform: uppercase; letter-spacing: 0.5px; }}
    .key-val-grid {{ display: grid; grid-template-columns: 140px 1fr; gap: 8px; font-size: 12px; }}
    .kv-k {{ color: var(--text-muted); }}
    .kv-v {{ color: #fff; font-family: 'JetBrains Mono', monospace; word-break: break-all; }}
  </style>
</head>
<body>

  <div class="header">
    <div class="title-area">
      <h1>📸 AWS EBS Snapshots, Volumes & EC2 Lineage Hub</h1>
      <p>Multi-Organization Infrastructure & FinOps Orphan Discovery: rus-ext, rus-ioc, cccs</p>
      <div class="badge-bar">
        <span class="tag-badge">SNAPSHOT IS CENTRAL</span>
        <span class="tag-badge">ORPHAN DETECTION</span>
        <span class="tag-badge">UNATTACHED VOLUMES</span>
        <span class="tag-badge">ZERO-DAY FINOPS</span>
      </div>
    </div>
    <div>
      <button class="btn-export" onclick="exportCurrentTabCSV()">📥 Export Filtered CSV</button>
    </div>
  </div>

  <!-- KPI Overview -->
  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-title">Total EBS Snapshots</div>
      <div class="kpi-value">{stats['total_snapshots']}</div>
      <div class="kpi-sub">
        <span>Footprint: {stats['total_snapshot_tb']} TB</span>
        <span>${stats['total_snapshot_cost_monthly']}/mo</span>
      </div>
    </div>

    <div class="kpi-card danger">
      <div class="kpi-title">Orphaned Snapshots</div>
      <div class="kpi-value">{stats['orphaned_snapshots_count']}</div>
      <div class="kpi-sub">
        <span>Volume Deleted / Missing</span>
        <span>${stats['orphaned_snapshots_monthly_cost']}/mo Waste</span>
      </div>
    </div>

    <div class="kpi-card warning">
      <div class="kpi-title">Unattached EBS Volumes</div>
      <div class="kpi-value">{stats['unattached_volumes_count']}</div>
      <div class="kpi-sub">
        <span>{stats['unattached_volume_gb']} GB Idle</span>
        <span>${stats['unattached_volume_monthly_cost']}/mo Waste</span>
      </div>
    </div>

    <div class="kpi-card purple">
      <div class="kpi-title">Total Recoverable Waste</div>
      <div class="kpi-value">${stats['total_monthly_waste']}<span style="font-size:14px;font-weight:400;color:var(--text-muted)">/mo</span></div>
      <div class="kpi-sub">
        <span>Annual: ${stats['total_annual_waste']}/yr</span>
        <span>Zero Downtime Impact</span>
      </div>
    </div>

    <div class="kpi-card success">
      <div class="kpi-title">EC2 Fleet & Protection</div>
      <div class="kpi-value">{stats['total_instances']}</div>
      <div class="kpi-sub">
        <span>{stats['running_instances']} Running / {stats['stopped_instances']} Stopped</span>
        <span style="color:#f87171">{stats['unprotected_instances']} No Snapshots</span>
      </div>
    </div>
  </div>

  <!-- Tabs Navigation -->
  <div class="tab-bar">
    <button class="tab-btn active" onclick="switchTab('snapshots')">📸 Snapshot Lineage Hub <span class="badge" id="snap-tab-badge">{stats['total_snapshots']}</span></button>
    <button class="tab-btn" onclick="switchTab('orphans')">⚠️ Unattached & Orphaned Waste <span class="badge" style="background:var(--danger-bg);color:#f87171" id="orphan-tab-badge">{len(all_data.get('orphans_waste', []))}</span></button>
    <button class="tab-btn" onclick="switchTab('instances')">🖥️ EC2 Storage Hierarchy <span class="badge" id="inst-tab-badge">{stats['total_instances']}</span></button>
    <button class="tab-btn" onclick="switchTab('accounts')">🏢 Account Rollup Matrix <span class="badge">{len(stats['accounts'])}</span></button>
  </div>

  <!-- Dynamic Filter Bar -->
  <div class="filter-section">
    <div class="filter-group">
      <input type="text" id="globalSearch" class="search-input" placeholder="Search Snapshots, Volumes, Instances, Tags..." oninput="applyFilters()">
      <select id="orgFilter" class="filter-select" onchange="applyFilters()">
        <option value="ALL">All Organizations</option>
        <option value="rus-ext">rus-ext</option>
        <option value="rus-ioc">rus-ioc</option>
        <option value="cccs">cccs</option>
      </select>
      <select id="statusFilter" class="filter-select" onchange="applyFilters()">
        <option value="ALL">All Association States</option>
        <option value="ATTACHED_RUNNING">Attached to Running EC2</option>
        <option value="ATTACHED_STOPPED">Attached to Stopped EC2</option>
        <option value="UNATTACHED_VOLUME">Unattached Volume</option>
        <option value="ORPHAN_VOLUME_DELETED">Volume Deleted (Orphan)</option>
        <option value="COMPLETE_ORPHAN">Complete Orphan</option>
      </select>
      <select id="ageFilter" class="filter-select" onchange="applyFilters()">
        <option value="ALL">All Ages</option>
        <option value="stale180">> 180 Days (Stale)</option>
        <option value="year1">> 1 Year (Legacy)</option>
        <option value="recent30">< 30 Days (Recent)</option>
      </select>
    </div>
    <div id="filterCount" style="font-size:12px;color:var(--text-muted)">Showing: <strong style="color:#fff" id="filteredRowCount">0</strong> records</div>
  </div>

  <!-- Tab 1: Snapshots Central Hub -->
  <div id="tab-snapshots" class="tab-content">
    <div class="table-container">
      <table id="snapshotsTable">
        <thead>
          <tr>
            <th>Organization</th>
            <th>Account</th>
            <th>Snapshot ID</th>
            <th>Snapshot Name</th>
            <th>Age (Days)</th>
            <th>Size (GB)</th>
            <th>Cost/Mo</th>
            <th>Source Volume</th>
            <th>Volume State</th>
            <th>Associated EC2</th>
            <th>EC2 State</th>
            <th>Association Verdict</th>
            <th>Action Recommendation</th>
          </tr>
        </thead>
        <tbody id="snapshotsBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Tab 2: Orphaned Waste Hub -->
  <div id="tab-orphans" class="tab-content" style="display:none">
    <div class="table-container">
      <table id="orphansTable">
        <thead>
          <tr>
            <th>Organization</th>
            <th>Account</th>
            <th>Resource Type</th>
            <th>Resource ID</th>
            <th>Name</th>
            <th>Age (Days)</th>
            <th>Size (GB)</th>
            <th>Waste / Mo</th>
            <th>Waste / Yr</th>
            <th>Orphan Reason</th>
            <th>Source Volume</th>
            <th>Associated EC2</th>
            <th>Action Recommendation</th>
          </tr>
        </thead>
        <tbody id="orphansBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Tab 3: EC2 Instances Storage Hierarchy -->
  <div id="tab-instances" class="tab-content" style="display:none">
    <div class="table-container">
      <table id="instancesTable">
        <thead>
          <tr>
            <th>Organization</th>
            <th>Account</th>
            <th>Instance ID</th>
            <th>Instance Name</th>
            <th>State</th>
            <th>Type</th>
            <th>Private IP</th>
            <th>Attached Vols</th>
            <th>Attached GB</th>
            <th>Snapshots Count</th>
            <th>Snapshots GB</th>
            <th>Backup Status</th>
          </tr>
        </thead>
        <tbody id="instancesBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Tab 4: Account Rollup Matrix -->
  <div id="tab-accounts" class="tab-content" style="display:none">
    <div class="table-container">
      <table id="accountsTable">
        <thead>
          <tr>
            <th>Organization</th>
            <th>Account ID</th>
            <th>Account Name</th>
            <th>Total Snapshots</th>
            <th>Snapshots GB</th>
            <th>Snapshots Cost/Mo</th>
            <th>Orphaned Snapshots</th>
            <th>Total Volumes</th>
            <th>Unattached Volumes</th>
            <th>Unattached Waste/Mo</th>
            <th>EC2 Fleet</th>
          </tr>
        </thead>
        <tbody id="accountsBody"></tbody>
      </table>
    </div>
  </div>

  <!-- Slide-out Drawer for Deep Inspection -->
  <div id="drawer" class="drawer">
    <div class="drawer-header">
      <div class="drawer-title" id="drawerTitle">Resource Inspector</div>
      <button class="close-btn" onclick="closeDrawer()">&times;</button>
    </div>
    <div id="drawerContent"></div>
  </div>

<script>
const snapshotsData = {snapshots_json};
const orphansData = {orphans_json};
const instancesData = {instances_json};
const statsData = {stats_json};

let currentTab = 'snapshots';
let filteredSnapshots = [...snapshotsData];
let filteredOrphans = [...orphansData];
let filteredInstances = [...instancesData];

function switchTab(tabId) {{
  currentTab = tabId;
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
  
  event.target.classList.add('active');
  document.getElementById(`tab-${{tabId}}`).style.display = 'block';
  applyFilters();
}}

function getPillForStatus(status) {{
  if (status === 'ATTACHED_RUNNING') return '<span class="pill pill-success">Attached (Running)</span>';
  if (status === 'ATTACHED_STOPPED') return '<span class="pill pill-warning">Attached (Stopped)</span>';
  if (status === 'UNATTACHED_VOLUME') return '<span class="pill pill-danger">Unattached Volume</span>';
  if (status.includes('VOLUME_DELETED')) return '<span class="pill pill-danger">Volume Deleted</span>';
  if (status === 'COMPLETE_ORPHAN') return '<span class="pill pill-danger">Complete Orphan</span>';
  return `<span class="pill pill-muted">${{status}}</span>`;
}}

function renderSnapshotsTable(data) {{
  const tbody = document.getElementById('snapshotsBody');
  tbody.innerHTML = data.map((s, idx) => `
    <tr onclick="inspectResource('snapshot', ${{idx}})">
      <td><span class="pill pill-info">${{s.OrganizationProfile}}</span></td>
      <td><strong>${{s.AccountName}}</strong><br><span style="font-size:10px;color:var(--text-dim)">${{s.AccountId}}</span></td>
      <td><code style="color:var(--accent)">${{s.SnapshotId}}</code></td>
      <td>${{s.SnapshotName !== 'N/A' ? s.SnapshotName : '<span style="color:var(--text-dim)">-</span>'}}</td>
      <td>${{s.SnapshotAgeDays}}d</td>
      <td>${{s.SnapshotSizeGB}} GB</td>
      <td style="color:#38bdf8;font-weight:600">$${{s.SnapshotEstimatedMonthlyCostUSD}}</td>
      <td><code style="color:${{s.VolumeExists ? '#a5b4fc' : '#ef4444'}}">${{s.VolumeId}}</code></td>
      <td>${{s.VolumeExists ? `<span class="pill pill-muted">${{s.VolumeState}}</span>` : '<span class="pill pill-danger">DELETED</span>'}}</td>
      <td>${{s.InstanceExists ? `<code style="color:#6ee7b7">${{s.InstanceId}}</code>` : `<span style="color:var(--text-dim)">${{s.InstanceId}}</span>`}}</td>
      <td>${{s.InstanceState === 'running' ? '<span class="pill pill-success">running</span>' : (s.InstanceState === 'stopped' ? '<span class="pill pill-warning">stopped</span>' : `<span class="pill pill-muted">${{s.InstanceState}}</span>`)}}</td>
      <td>${{getPillForStatus(s.AssociationStatus)}}</td>
      <td style="font-size:11px;color:${{s.IsOrphan ? '#fca5a5' : 'var(--text-muted)'}}">${{s.Recommended_Action}}</td>
    </tr>
  `).join('');
  document.getElementById('filteredRowCount').innerText = data.length;
}}

function renderOrphansTable(data) {{
  const tbody = document.getElementById('orphansBody');
  tbody.innerHTML = data.map((o, idx) => `
    <tr onclick="inspectResource('orphan', ${{idx}})">
      <td><span class="pill pill-info">${{o.OrganizationProfile}}</span></td>
      <td><strong>${{o.AccountName}}</strong></td>
      <td><span class="pill ${{o.ResourceType === 'EBS_VOLUME' ? 'pill-warning' : 'pill-purple'}}">${{o.ResourceType}}</span></td>
      <td><code style="color:var(--accent)">${{o.ResourceId}}</code></td>
      <td>${{o.ResourceName !== 'N/A' ? o.ResourceName : '-'}}</td>
      <td>${{o.AgeDays}}d</td>
      <td>${{o.SizeGB}} GB</td>
      <td style="color:#ef4444;font-weight:700">$${{o.EstimatedMonthlyWasteUSD}}</td>
      <td style="color:#f87171">$${{o.EstimatedAnnualWasteUSD}}</td>
      <td style="color:#fca5a5">${{o.OrphanReason}}</td>
      <td><code>${{o.SourceVolumeId}}</code></td>
      <td>${{o.AssociatedInstanceId}}</td>
      <td style="font-size:11px;color:var(--accent)">${{o.RecommendedAction}}</td>
    </tr>
  `).join('');
  document.getElementById('filteredRowCount').innerText = data.length;
}}

function renderInstancesTable(data) {{
  const tbody = document.getElementById('instancesBody');
  tbody.innerHTML = data.map((i, idx) => `
    <tr onclick="inspectResource('instance', ${{idx}})">
      <td><span class="pill pill-info">${{i.OrganizationProfile}}</span></td>
      <td><strong>${{i.AccountName}}</strong></td>
      <td><code style="color:var(--accent)">${{i.InstanceId}}</code></td>
      <td>${{i.InstanceName !== 'N/A' ? i.InstanceName : '-'}}</td>
      <td>${{i.InstanceState === 'running' ? '<span class="pill pill-success">running</span>' : '<span class="pill pill-warning">stopped</span>'}}</td>
      <td><code style="font-size:11px">${{i.InstanceType}}</code></td>
      <td>${{i.PrivateIpAddress}}</td>
      <td><span class="pill pill-muted">${{i.AttachedVolumesCount}} vols</span></td>
      <td>${{i.TotalAttachedStorageGB}} GB</td>
      <td><span class="pill ${{i.AssociatedSnapshotsCount > 0 ? 'pill-purple' : 'pill-danger'}}">${{i.AssociatedSnapshotsCount}} snaps</span></td>
      <td>${{i.TotalSnapshotsStorageGB}} GB</td>
      <td><span class="pill ${{i.AssociatedSnapshotsCount > 0 ? 'pill-success' : 'pill-danger'}}">${{i.BackupProtectionStatus}}</span></td>
    </tr>
  `).join('');
  document.getElementById('filteredRowCount').innerText = data.length;
}}

function renderAccountsTable() {{
  const tbody = document.getElementById('accountsBody');
  tbody.innerHTML = statsData.accounts.map(a => `
    <tr>
      <td><span class="pill pill-info">${{a.Org}}</span></td>
      <td><code>${{a.AccountId}}</code></td>
      <td><strong>${{a.AccountName}}</strong></td>
      <td>${{a.SnapshotsCount}}</td>
      <td>${{a.SnapshotsGB}} GB</td>
      <td style="color:var(--accent)">$${{a.SnapshotsCost}}</td>
      <td style="color:#f87171;font-weight:600">${{a.OrphanedSnapshots}}</td>
      <td>${{a.VolumesCount}}</td>
      <td style="color:#fbbf24;font-weight:600">${{a.UnattachedVolumes}}</td>
      <td style="color:#f87171">$${{a.UnattachedWasteUSD}}</td>
      <td>${{a.EC2Count}} EC2</td>
    </tr>
  `).join('');
  document.getElementById('filteredRowCount').innerText = statsData.accounts.length;
}}

function applyFilters() {{
  const q = document.getElementById('globalSearch').value.toLowerCase();
  const org = document.getElementById('orgFilter').value;
  const status = document.getElementById('statusFilter').value;
  const age = document.getElementById('ageFilter').value;

  if (currentTab === 'snapshots') {{
    filteredSnapshots = snapshotsData.filter(s => {{
      const matchQ = !q || (s.SnapshotId && s.SnapshotId.toLowerCase().includes(q)) ||
                           (s.SnapshotName && s.SnapshotName.toLowerCase().includes(q)) ||
                           (s.VolumeId && s.VolumeId.toLowerCase().includes(q)) ||
                           (s.InstanceId && s.InstanceId.toLowerCase().includes(q)) ||
                           (s.SnapshotTags_Formatted && s.SnapshotTags_Formatted.toLowerCase().includes(q));
      const matchOrg = (org === 'ALL') || (s.OrganizationProfile === org);
      let matchStatus = true;
      if (status !== 'ALL') {{
        if (status === 'ORPHAN_VOLUME_DELETED') matchStatus = s.AssociationStatus.includes('VOLUME_DELETED');
        else matchStatus = (s.AssociationStatus === status);
      }}
      let matchAge = true;
      if (age === 'stale180') matchAge = s.SnapshotAgeDays > 180;
      else if (age === 'year1') matchAge = s.SnapshotAgeDays > 365;
      else if (age === 'recent30') matchAge = s.SnapshotAgeDays <= 30;

      return matchQ && matchOrg && matchStatus && matchAge;
    }});
    renderSnapshotsTable(filteredSnapshots);
  }} else if (currentTab === 'orphans') {{
    filteredOrphans = orphansData.filter(o => {{
      const matchQ = !q || (o.ResourceId && o.ResourceId.toLowerCase().includes(q)) ||
                           (o.ResourceName && o.ResourceName.toLowerCase().includes(q)) ||
                           (o.SourceVolumeId && o.SourceVolumeId.toLowerCase().includes(q)) ||
                           (o.AssociatedInstanceId && o.AssociatedInstanceId.toLowerCase().includes(q));
      const matchOrg = (org === 'ALL') || (o.OrganizationProfile === org);
      let matchAge = true;
      if (age === 'stale180') matchAge = o.AgeDays > 180;
      else if (age === 'year1') matchAge = o.AgeDays > 365;
      else if (age === 'recent30') matchAge = o.AgeDays <= 30;
      return matchQ && matchOrg && matchAge;
    }});
    renderOrphansTable(filteredOrphans);
  }} else if (currentTab === 'instances') {{
    filteredInstances = instancesData.filter(i => {{
      const matchQ = !q || (i.InstanceId && i.InstanceId.toLowerCase().includes(q)) ||
                           (i.InstanceName && i.InstanceName.toLowerCase().includes(q)) ||
                           (i.PrivateIpAddress && i.PrivateIpAddress.includes(q)) ||
                           (i.Tags_Formatted && i.Tags_Formatted.toLowerCase().includes(q));
      const matchOrg = (org === 'ALL') || (i.OrganizationProfile === org);
      return matchQ && matchOrg;
    }});
    renderInstancesTable(filteredInstances);
  }} else if (currentTab === 'accounts') {{
    renderAccountsTable();
  }}
}}

function inspectResource(type, index) {{
  let item = null;
  if (type === 'snapshot') item = filteredSnapshots[index];
  else if (type === 'orphan') item = filteredOrphans[index];
  else if (type === 'instance') item = filteredInstances[index];
  if (!item) return;

  const drawer = document.getElementById('drawer');
  const title = document.getElementById('drawerTitle');
  const content = document.getElementById('drawerContent');

  if (type === 'snapshot') {{
    title.innerText = `📸 Snapshot: ${{item.SnapshotId}}`;
    content.innerHTML = `
      <div class="drawer-section">
        <h4>Snapshot Overview</h4>
        <div class="key-val-grid">
          <div class="kv-k">Snapshot Name:</div><div class="kv-v">${{item.SnapshotName}}</div>
          <div class="kv-k">Organization:</div><div class="kv-v">${{item.OrganizationProfile}} (${{item.AccountId}})</div>
          <div class="kv-k">Region:</div><div class="kv-v">${{item.Region}}</div>
          <div class="kv-k">Size & Cost:</div><div class="kv-v">${{item.SnapshotSizeGB}} GB ($${{item.SnapshotEstimatedMonthlyCostUSD}}/mo)</div>
          <div class="kv-k">Age:</div><div class="kv-v">${{item.SnapshotAgeDays}} days (${{item.SnapshotStartTime}})</div>
          <div class="kv-k">Storage Tier:</div><div class="kv-v">${{item.SnapshotStorageTier}}</div>
          <div class="kv-k">Encrypted:</div><div class="kv-v">${{item.SnapshotEncrypted}} (KMS: ${{item.SnapshotKmsKeyId}})</div>
          <div class="kv-k">Description:</div><div class="kv-v">${{item.SnapshotDescription || 'None'}}</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>Source EBS Volume Lineage</h4>
        <div class="key-val-grid">
          <div class="kv-k">Volume ID:</div><div class="kv-v">${{item.VolumeId}}</div>
          <div class="kv-k">Volume Status:</div><div class="kv-v">${{item.VolumeExists ? `<span class="pill pill-success">EXISTS in AWS (${{item.VolumeState}})</span>` : '<span class="pill pill-danger">DELETED / NOT FOUND</span>'}}</div>
          <div class="kv-k">Volume Type:</div><div class="kv-v">${{item.VolumeType}} (${{item.VolumeSizeGB}} GB)</div>
          <div class="kv-k">Created:</div><div class="kv-v">${{item.VolumeCreateTime}}</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>Originating EC2 Instance Lineage</h4>
        <div class="key-val-grid">
          <div class="kv-k">Instance ID:</div><div class="kv-v">${{item.InstanceId}}</div>
          <div class="kv-k">Instance Exists:</div><div class="kv-v">${{item.InstanceExists ? '<span class="pill pill-success">YES (Active in AWS)</span>' : '<span class="pill pill-danger">NO (Terminated / Missing)</span>'}}</div>
          <div class="kv-k">Instance State:</div><div class="kv-v">${{item.InstanceState}}</div>
          <div class="kv-k">Instance Type:</div><div class="kv-v">${{item.InstanceType}}</div>
          <div class="kv-k">Private IP:</div><div class="kv-v">${{item.InstancePrivateIp}}</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>FinOps Waste & Remediation</h4>
        <div class="key-val-grid">
          <div class="kv-k">Association:</div><div class="kv-v">${{getPillForStatus(item.AssociationStatus)}}</div>
          <div class="kv-k">Orphan Flag:</div><div class="kv-v">${{item.IsOrphan ? '<span class="pill pill-danger">YES - ORPHANED</span>' : '<span class="pill pill-success">NO - ACTIVE</span>'}}</div>
          <div class="kv-k">FinOps Finding:</div><div class="kv-v" style="color:#fca5a5">${{item.FinOps_Finding}}</div>
          <div class="kv-k">Recommendation:</div><div class="kv-v" style="color:var(--accent)">${{item.Recommended_Action}}</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>Snapshot Tags</h4>
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#cbd5e1;white-space:pre-wrap">${{item.SnapshotTags_Formatted || 'No tags attached'}}</div>
      </div>
    `;
  }} else if (type === 'orphan') {{
    title.innerText = `⚠️ Orphan Waste: ${{item.ResourceId}}`;
    content.innerHTML = `
      <div class="drawer-section">
        <h4>Resource Overview</h4>
        <div class="key-val-grid">
          <div class="kv-k">Resource Type:</div><div class="kv-v"><span class="pill ${{item.ResourceType === 'EBS_VOLUME' ? 'pill-warning' : 'pill-purple'}}">${{item.ResourceType}}</span></div>
          <div class="kv-k">Resource ID:</div><div class="kv-v">${{item.ResourceId}}</div>
          <div class="kv-k">Resource Name:</div><div class="kv-v">${{item.ResourceName}}</div>
          <div class="kv-k">Organization:</div><div class="kv-v">${{item.OrganizationProfile}} (${{item.AccountId}})</div>
          <div class="kv-k">Region:</div><div class="kv-v">${{item.Region}}</div>
          <div class="kv-k">Age:</div><div class="kv-v">${{item.AgeDays}} days (${{item.CreationTime}})</div>
          <div class="kv-k">Size & Type:</div><div class="kv-v">${{item.SizeGB}} GB (${{item.VolumeType}})</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>FinOps Waste Quantification</h4>
        <div class="key-val-grid">
          <div class="kv-k">Monthly Waste:</div><div class="kv-v" style="color:#ef4444;font-weight:700">$${{item.EstimatedMonthlyWasteUSD}}/month</div>
          <div class="kv-k">Annual Waste:</div><div class="kv-v" style="color:#f87171">$${{item.EstimatedAnnualWasteUSD}}/year</div>
          <div class="kv-k">Orphan Reason:</div><div class="kv-v" style="color:#fca5a5">${{item.OrphanReason}}</div>
          <div class="kv-k">Recommended Action:</div><div class="kv-v" style="color:var(--accent);font-weight:600">${{item.RecommendedAction}}</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>Lineage Details</h4>
        <div class="key-val-grid">
          <div class="kv-k">Source Volume:</div><div class="kv-v">${{item.SourceVolumeId}} (${{item.SourceVolumeState}})</div>
          <div class="kv-k">Associated EC2:</div><div class="kv-v">${{item.AssociatedInstanceId}} (${{item.AssociatedInstanceState}})</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>Resource Tags</h4>
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#cbd5e1;white-space:pre-wrap">${{item.Tags_Formatted || 'No tags attached'}}</div>
      </div>
    `;
  }} else if (type === 'instance') {{
    title.innerText = `🖥️ EC2 Instance: ${{item.InstanceId}}`;
    content.innerHTML = `
      <div class="drawer-section">
        <h4>Instance Overview</h4>
        <div class="key-val-grid">
          <div class="kv-k">Instance Name:</div><div class="kv-v">${{item.InstanceName}}</div>
          <div class="kv-k">Organization:</div><div class="kv-v">${{item.OrganizationProfile}} (${{item.AccountId}})</div>
          <div class="kv-k">Region:</div><div class="kv-v">${{item.Region}}</div>
          <div class="kv-k">State:</div><div class="kv-v">${{item.InstanceState}}</div>
          <div class="kv-k">Type:</div><div class="kv-v">${{item.InstanceType}}</div>
          <div class="kv-k">VPC / Subnet:</div><div class="kv-v">${{item.VpcId}} / ${{item.SubnetId}}</div>
          <div class="kv-k">IP Addresses:</div><div class="kv-v">Private: ${{item.PrivateIpAddress}} | Public: ${{item.PublicIpAddress}}</div>
          <div class="kv-k">Launched:</div><div class="kv-v">${{item.LaunchTime}}</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>Attached EBS Storage & Backups</h4>
        <div class="key-val-grid">
          <div class="kv-k">Attached Volumes:</div><div class="kv-v">${{item.AttachedVolumesCount}} (${{item.TotalAttachedStorageGB}} GB)</div>
          <div class="kv-k">Volume IDs:</div><div class="kv-v">${{item.AttachedVolumeIds || 'None'}}</div>
          <div class="kv-k">Snapshots Count:</div><div class="kv-v">${{item.AssociatedSnapshotsCount}} (${{item.TotalSnapshotsStorageGB}} GB)</div>
          <div class="kv-k">Snapshot IDs:</div><div class="kv-v">${{item.AssociatedSnapshotIds || 'None'}}</div>
          <div class="kv-k">Protection Status:</div><div class="kv-v">${{item.BackupProtectionStatus}}</div>
        </div>
      </div>
      <div class="drawer-section">
        <h4>Instance Tags</h4>
        <div style="font-family:'JetBrains Mono',monospace;font-size:11px;color:#cbd5e1;white-space:pre-wrap">${{item.Tags_Formatted || 'No tags attached'}}</div>
      </div>
    `;
  }}
  drawer.classList.add('open');
}}

function closeDrawer() {{
  document.getElementById('drawer').classList.remove('open');
}}

function exportCurrentTabCSV() {{
  let dataArray = [];
  let filename = 'export.csv';
  if (currentTab === 'snapshots') {{
    dataArray = filteredSnapshots;
    filename = 'snapshots_lineage_filtered.csv';
  }} else if (currentTab === 'orphans') {{
    dataArray = filteredOrphans;
    filename = 'orphaned_waste_filtered.csv';
  }} else if (currentTab === 'instances') {{
    dataArray = filteredInstances;
    filename = 'ec2_storage_filtered.csv';
  }} else {{
    dataArray = statsData.accounts;
    filename = 'account_rollup.csv';
  }}

  if (!dataArray || dataArray.length === 0) {{
    alert('No data to export in current view.');
    return;
  }}

  const headers = Object.keys(dataArray[0]);
  let csvContent = headers.join(",") + "\\n";
  dataArray.forEach(row => {{
    const line = headers.map(h => {{
      let val = row[h] !== undefined && row[h] !== null ? row[h] : "";
      if (typeof val === 'object') val = JSON.stringify(val);
      val = val.toString().replace(/"/g, '""');
      if (val.includes(",") || val.includes("\\n") || val.includes('"')) {{
        val = `"${{val}}"`;
      }}
      return val;
    }}).join(",");
    csvContent += line + "\\n";
  }});

  const blob = new Blob([csvContent], {{ type: 'text/csv;charset=utf-8;' }});
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = filename;
  link.click();
}}

// Initialize
renderSnapshotsTable(snapshotsData);
</script>
</body>
</html>
'''
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    size_kb = round(os.path.getsize(output_path) / 1024, 1)
    safe_print(f"  [+] Saved HTML Portal: {output_path} ({size_kb} KB)")

def main():
    args = parse_args()
    start_time = datetime.now()

    safe_print("=" * 85)
    safe_print("  AWS Multi-Organization EC2, EBS Volumes & Snapshots Lineage Auditor")
    safe_print(f"  Run Time:         {start_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    if args.input_json:
        safe_print(f"  Mode:             OFFLINE from JSON ({args.input_json})")
    elif args.current_session:
        safe_print("  Mode:             CURRENT Active Session (PowerShell)")
    else:
        safe_print(f"  Target Profiles:  {', '.join(args.profiles)}")
    safe_print(f"  Snapshot Stale:   > {args.stale_snapshot_days} days")
    safe_print("=" * 85)

    all_data = {
        "snapshots": [],
        "instances": [],
        "volumes": [],
        "unattached_volumes": [],
        "orphans_waste": [],
    }

    if args.input_json:
        if not os.path.exists(args.input_json):
            safe_print(f"[-] Input JSON not found: {args.input_json}")
            sys.exit(1)
        safe_print(f"Loading data from JSON: {args.input_json}...")
        with open(args.input_json, "r", encoding="utf-8") as f:
            all_data = json.load(f)
        safe_print(f"Loaded {len(all_data.get('snapshots', []))} snapshots, {len(all_data.get('volumes', []))} volumes, {len(all_data.get('instances', []))} EC2 instances.")
    else:
        candidate_roles = get_candidate_roles(args.role)

        profiles_to_scan = ["current"] if args.current_session else args.profiles
        for prof in profiles_to_scan:
            is_cur = (prof == "current" or args.current_session)
            org_res = scan_single_organization(prof, args, candidate_roles, is_current_session=is_cur)
            all_data["snapshots"].extend(org_res["snapshots"])
            all_data["instances"].extend(org_res["instances"])
            all_data["volumes"].extend(org_res["volumes"])
            all_data["unattached_volumes"].extend(org_res["unattached_volumes"])
            all_data["orphans_waste"].extend(org_res["orphans_waste"])

    stats = compute_portal_statistics(all_data)

    safe_print("\n" + "=" * 85)
    safe_print("  AUDIT SUMMARY & FINOPS WASTE METRICS")
    safe_print("=" * 85)
    safe_print(f"  Total Snapshots:          {stats['total_snapshots']} ({stats['total_snapshot_tb']} TB, ${stats['total_snapshot_cost_monthly']}/mo)")
    safe_print(f"  Orphaned Snapshots:       {stats['orphaned_snapshots_count']} (${stats['orphaned_snapshots_monthly_cost']}/mo Waste) -> [Source Volume/EC2 Deleted]")
    safe_print(f"  Total EBS Volumes:        {stats['total_volumes']} ({stats['total_volume_gb']} GB)")
    safe_print(f"  Unattached EBS Volumes:   {stats['unattached_volumes_count']} (${stats['unattached_volume_monthly_cost']}/mo Waste) -> [Status: available]")
    safe_print(f"  Total Monthly Waste:      ${stats['total_monthly_waste']}/month (${stats['total_annual_waste']}/year)")
    safe_print(f"  EC2 Fleet:                {stats['total_instances']} ({stats['running_instances']} Running, {stats['stopped_instances']} Stopped)")
    safe_print(f"  Unprotected EC2:          {stats['unprotected_instances']} instances have ZERO snapshot backups")
    safe_print("=" * 85)

    # 1. Save Master JSON FIRST so all collected audit data is safely secured on disk
    os.makedirs(os.path.dirname(os.path.abspath(args.output_json)), exist_ok=True)
    actual_json_path = args.output_json
    try:
        with open(actual_json_path, "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, default=str)
    except PermissionError:
        base, ext = os.path.splitext(args.output_json)
        actual_json_path = f"{base}_latest{ext}"
        safe_print(f"  [!] Lock Warning: '{args.output_json}' is locked. Saving to '{actual_json_path}'")
        with open(actual_json_path, "w", encoding="utf-8") as f:
            json.dump(all_data, f, indent=2, default=str)
    safe_print(f"  [+] Saved Master JSON: {actual_json_path} ({round(os.path.getsize(actual_json_path)/1024, 1)} KB)")

    # 2. Export CSV Reports (each handles Excel file locks gracefully)
    safe_print("\nExporting Reports...")
    actual_snap_csv = export_csv(all_data["snapshots"], args.output_snapshots_csv)
    actual_orphan_csv = export_csv(all_data["orphans_waste"], args.output_orphans_csv)
    actual_ec2_csv = export_csv(all_data["instances"], args.output_ec2_csv)
    actual_vol_csv = export_csv(all_data["volumes"], args.output_volumes_csv)
    actual_fleet_csv = None
    if args.output_ec2_csv != args.output_ec2_fleet_csv:
        actual_fleet_csv = export_csv(all_data["instances"], args.output_ec2_fleet_csv)

    # 3. Save HTML Dashboard Portal
    actual_html_path = args.output_html
    try:
        generate_html_portal(all_data, stats, actual_html_path)
    except PermissionError:
        base, ext = os.path.splitext(args.output_html)
        actual_html_path = f"{base}_latest{ext}"
        safe_print(f"  [!] Lock Warning: '{args.output_html}' is locked. Saving to '{actual_html_path}'")
        generate_html_portal(all_data, stats, actual_html_path)

    # All generated deliverables
    all_output_files = [
        actual_snap_csv,
        actual_orphan_csv,
        actual_ec2_csv,
        actual_vol_csv,
        actual_json_path,
        actual_html_path,
    ]
    if actual_fleet_csv:
        all_output_files.append(actual_fleet_csv)

    # Sync to C:\kiro-projects\Asecure if distinct from current working directory
    kiro_dir = r"C:\kiro-projects\Asecure"
    if os.path.exists(kiro_dir):
        for src in all_output_files:
            if os.path.exists(src):
                src_abs = os.path.abspath(src)
                dst_abs = os.path.abspath(os.path.join(kiro_dir, os.path.basename(src)))
                if src_abs.lower() == dst_abs.lower():
                    # Source and destination are identical in C:\kiro-projects\ASecure; skip to prevent truncation
                    continue
                try:
                    shutil.copy2(src_abs, dst_abs)
                    safe_print(f"  [+] Synced to kiro-projects: {dst_abs}")
                except Exception as e:
                    safe_print(f"  [-] Failed to sync {src} to {dst_abs}: {e}")

    # Save copy to Artifact directory if present
    artifact_dir = r"C:\Users\karu\.gemini\antigravity\brain\17ae7d5f-fd1e-482a-abac-5ec857b0af00"
    if os.path.exists(artifact_dir):
        for src in [args.output_html, args.output_orphans_csv, args.output_snapshots_csv]:
            if os.path.exists(src):
                src_abs = os.path.abspath(src)
                dst_abs = os.path.abspath(os.path.join(artifact_dir, os.path.basename(src)))
                if src_abs.lower() == dst_abs.lower():
                    continue
                try:
                    shutil.copy2(src_abs, dst_abs)
                    safe_print(f"  [+] Saved Artifact: {dst_abs}")
                except Exception as e:
                    pass

    safe_print("\n[SUCCESS] EC2, EBS Volumes & Snapshots Lineage Audit complete!")

if __name__ == "__main__":
    main()
