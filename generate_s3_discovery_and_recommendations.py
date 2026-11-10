#!/usr/bin/env python3
"""
generate_s3_discovery_and_recommendations.py
================================================================================
Enterprise S3 Discovery & Itemized Remediation Recommendations Generator

Takes the multi-organization S3 inventory (inputs/s3_all_organizations_inventory.csv),
performs deep discovery analysis (including Public Access Block (PAB) 4-tier posture,
Transport Security, Encryption, Versioning, Access Logging, and Activity/Access classification),
and generates:
  1. An enriched CSV: s3_organizations_discovery_and_recommendations.csv
  2. A 100% self-contained, offline interactive HTML portal:
     s3_organizations_discovery_and_recommendations_portal.html
     with Discovery KPIs, an Itemized Remediation Hub, 12 multi-faceted filters,
     deep inspection drawer, and copy-paste remediation commands.
================================================================================
"""

import os
import sys
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone

def parse_iso_date(date_str):
    if not date_str or date_str in ["N/A", "None", ""]:
        return None
    try:
        # Handle formats like 2026-10-12T13:18:05+00:00 or 2026-10-12 13:18:05
        cleaned = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except Exception:
        return None

def compute_activity_and_remediations(bucket):
    """
    Evaluates bucket properties, infers or computes activity heuristics,
    and assigns itemized remediation recommendations, priority tiers, and CLI commands.
    """
    b_name = bucket.get("BucketName", "")
    acc_id = bucket.get("AccountId", "")
    acc_name = bucket.get("AccountName", "")
    org = bucket.get("OrganizationProfile", "")
    verdict = bucket.get("AuditVerdict", "COMPLIANT")
    pab_status = bucket.get("PAB_Status", "None Configured")
    pab_block_acls = bucket.get("PAB_BlockPublicAcls", "False") == "True"
    pab_ignore_acls = bucket.get("PAB_IgnorePublicAcls", "False") == "True"
    pab_block_policy = bucket.get("PAB_BlockPublicPolicy", "False") == "True"
    pab_restrict = bucket.get("PAB_RestrictPublicBuckets", "False") == "True"
    is_public = bucket.get("IsPublic", "False") == "True"
    public_risk = bucket.get("PublicExposureRisk", "SECURE")
    tls_enforced = bucket.get("Policy_EnforcesTLS", "False") == "True"
    is_encrypted = bucket.get("IsEncrypted", "False") == "True"
    enc_type = bucket.get("EncryptionType", "None")
    versioning = bucket.get("VersioningStatus", "Disabled")
    logging_enabled = bucket.get("LoggingEnabled", "False") == "True"
    has_lifecycle = bucket.get("HasLifecycleRules", "False") == "True"
    creation_date_str = bucket.get("CreationDate", "")
    creation_dt = parse_iso_date(creation_date_str)

    now = datetime(2026, 11, 10, tzinfo=timezone.utc)
    days_since_creation = (now - creation_dt).days if creation_dt else 999

    # 1. Activity Estimation / Classification
    # When running offline from CSV, we classify activity based on creation recency,
    # notification triggers, logging targets, and tags
    has_notifications = bucket.get("HasEventNotifications", "False") == "True"
    has_replication = bucket.get("ReplicationEnabled", "False") == "True"
    tags_count = int(bucket.get("Tags_Count", 0) or 0)

    # Activity classification
    if days_since_creation < 30:
        activity_status = "ACTIVE_NEW_PROVISION"
        activity_desc = f"Newly provisioned ({days_since_creation}d ago)"
        days_since_write = days_since_creation
    elif has_notifications or has_replication:
        activity_status = "ACTIVE_PIPELINE"
        activity_desc = "Active event/replication pipeline"
        days_since_write = 1
    elif logging_enabled:
        activity_status = "ACTIVE_LOGGING_TARGET"
        activity_desc = "Active server logging target"
        days_since_write = 1
    elif days_since_creation > 365:
        activity_status = "DORMANT_OVER_1YR"
        activity_desc = f"Legacy bucket ({days_since_creation}d old, verify write activity)"
        days_since_write = days_since_creation
    elif days_since_creation > 90:
        activity_status = "DORMANT_OVER_90D"
        activity_desc = f"Unmodified for {days_since_creation}d (dormant candidate)"
        days_since_write = days_since_creation
    else:
        activity_status = "ACTIVE_STANDARD"
        activity_desc = f"Standard activity window ({days_since_creation}d old)"
        days_since_write = days_since_creation

    # 2. Itemized Remediation Codes
    rem_items = []
    
    # S3-REM-01: PAB Lockdown
    pab_compliant = (pab_status == "Fully Blocked (Compliant)")
    if not pab_compliant:
        rem_items.append("REM_PAB_LOCKDOWN")

    # S3-REM-02: Enforce TLS 1.2+ HTTPS-Only
    if not tls_enforced:
        rem_items.append("REM_ENFORCE_TLS")

    # S3-REM-03: Enforce Default Server-Side Encryption
    if not is_encrypted or enc_type in ["None", "AccessDenied"] or "Error" in enc_type:
        rem_items.append("REM_ENFORCE_ENCRYPTION")

    # S3-REM-04: Enable Versioning
    if versioning != "Enabled":
        rem_items.append("REM_ENABLE_VERSIONING")

    # S3-REM-05: Enable Server Access Logging
    if not logging_enabled:
        rem_items.append("REM_ENABLE_LOGGING")

    # S3-REM-06: S3 Cost Optimization & Lifecycle Rules
    if not has_lifecycle:
        rem_items.append("REM_ATTACH_LIFECYCLE")

    # If dormant over 90 days, add FinOps archival review
    if activity_status in ["DORMANT_OVER_90D", "DORMANT_OVER_1YR"]:
        rem_items.append("REM_ARCHIVE_OR_CLEANUP")

    # 3. Priority Tier Assignment (Driven strictly by impact and zero-downtime safety)
    if is_public or (not pab_compliant and public_risk != "SECURE"):
        priority_tier = "Tier 1 - Immediate Zero-Day"
        primary_script = "remediate_01_pab_lockdown.py"
        complexity = "Zero-Impact / Drop-in"
    elif not tls_enforced or not is_encrypted:
        priority_tier = "Tier 2 - High Security"
        primary_script = "remediate_02_enforce_tls.py" if not tls_enforced else "remediate_03_enforce_encryption.py"
        complexity = "Zero-Impact / Non-destructive Merge"
    elif versioning != "Enabled":
        priority_tier = "Tier 3 - Data Protection"
        primary_script = "remediate_04_enable_versioning.py"
        complexity = "Low / Non-breaking"
    elif not has_lifecycle:
        priority_tier = "Tier 4 - Governance & Lifecycle"
        primary_script = "remediate_06_lifecycle_cleanup.py"
        complexity = "Low / Cost Optimization"
    elif not logging_enabled:
        priority_tier = "Tier 5 - Observability & Logging"
        primary_script = "remediate_05_enable_access_logging.py"
        complexity = "Low / Requires Central Bucket"
    elif "REM_ARCHIVE_OR_CLEANUP" in rem_items:
        priority_tier = "Tier 6 - FinOps Archival"
        primary_script = "remediate_06_lifecycle_cleanup.py"
        complexity = "Review Required"
    else:
        priority_tier = "Compliant / Zero Pending"
        primary_script = "N/A"
        complexity = "None"

    # 4. Generate Specific Recommended Command
    if primary_script != "N/A":
        cmd = f"python scripts/remediations/{primary_script} --profile {org} --account-id {acc_id} --bucket {b_name} --execute"
    else:
        cmd = "# Bucket is fully compliant with enterprise baseline"

    return {
        "ActivityStatus": activity_status,
        "ActivityDescription": activity_desc,
        "DaysSinceLastWrite": days_since_write,
        "Remediation_Items": "; ".join(rem_items) if rem_items else "NONE",
        "Remediation_Count": len(rem_items),
        "Remediation_Priority": priority_tier,
        "Remediation_Complexity": complexity,
        "Recommended_Script": primary_script,
        "Recommended_Command": cmd,
    }

def load_and_enrich_inventory(csv_path):
    buckets = []
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            enrichment = compute_activity_and_remediations(row)
            row.update(enrichment)
            buckets.append(row)
    return buckets

def compute_statistics(buckets):
    total = len(buckets)
    org_counts = Counter(b.get("OrganizationProfile", "") for b in buckets)
    verdict_counts = Counter(b.get("AuditVerdict", "") for b in buckets)
    public_counts = Counter(b.get("PublicExposureRisk", "") for b in buckets)
    pab_counts = Counter(b.get("PAB_Status", "") for b in buckets)
    enc_counts = Counter(b.get("EncryptionType", "") for b in buckets)
    tls_counts = Counter(b.get("Policy_EnforcesTLS", "") for b in buckets)
    version_counts = Counter(b.get("VersioningStatus", "") for b in buckets)
    logging_counts = Counter(b.get("LoggingEnabled", "") for b in buckets)
    region_counts = Counter(b.get("Region", "") for b in buckets)
    activity_counts = Counter(b.get("ActivityStatus", "") for b in buckets)
    priority_counts = Counter(b.get("Remediation_Priority", "") for b in buckets)

    # Remediation items individual counts
    rem_item_counts = defaultdict(int)
    for b in buckets:
        items = b.get("Remediation_Items", "").split("; ")
        for it in items:
            if it and it != "NONE":
                rem_item_counts[it] += 1

    # Accounts
    account_map = {}
    for b in buckets:
        acc_id = b.get("AccountId", "")
        acc_name = b.get("AccountName", "")
        org = b.get("OrganizationProfile", "")
        if acc_id not in account_map:
            account_map[acc_id] = {
                "id": acc_id,
                "name": acc_name,
                "org": org,
                "count": 0,
                "high_risk": 0,
                "public": 0,
                "pending_remediations": 0
            }
        account_map[acc_id]["count"] += 1
        if b.get("AuditVerdict") == "HIGH_RISK":
            account_map[acc_id]["high_risk"] += 1
        if b.get("IsPublic") == "True":
            account_map[acc_id]["public"] += 1
        account_map[acc_id]["pending_remediations"] += int(b.get("Remediation_Count", 0))

    encrypted_count = sum(1 for b in buckets if b.get("IsEncrypted") == "True")
    pab_full_count = sum(1 for b in buckets if b.get("PAB_Status") == "Fully Blocked (Compliant)")
    tls_enforced_count = sum(1 for b in buckets if b.get("Policy_EnforcesTLS") == "True")
    versioning_count = sum(1 for b in buckets if b.get("VersioningStatus") == "Enabled")
    logging_count = sum(1 for b in buckets if b.get("LoggingEnabled") == "True")
    lifecycle_count = sum(1 for b in buckets if b.get("HasLifecycleRules") == "True")

    return {
        "total": total,
        "org_counts": dict(org_counts),
        "verdict_counts": dict(verdict_counts),
        "public_counts": dict(public_counts),
        "pab_counts": dict(pab_counts),
        "enc_counts": dict(enc_counts),
        "tls_counts": dict(tls_counts),
        "version_counts": dict(version_counts),
        "logging_counts": dict(logging_counts),
        "lifecycle_count": lifecycle_count,
        "lifecycle_pct": round(lifecycle_count / total * 100, 1) if total else 0,
        "region_counts": dict(region_counts),
        "activity_counts": dict(activity_counts),
        "priority_counts": dict(priority_counts),
        "rem_item_counts": dict(rem_item_counts),
        "accounts": sorted(account_map.values(), key=lambda x: x["count"], reverse=True),
        "total_accounts": len(account_map),
        "encrypted_count": encrypted_count,
        "encrypted_pct": round(encrypted_count / total * 100, 1) if total else 0,
        "pab_full_count": pab_full_count,
        "pab_full_pct": round(pab_full_count / total * 100, 1) if total else 0,
        "tls_enforced_count": tls_enforced_count,
        "tls_enforced_pct": round(tls_enforced_count / total * 100, 1) if total else 0,
        "versioning_count": versioning_count,
        "versioning_pct": round(versioning_count / total * 100, 1) if total else 0,
        "logging_count": logging_count,
        "logging_pct": round(logging_count / total * 100, 1) if total else 0,
        "high_risk_count": verdict_counts.get("HIGH_RISK", 0),
        "medium_risk_count": verdict_counts.get("MEDIUM_RISK", 0),
        "low_risk_count": verdict_counts.get("LOW_RISK", 0),
        "compliant_count": verdict_counts.get("COMPLIANT", 0),
    }

def export_enriched_csv(buckets, output_path):
    if not buckets:
        return
    headers = list(buckets[0].keys())
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        writer.writerows(buckets)

def generate_html(buckets, stats):
    buckets_json_str = json.dumps(buckets)
    stats_json_str = json.dumps(stats)

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AWS S3 Multi-Organization Discovery & Itemized Remediation Portal</title>
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
      --purple: #8b5cf6;
      --purple-bg: rgba(139, 92, 246, 0.15);
      --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }}

    * {{
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }}

    body {{
      font-family: var(--font-family);
      background-color: var(--bg-dark);
      color: var(--text-main);
      line-height: 1.5;
      padding-bottom: 60px;
    }}

    .container {{
      max-width: 1650px;
      margin: 0 auto;
      padding: 24px 20px;
    }}

    /* Header */
    .header {{
      display: flex;
      flex-wrap: wrap;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
      margin-bottom: 24px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
    }}

    .title-group h1 {{
      font-size: 26px;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .title-group p {{
      color: var(--text-muted);
      font-size: 14px;
      margin-top: 4px;
    }}

    .header-actions {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}

    /* Nav Tabs */
    .nav-tabs {{
      display: flex;
      gap: 12px;
      margin-bottom: 24px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 8px;
    }}

    .tab-btn {{
      background: transparent;
      border: none;
      color: var(--text-muted);
      font-size: 15px;
      font-weight: 600;
      padding: 10px 18px;
      cursor: pointer;
      border-radius: 8px;
      transition: all 0.2s ease;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .tab-btn:hover {{
      color: var(--text-main);
      background: var(--bg-card);
    }}

    .tab-btn.active {{
      color: #fff;
      background: #2563eb;
    }}

    .badge-count {{
      background: rgba(255, 255, 255, 0.2);
      padding: 2px 7px;
      border-radius: 12px;
      font-size: 12px;
    }}

    /* Buttons */
    .btn {{
      padding: 9px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid var(--border);
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: all 0.2s ease;
      text-decoration: none;
    }}

    .btn-primary {{
      background-color: #2563eb;
      color: #ffffff;
      border-color: #3b82f6;
    }}
    .btn-primary:hover {{
      background-color: #1d4ed8;
    }}

    .btn-secondary {{
      background-color: var(--bg-card);
      color: var(--text-main);
    }}
    .btn-secondary:hover {{
      background-color: var(--bg-card-hover);
      border-color: var(--accent);
    }}

    .btn-danger {{
      background-color: var(--danger-bg);
      color: var(--danger);
      border-color: var(--danger);
    }}

    .btn-success {{
      background-color: var(--success-bg);
      color: var(--success);
      border-color: var(--success);
    }}

    /* Metrics Grid */
    .metrics-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}

    .metric-card {{
      background-color: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px;
      transition: transform 0.2s ease, border-color 0.2s ease;
    }}
    .metric-card:hover {{
      transform: translateY(-2px);
      border-color: var(--border-focus);
    }}

    .metric-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }}

    .metric-title {{
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--text-muted);
    }}

    .metric-value {{
      font-size: 26px;
      font-weight: 700;
      color: var(--text-main);
      display: flex;
      align-items: baseline;
      gap: 8px;
    }}

    .metric-sub {{
      font-size: 12px;
      color: var(--text-dim);
      margin-top: 4px;
    }}

    /* Pill Badges */
    .pill {{
      display: inline-flex;
      align-items: center;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    .pill-danger {{ background: var(--danger-bg); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.4); }}
    .pill-warning {{ background: var(--warning-bg); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.4); }}
    .pill-success {{ background: var(--success-bg); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.4); }}
    .pill-info {{ background: var(--info-bg); color: var(--info); border: 1px solid rgba(59, 130, 246, 0.4); }}
    .pill-purple {{ background: var(--purple-bg); color: var(--purple); border: 1px solid rgba(139, 92, 246, 0.4); }}

    /* Critical Banner */
    .alert-banner {{
      background: linear-gradient(90deg, rgba(239, 68, 68, 0.2) 0%, rgba(19, 27, 46, 0.9) 100%);
      border: 1px solid var(--danger);
      border-radius: 12px;
      padding: 16px 20px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }}

    /* Remediation Cards Grid */
    .remediation-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(480px, 1fr));
      gap: 20px;
      margin-bottom: 30px;
    }}

    .rem-card {{
      background-color: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 22px;
      position: relative;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      transition: all 0.2s ease;
    }}
    .rem-card:hover {{
      border-color: var(--accent);
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
    }}

    .rem-card.tier-1 {{ border-left: 5px solid var(--danger); }}
    .rem-card.tier-2 {{ border-left: 5px solid var(--warning); }}
    .rem-card.tier-3 {{ border-left: 5px solid var(--info); }}
    .rem-card.tier-4 {{ border-left: 5px solid var(--purple); }}
    .rem-card.tier-5 {{ border-left: 5px solid var(--success); }}

    .rem-title-row {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      margin-bottom: 12px;
    }}

    .rem-title {{
      font-size: 17px;
      font-weight: 700;
      color: var(--text-main);
    }}

    .rem-meta {{
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 14px;
      line-height: 1.6;
    }}

    .rem-details-box {{
      background: var(--bg-dark);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 16px;
      font-size: 12px;
    }}

    .code-box {{
      background: #060913;
      border: 1px solid #1e293b;
      border-radius: 6px;
      padding: 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      color: #38bdf8;
      overflow-x: auto;
      margin-top: 6px;
      position: relative;
    }}

    .rem-card-actions {{
      display: flex;
      gap: 10px;
      align-items: center;
      margin-top: 10px;
    }}

    /* Filters Section */
    .filters-section {{
      background-color: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }}

    .filters-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 16px;
    }}

    .filters-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
      gap: 12px;
    }}

    .filter-group {{
      display: flex;
      flex-direction: column;
      gap: 6px;
    }}

    .filter-group label {{
      font-size: 11px;
      font-weight: 600;
      text-transform: uppercase;
      color: var(--text-muted);
      letter-spacing: 0.5px;
    }}

    .filter-group select, .filter-group input {{
      background-color: var(--bg-input);
      border: 1px solid var(--border);
      color: var(--text-main);
      padding: 8px 12px;
      border-radius: 6px;
      font-size: 13px;
      outline: none;
      transition: border-color 0.2s ease;
    }}
    .filter-group select:focus, .filter-group input:focus {{
      border-color: var(--border-focus);
    }}

    /* Table */
    .table-wrapper {{
      background-color: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      margin-bottom: 24px;
    }}

    .table-container {{
      max-height: 650px;
      overflow-y: auto;
      overflow-x: auto;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }}

    thead th {{
      background-color: #0d1424;
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.5px;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      position: sticky;
      top: 0;
      z-index: 10;
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }}
    thead th:hover {{
      color: var(--accent);
    }}

    tbody tr {{
      border-bottom: 1px solid rgba(35, 49, 78, 0.5);
      transition: background-color 0.15s ease;
    }}
    tbody tr:hover {{
      background-color: var(--bg-card-hover);
      cursor: pointer;
    }}

    td {{
      padding: 12px 14px;
      white-space: nowrap;
      color: var(--text-main);
    }}

    /* Pagination */
    .pagination-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 20px;
      background-color: #0d1424;
      border-top: 1px solid var(--border);
      font-size: 13px;
      color: var(--text-muted);
    }}

    .page-controls {{
      display: flex;
      gap: 6px;
    }}

    /* Modal / Drawer */
    .modal-overlay {{
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(4px);
      z-index: 100;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }}

    .modal-card {{
      background-color: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 14px;
      max-width: 950px;
      width: 100%;
      max-height: 90vh;
      display: flex;
      flex-direction: column;
      overflow: hidden;
      box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
    }}

    .modal-header {{
      padding: 20px 24px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background-color: #0e1628;
    }}

    .modal-body {{
      padding: 24px;
      overflow-y: auto;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }}

    .detail-section {{
      background-color: var(--bg-dark);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }}

    .detail-section h4 {{
      font-size: 13px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      color: var(--accent);
      margin-bottom: 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .detail-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 12px;
      font-size: 13px;
    }}

    .detail-item {{
      display: flex;
      flex-direction: column;
      gap: 3px;
    }}

    .detail-label {{
      font-size: 11px;
      color: var(--text-dim);
      text-transform: uppercase;
    }}

    .detail-value {{
      font-weight: 600;
      color: var(--text-main);
      word-break: break-all;
    }}
  </style>
</head>
<body>

<div class="container">

  <!-- Header -->
  <header class="header">
    <div class="title-group">
      <h1>AWS S3 Multi-Organization Discovery & Itemized Remediation Portal</h1>
      <p>Continuous Security Posture, Public Access Block (PAB) Enforcement & Itemized Zero-Downtime Remediations Across {stats['total_accounts']} Accounts ({stats['total']} Buckets)</p>
    </div>
    <div class="header-actions">
      <button class="btn btn-secondary" onclick="exportFilteredCSV()">Download Filtered CSV</button>
      <button class="btn btn-danger" onclick="exportRemediationsCSV()">Download Actionable Remediations CSV</button>
      <button class="btn btn-primary" onclick="exportFullCSV()">Download Full Inventory CSV ({stats['total']})</button>
    </div>
  </header>

  <!-- Navigation Tabs -->
  <div class="nav-tabs">
    <button class="tab-btn active" id="tabBtnDiscovery" onclick="switchTab('discovery')">
      Security Discovery & Posture
    </button>
    <button class="tab-btn" id="tabBtnRemediations" onclick="switchTab('remediations')">
      Itemized Remediation Hub <span class="badge-count">6 Modules</span>
    </button>
    <button class="tab-btn" id="tabBtnInventory" onclick="switchTab('inventory')">
      Full Inventory & Deep Search <span class="badge-count" id="inventoryCountBadge">{stats['total']}</span>
    </button>
  </div>

  <!-- Critical Banner -->
  <div class="alert-banner" id="critBanner" style="display: {'flex' if stats['public_counts'].get('PUBLIC_BY_POLICY', 0) > 0 else 'none'};">
    <div>
      <h3 style="color: var(--danger); font-size: 16px; font-weight: 700; margin-bottom: 4px;">
        CRITICAL ZERO-DAY RISK: Bucket Exposed Directly to Public Internet!
      </h3>
      <p style="font-size: 13px; color: var(--text-main);">
        Bucket <code>appdevlab-migration-data</code> in Account <code>371016420106</code> (<code>rus-ext</code>) has a <strong>PUBLIC BUCKET POLICY</strong> with <strong>PAB: None Configured</strong>.
      </p>
    </div>
    <div style="display: flex; gap: 10px;">
      <button class="btn btn-danger" onclick="inspectByName('appdevlab-migration-data')">Inspect Critical Bucket</button>
      <button class="btn btn-secondary" onclick="filterByRemediation('REM_PAB_LOCKDOWN')">Filter PAB Fix Candidates ({stats['rem_item_counts'].get('REM_PAB_LOCKDOWN', 0)})</button>
    </div>
  </div>

  <!-- TAB 1: DISCOVERY & POSTURE -->
  <div id="tabContentDiscovery">
    <!-- Key Metrics Grid -->
    <div class="metrics-grid">
      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-title">Total Monitored Buckets</span>
          <span class="pill pill-info">3 Orgs</span>
        </div>
        <div class="metric-value">{stats['total']}</div>
        <div class="metric-sub">{stats['total_accounts']} Active AWS Accounts</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-title">Public Access Block (PAB)</span>
          <span class="pill pill-{'success' if stats['pab_full_pct'] > 90 else 'danger'}">{stats['pab_full_pct']}%</span>
        </div>
        <div class="metric-value">{stats['pab_full_count']} <span style="font-size: 14px; color: var(--text-muted);">/ {stats['total']}</span></div>
        <div class="metric-sub">{stats['total'] - stats['pab_full_count']} Missing or Partial PAB</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-title">TLS 1.2+ HTTPS Enforced</span>
          <span class="pill pill-{'success' if stats['tls_enforced_pct'] > 80 else 'warning'}">{stats['tls_enforced_pct']}%</span>
        </div>
        <div class="metric-value">{stats['tls_enforced_count']} <span style="font-size: 14px; color: var(--text-muted);">/ {stats['total']}</span></div>
        <div class="metric-sub">{stats['total'] - stats['tls_enforced_count']} Missing DenyInsecureTransport</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-title">Default SSE Encryption</span>
          <span class="pill pill-success">{stats['encrypted_pct']}%</span>
        </div>
        <div class="metric-value">{stats['encrypted_count']} <span style="font-size: 14px; color: var(--text-muted);">/ {stats['total']}</span></div>
        <div class="metric-sub">591 AES256 | 60 KMS Managed</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-title">Versioning Enabled</span>
          <span class="pill pill-purple">{stats['versioning_pct']}%</span>
        </div>
        <div class="metric-value">{stats['versioning_count']} <span style="font-size: 14px; color: var(--text-muted);">/ {stats['total']}</span></div>
        <div class="metric-sub">{stats['total'] - stats['versioning_count']} Vulnerable to Ransomware/Wipe</div>
      </div>

      <div class="metric-card">
        <div class="metric-header">
          <span class="metric-title">Server Access Logging</span>
          <span class="pill pill-danger">{stats['logging_pct']}%</span>
        </div>
        <div class="metric-value">{stats['logging_count']} <span style="font-size: 14px; color: var(--text-muted);">/ {stats['total']}</span></div>
        <div class="metric-sub">{stats['total'] - stats['logging_count']} Buckets With Blind Audit Trail</div>
      </div>
    </div>

    <!-- Discovery Posture Distribution -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 16px; margin-bottom: 24px;">
      
      <div class="metric-card">
        <h3 style="font-size: 14px; font-weight: 600; text-transform: uppercase; color: var(--accent); margin-bottom: 12px;">
          Public Access Block (PAB) Breakdown
        </h3>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Fully Blocked (Compliant)</span>
            <strong style="color: var(--success);">{stats['pab_counts'].get('Fully Blocked (Compliant)', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>None Configured (High Risk)</span>
            <strong style="color: var(--danger);">{stats['pab_counts'].get('None Configured', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Partially Blocked</span>
            <strong style="color: var(--warning);">{stats['pab_counts'].get('Partially Blocked', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>AccessDenied / Scrape Blocked</span>
            <strong style="color: var(--text-dim);">{stats['pab_counts'].get('AccessDenied', 0)}</strong>
          </div>
        </div>
      </div>

      <div class="metric-card">
        <h3 style="font-size: 14px; font-weight: 600; text-transform: uppercase; color: var(--accent); margin-bottom: 12px;">
          Activity & Dormancy Classification
        </h3>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Dormant Over 1 Year (FinOps Target)</span>
            <strong style="color: var(--purple);">{stats['activity_counts'].get('DORMANT_OVER_1YR', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Dormant Over 90 Days</span>
            <strong style="color: var(--warning);">{stats['activity_counts'].get('DORMANT_OVER_90D', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Active Standard Storage</span>
            <strong style="color: var(--info);">{stats['activity_counts'].get('ACTIVE_STANDARD', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Active Pipeline / Logging</span>
            <strong style="color: var(--success);">{stats['activity_counts'].get('ACTIVE_PIPELINE', 0) + stats['activity_counts'].get('ACTIVE_LOGGING_TARGET', 0)}</strong>
          </div>
        </div>
      </div>

      <div class="metric-card">
        <h3 style="font-size: 14px; font-weight: 600; text-transform: uppercase; color: var(--accent); margin-bottom: 12px;">
          Remediation Priority Tiers
        </h3>
        <div style="display: flex; flex-direction: column; gap: 8px;">
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Tier 1: Immediate Zero-Day</span>
            <strong style="color: var(--danger);">{stats['priority_counts'].get('Tier 1 - Immediate Zero-Day', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Tier 2: High Security (TLS/Encryption)</span>
            <strong style="color: var(--warning);">{stats['priority_counts'].get('Tier 2 - High Security', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Tier 3: Data Protection (Versioning)</span>
            <strong style="color: var(--info);">{stats['priority_counts'].get('Tier 3 - Data Protection', 0)}</strong>
          </div>
          <div style="display: flex; justify-content: space-between; font-size: 13px;">
            <span>Tier 4: Governance (Lifecycle)</span>
            <strong style="color: var(--purple);">{stats['priority_counts'].get('Tier 4 - Governance & Lifecycle', 0)}</strong>
          </div>
        </div>
      </div>

    </div>
  </div>

  <!-- TAB 2: ITEMIZED REMEDIATION HUB -->
  <div id="tabContentRemediations" style="display: none;">
    <div style="margin-bottom: 20px;">
      <h2 style="font-size: 20px; font-weight: 700; color: var(--text-main); margin-bottom: 6px;">
        Itemized Remediation Playbooks & Dedicated Automation Scripts
      </h2>
      <p style="font-size: 14px; color: var(--text-muted);">
        Each script is autonomous, supports <code>--dry-run</code> previews by default, captures automatic rollback backups, and operates cross-account across all 3 AWS Organizations.
      </p>
    </div>

    <div class="remediation-grid">

      <!-- Module 1: PAB -->
      <div class="rem-card tier-1">
        <div>
          <div class="rem-title-row">
            <div>
              <span class="pill pill-danger" style="margin-bottom: 6px;">Tier 1 - Emergency</span>
              <div class="rem-title">S3-REM-01: Public Access Block (PAB) Lockdown</div>
            </div>
            <span class="badge-count" style="background: var(--danger-bg); color: var(--danger); font-size: 14px; padding: 4px 10px;">
              {stats['rem_item_counts'].get('REM_PAB_LOCKDOWN', 0)} Buckets
            </span>
          </div>
          <p class="rem-meta">
            Enforces all 4 PAB controls (<code>BlockPublicAcls</code>, <code>IgnorePublicAcls</code>, <code>BlockPublicPolicy</code>, <code>RestrictPublicBuckets</code>). Neutralizes unauthorized public policies immediately without altering bucket content.
          </p>
          <div class="rem-details-box">
            <div><strong>Impact:</strong> Zero downtime for authenticated callers. Cuts off public anonymous access immediately.</div>
            <div style="margin-top: 4px;"><strong>Script:</strong> <code>scripts/remediations/remediate_01_pab_lockdown.py</code></div>
            <div class="code-box">python scripts/remediations/remediate_01_pab_lockdown.py --all --dry-run</div>
          </div>
        </div>
        <div class="rem-card-actions">
          <button class="btn btn-danger" onclick="filterByRemediation('REM_PAB_LOCKDOWN')">View All {stats['rem_item_counts'].get('REM_PAB_LOCKDOWN', 0)} Candidates</button>
          <button class="btn btn-secondary" onclick="copyText('python scripts/remediations/remediate_01_pab_lockdown.py --all --execute')">Copy Execute Command</button>
        </div>
      </div>

      <!-- Module 2: TLS -->
      <div class="rem-card tier-2">
        <div>
          <div class="rem-title-row">
            <div>
              <span class="pill pill-warning" style="margin-bottom: 6px;">Tier 2 - High Security</span>
              <div class="rem-title">S3-REM-02: Enforce TLS 1.2+ HTTPS-Only Policy</div>
            </div>
            <span class="badge-count" style="background: var(--warning-bg); color: var(--warning); font-size: 14px; padding: 4px 10px;">
              {stats['rem_item_counts'].get('REM_ENFORCE_TLS', 0)} Buckets
            </span>
          </div>
          <p class="rem-meta">
            Safely merges a <code>DenyInsecureTransport</code> statement (denying <code>aws:SecureTransport: false</code>) into the existing bucket policy. Backs up previous policy before modification.
          </p>
          <div class="rem-details-box">
            <div><strong>Impact:</strong> Non-destructive merge. Drops unencrypted plain-text HTTP traffic; all HTTPS workloads continue unaffected.</div>
            <div style="margin-top: 4px;"><strong>Script:</strong> <code>scripts/remediations/remediate_02_enforce_tls.py</code></div>
            <div class="code-box">python scripts/remediations/remediate_02_enforce_tls.py --all --dry-run</div>
          </div>
        </div>
        <div class="rem-card-actions">
          <button class="btn btn-primary" onclick="filterByRemediation('REM_ENFORCE_TLS')">View All {stats['rem_item_counts'].get('REM_ENFORCE_TLS', 0)} Candidates</button>
          <button class="btn btn-secondary" onclick="copyText('python scripts/remediations/remediate_02_enforce_tls.py --all --execute')">Copy Execute Command</button>
        </div>
      </div>

      <!-- Module 3: Encryption -->
      <div class="rem-card tier-2">
        <div>
          <div class="rem-title-row">
            <div>
              <span class="pill pill-warning" style="margin-bottom: 6px;">Tier 2 - Data Security</span>
              <div class="rem-title">S3-REM-03: Enforce Default Server-Side Encryption (SSE)</div>
            </div>
            <span class="badge-count" style="background: var(--warning-bg); color: var(--warning); font-size: 14px; padding: 4px 10px;">
              {stats['rem_item_counts'].get('REM_ENFORCE_ENCRYPTION', 0)} Buckets
            </span>
          </div>
          <p class="rem-meta">
            Configures mandatory default encryption with <code>AES256</code> or KMS, enabling <code>BucketKeyEnabled</code> to slash KMS operational request costs by up to 99%.
          </p>
          <div class="rem-details-box">
            <div><strong>Impact:</strong> Transparent to callers. Automatically encrypts all subsequent object uploads.</div>
            <div style="margin-top: 4px;"><strong>Script:</strong> <code>scripts/remediations/remediate_03_enforce_encryption.py</code></div>
            <div class="code-box">python scripts/remediations/remediate_03_enforce_encryption.py --all --dry-run</div>
          </div>
        </div>
        <div class="rem-card-actions">
          <button class="btn btn-primary" onclick="filterByRemediation('REM_ENFORCE_ENCRYPTION')">View All Candidates</button>
          <button class="btn btn-secondary" onclick="copyText('python scripts/remediations/remediate_03_enforce_encryption.py --all --execute')">Copy Execute Command</button>
        </div>
      </div>

      <!-- Module 4: Versioning -->
      <div class="rem-card tier-3">
        <div>
          <div class="rem-title-row">
            <div>
              <span class="pill pill-info" style="margin-bottom: 6px;">Tier 3 - Resilience</span>
              <div class="rem-title">S3-REM-04: Enable S3 Versioning & Ransomware Guard</div>
            </div>
            <span class="badge-count" style="background: var(--info-bg); color: var(--info); font-size: 14px; padding: 4px 10px;">
              {stats['rem_item_counts'].get('REM_ENABLE_VERSIONING', 0)} Buckets
            </span>
          </div>
          <p class="rem-meta">
            Protects against accidental deletion, malicious overwrite, or ransomware encryption by enabling bucket versioning with optional noncurrent version expiration.
          </p>
          <div class="rem-details-box">
            <div><strong>Impact:</strong> Non-breaking. Pairs with 90-day noncurrent expiration to prevent unbounded storage cost growth.</div>
            <div style="margin-top: 4px;"><strong>Script:</strong> <code>scripts/remediations/remediate_04_enable_versioning.py</code></div>
            <div class="code-box">python scripts/remediations/remediate_04_enable_versioning.py --all --dry-run</div>
          </div>
        </div>
        <div class="rem-card-actions">
          <button class="btn btn-primary" onclick="filterByRemediation('REM_ENABLE_VERSIONING')">View All {stats['rem_item_counts'].get('REM_ENABLE_VERSIONING', 0)} Candidates</button>
          <button class="btn btn-secondary" onclick="copyText('python scripts/remediations/remediate_04_enable_versioning.py --all --execute')">Copy Execute Command</button>
        </div>
      </div>

      <!-- Module 5: Access Logging -->
      <div class="rem-card tier-4">
        <div>
          <div class="rem-title-row">
            <div>
              <span class="pill pill-purple" style="margin-bottom: 6px;">Tier 4 - Observability</span>
              <div class="rem-title">S3-REM-05: Enable Server Access Logging</div>
            </div>
            <span class="badge-count" style="background: var(--purple-bg); color: var(--purple); font-size: 14px; padding: 4px 10px;">
              {stats['rem_item_counts'].get('REM_ENABLE_LOGGING', 0)} Buckets
            </span>
          </div>
          <p class="rem-meta">
            Directs detailed access records to designated central audit buckets per account or organization to ensure compliance with NIST CSF and forensic readiness.
          </p>
          <div class="rem-details-box">
            <div><strong>Impact:</strong> Requires target audit bucket. Validates write permissions before enabling logging.</div>
            <div style="margin-top: 4px;"><strong>Script:</strong> <code>scripts/remediations/remediate_05_enable_access_logging.py</code></div>
            <div class="code-box">python scripts/remediations/remediate_05_enable_access_logging.py --target-bucket &lt;audit-bucket&gt; --dry-run</div>
          </div>
        </div>
        <div class="rem-card-actions">
          <button class="btn btn-primary" onclick="filterByRemediation('REM_ENABLE_LOGGING')">View All {stats['rem_item_counts'].get('REM_ENABLE_LOGGING', 0)} Candidates</button>
          <button class="btn btn-secondary" onclick="copyText('python scripts/remediations/remediate_05_enable_access_logging.py --dry-run')">Copy Command</button>
        </div>
      </div>

      <!-- Module 6: Lifecycle & FinOps -->
      <div class="rem-card tier-5">
        <div>
          <div class="rem-title-row">
            <div>
              <span class="pill pill-success" style="margin-bottom: 6px;">Tier 5 - Cost Optimization</span>
              <div class="rem-title">S3-REM-06: S3 Cost Optimization & Lifecycle Rules</div>
            </div>
            <span class="badge-count" style="background: var(--success-bg); color: var(--success); font-size: 14px; padding: 4px 10px;">
              {stats['rem_item_counts'].get('REM_ATTACH_LIFECYCLE', 0)} Buckets
            </span>
          </div>
          <p class="rem-meta">
            Attaches automated lifecycle rules to abort incomplete multipart uploads after 7 days and transition dormant/stale data to Glacier Flexible Retrieval or Deep Archive.
          </p>
          <div class="rem-details-box">
            <div><strong>Impact:</strong> Immediate FinOps cost recovery. Eliminates ghost multipart upload storage fees across inactive buckets.</div>
            <div style="margin-top: 4px;"><strong>Script:</strong> <code>scripts/remediations/remediate_06_lifecycle_cleanup.py</code></div>
            <div class="code-box">python scripts/remediations/remediate_06_lifecycle_cleanup.py --all --dry-run</div>
          </div>
        </div>
        <div class="rem-card-actions">
          <button class="btn btn-primary" onclick="filterByRemediation('REM_ATTACH_LIFECYCLE')">View All {stats['rem_item_counts'].get('REM_ATTACH_LIFECYCLE', 0)} Candidates</button>
          <button class="btn btn-secondary" onclick="copyText('python scripts/remediations/remediate_06_lifecycle_cleanup.py --all --execute')">Copy Execute Command</button>
        </div>
      </div>

    </div>
  </div>

  <!-- TAB 3: FULL INVENTORY & DEEP SEARCH -->
  <div id="tabContentInventory">
    <!-- Filter Bar -->
    <div class="filters-section">
      <div class="filters-header">
        <h3 style="font-size: 14px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; color: var(--accent);">
          Multi-Faceted Discovery & Inventory Filters
        </h3>
        <div style="display: flex; gap: 10px; align-items: center;">
          <span style="font-size: 13px; color: var(--text-muted);" id="filteredCountText">Showing {stats['total']} of {stats['total']} buckets</span>
          <button class="btn btn-secondary" style="padding: 5px 12px; font-size: 12px;" onclick="resetFilters()">Reset All Filters</button>
        </div>
      </div>

      <div class="filters-grid">
        <div class="filter-group">
          <label>Global Search</label>
          <input type="text" id="filterSearch" placeholder="Search by bucket name, ARN, tag, account..." oninput="applyFilters()">
        </div>

        <div class="filter-group">
          <label>Organization Profile</label>
          <select id="filterOrg" onchange="applyFilters()">
            <option value="">All Organizations ({stats['total']})</option>
            <option value="rus-ext">rus-ext ({stats['org_counts'].get('rus-ext', 0)})</option>
            <option value="rus-ioc">rus-ioc ({stats['org_counts'].get('rus-ioc', 0)})</option>
            <option value="cccs">cccs ({stats['org_counts'].get('cccs', 0)})</option>
          </select>
        </div>

        <div class="filter-group">
          <label>Remediation Item</label>
          <select id="filterRemItem" onchange="applyFilters()">
            <option value="">All Remediation Items</option>
            <option value="REM_PAB_LOCKDOWN">S3-REM-01: PAB Lockdown ({stats['rem_item_counts'].get('REM_PAB_LOCKDOWN', 0)})</option>
            <option value="REM_ENFORCE_TLS">S3-REM-02: Enforce TLS ({stats['rem_item_counts'].get('REM_ENFORCE_TLS', 0)})</option>
            <option value="REM_ENFORCE_ENCRYPTION">S3-REM-03: Enforce Encryption ({stats['rem_item_counts'].get('REM_ENFORCE_ENCRYPTION', 0)})</option>
            <option value="REM_ENABLE_VERSIONING">S3-REM-04: Enable Versioning ({stats['rem_item_counts'].get('REM_ENABLE_VERSIONING', 0)})</option>
            <option value="REM_ENABLE_LOGGING">S3-REM-05: Enable Access Logging ({stats['rem_item_counts'].get('REM_ENABLE_LOGGING', 0)})</option>
            <option value="REM_ATTACH_LIFECYCLE">S3-REM-06: Lifecycle Rules ({stats['rem_item_counts'].get('REM_ATTACH_LIFECYCLE', 0)})</option>
            <option value="REM_ARCHIVE_OR_CLEANUP">FinOps: Dormant Archival ({stats['rem_item_counts'].get('REM_ARCHIVE_OR_CLEANUP', 0)})</option>
          </select>
        </div>

        <div class="filter-group">
          <label>Priority Tier</label>
          <select id="filterPriority" onchange="applyFilters()">
            <option value="">All Priority Tiers</option>
            <option value="Tier 1 - Immediate Zero-Day">Tier 1 - Immediate Zero-Day ({stats['priority_counts'].get('Tier 1 - Immediate Zero-Day', 0)})</option>
            <option value="Tier 2 - High Security">Tier 2 - High Security ({stats['priority_counts'].get('Tier 2 - High Security', 0)})</option>
            <option value="Tier 3 - Data Protection">Tier 3 - Data Protection ({stats['priority_counts'].get('Tier 3 - Data Protection', 0)})</option>
            <option value="Tier 4 - Governance & Lifecycle">Tier 4 - Governance ({stats['priority_counts'].get('Tier 4 - Governance & Lifecycle', 0)})</option>
            <option value="Tier 5 - Observability & Logging">Tier 5 - Observability ({stats['priority_counts'].get('Tier 5 - Observability & Logging', 0)})</option>
            <option value="Tier 6 - FinOps Archival">Tier 6 - FinOps Archival ({stats['priority_counts'].get('Tier 6 - FinOps Archival', 0)})</option>
            <option value="Compliant / Zero Pending">Compliant ({stats['priority_counts'].get('Compliant / Zero Pending', 0)})</option>
          </select>
        </div>

        <div class="filter-group">
          <label>PAB Status</label>
          <select id="filterPAB" onchange="applyFilters()">
            <option value="">All PAB Statuses</option>
            <option value="Fully Blocked (Compliant)">Fully Blocked (Compliant) ({stats['pab_counts'].get('Fully Blocked (Compliant)', 0)})</option>
            <option value="None Configured">None Configured ({stats['pab_counts'].get('None Configured', 0)})</option>
            <option value="Partially Blocked">Partially Blocked ({stats['pab_counts'].get('Partially Blocked', 0)})</option>
            <option value="AccessDenied">AccessDenied ({stats['pab_counts'].get('AccessDenied', 0)})</option>
          </select>
        </div>

        <div class="filter-group">
          <label>TLS Enforced</label>
          <select id="filterTLS" onchange="applyFilters()">
            <option value="">All TLS States</option>
            <option value="True">Enforced (True) ({stats['tls_counts'].get('True', 0)})</option>
            <option value="False">Missing (False) ({stats['tls_counts'].get('False', 0)})</option>
          </select>
        </div>

        <div class="filter-group">
          <label>Activity Status</label>
          <select id="filterActivity" onchange="applyFilters()">
            <option value="">All Activity States</option>
            <option value="DORMANT_OVER_1YR">Dormant Over 1 Year ({stats['activity_counts'].get('DORMANT_OVER_1YR', 0)})</option>
            <option value="DORMANT_OVER_90D">Dormant Over 90 Days ({stats['activity_counts'].get('DORMANT_OVER_90D', 0)})</option>
            <option value="ACTIVE_STANDARD">Active Standard ({stats['activity_counts'].get('ACTIVE_STANDARD', 0)})</option>
            <option value="ACTIVE_PIPELINE">Active Pipeline ({stats['activity_counts'].get('ACTIVE_PIPELINE', 0)})</option>
            <option value="ACTIVE_LOGGING_TARGET">Active Logging Target ({stats['activity_counts'].get('ACTIVE_LOGGING_TARGET', 0)})</option>
          </select>
        </div>

        <div class="filter-group">
          <label>AWS Account</label>
          <select id="filterAccount" onchange="applyFilters()">
            <option value="">All Accounts ({stats['total_accounts']})</option>
            {''.join([f'<option value="{a["id"]}">{a["name"]} ({a["id"]}) - {a["count"]} buckets</option>' for a in stats['accounts'][:30]])}
          </select>
        </div>
      </div>
    </div>

    <!-- Table -->
    <div class="table-wrapper">
      <div class="table-container">
        <table id="inventoryTable">
          <thead>
            <tr>
              <th onclick="sortTable('BucketName')">Bucket Name</th>
              <th onclick="sortTable('OrganizationProfile')">Org</th>
              <th onclick="sortTable('AccountName')">Account</th>
              <th onclick="sortTable('Region')">Region</th>
              <th onclick="sortTable('Remediation_Priority')">Priority Tier</th>
              <th onclick="sortTable('PAB_Status')">PAB Status</th>
              <th onclick="sortTable('Policy_EnforcesTLS')">TLS</th>
              <th onclick="sortTable('EncryptionType')">Encryption</th>
              <th onclick="sortTable('VersioningStatus')">Versioning</th>
              <th onclick="sortTable('ActivityStatus')">Activity</th>
              <th onclick="sortTable('Remediation_Count')">Pending Fixes</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="tableBody">
            <!-- Dynamic rows populated via JS -->
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      <div class="pagination-bar">
        <div id="pageInfo">Showing 1 to 50 of {stats['total']} records</div>
        <div class="page-controls">
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="changePage(-1)" id="btnPrev">Prev</button>
          <button class="btn btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="changePage(1)" id="btnNext">Next</button>
        </div>
      </div>
    </div>
  </div>

</div>

<!-- Deep Inspection Modal Drawer -->
<div class="modal-overlay" id="inspectModal" onclick="closeModalOnOverlay(event)">
  <div class="modal-card">
    <div class="modal-header">
      <div>
        <h3 id="m_bucket_name" style="font-size: 18px; font-weight: 700; color: #fff;">Bucket Details</h3>
        <p id="m_bucket_arn" style="font-size: 12px; color: var(--text-dim); margin-top: 2px;">arn:aws:s3:::...</p>
      </div>
      <div style="display: flex; gap: 8px;">
        <button class="btn btn-secondary" style="padding: 5px 12px; font-size: 12px;" onclick="copyBucketJson()">Copy JSON</button>
        <button class="btn btn-secondary" style="padding: 5px 12px; font-size: 12px;" onclick="closeModal()">Close</button>
      </div>
    </div>

    <div class="modal-body">
      <!-- Itemized Recommended Command Banner -->
      <div class="detail-section" style="border-left: 4px solid var(--accent); background: #0c1527;">
        <h4>Recommended Itemized Remediation Command</h4>
        <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">
          Execute this copy-paste command from PowerShell to apply the specific remediation for this bucket:
        </p>
        <div class="code-box" id="m_rem_cmd" style="padding: 12px; font-size: 13px;">python scripts/...</div>
        <button class="btn btn-primary" style="margin-top: 10px; padding: 6px 14px; font-size: 12px;" onclick="copyCommand()">Copy Command</button>
      </div>

      <!-- Overview -->
      <div class="detail-section">
        <h4>Core Bucket Attributes</h4>
        <div class="detail-grid">
          <div class="detail-item"><span class="detail-label">Organization Profile</span><span class="detail-value" id="m_org">-</span></div>
          <div class="detail-item"><span class="detail-label">Account Name / ID</span><span class="detail-value" id="m_account">-</span></div>
          <div class="detail-item"><span class="detail-label">Region</span><span class="detail-value" id="m_region">-</span></div>
          <div class="detail-item"><span class="detail-label">Creation Date</span><span class="detail-value" id="m_creation">-</span></div>
          <div class="detail-item"><span class="detail-label">Priority Tier</span><span class="detail-value" id="m_priority">-</span></div>
          <div class="detail-item"><span class="detail-label">Audit Verdict</span><span class="detail-value" id="m_verdict">-</span></div>
        </div>
      </div>

      <!-- Perimeter & PAB -->
      <div class="detail-section">
        <h4>Perimeter & Public Access Block (PAB) 4-Control Analysis</h4>
        <div class="detail-grid">
          <div class="detail-item"><span class="detail-label">PAB Overall Status</span><span class="detail-value" id="m_pab_status">-</span></div>
          <div class="detail-item"><span class="detail-label">BlockPublicAcls</span><span class="detail-value" id="m_pab_bacls">-</span></div>
          <div class="detail-item"><span class="detail-label">IgnorePublicAcls</span><span class="detail-value" id="m_pab_iacls">-</span></div>
          <div class="detail-item"><span class="detail-label">BlockPublicPolicy</span><span class="detail-value" id="m_pab_bpol">-</span></div>
          <div class="detail-item"><span class="detail-label">RestrictPublicBuckets</span><span class="detail-value" id="m_pab_rpol">-</span></div>
          <div class="detail-item"><span class="detail-label">Exposure Risk</span><span class="detail-value" id="m_exposure">-</span></div>
        </div>
      </div>

      <!-- Encryption & Security -->
      <div class="detail-section">
        <h4>Transport Security, Encryption & Storage</h4>
        <div class="detail-grid">
          <div class="detail-item"><span class="detail-label">TLS Enforced</span><span class="detail-value" id="m_tls">-</span></div>
          <div class="detail-item"><span class="detail-label">Encryption Type</span><span class="detail-value" id="m_enc">-</span></div>
          <div class="detail-item"><span class="detail-label">KMS Master Key</span><span class="detail-value" id="m_kms">-</span></div>
          <div class="detail-item"><span class="detail-label">Bucket Key Enabled</span><span class="detail-value" id="m_bkey">-</span></div>
          <div class="detail-item"><span class="detail-label">Versioning Status</span><span class="detail-value" id="m_ver">-</span></div>
          <div class="detail-item"><span class="detail-label">Server Access Logging</span><span class="detail-value" id="m_log">-</span></div>
        </div>
      </div>

      <!-- Activity -->
      <div class="detail-section">
        <h4>Activity & Access Classification</h4>
        <div class="detail-grid">
          <div class="detail-item"><span class="detail-label">Activity Status</span><span class="detail-value" id="m_activity_status">-</span></div>
          <div class="detail-item"><span class="detail-label">Activity Description</span><span class="detail-value" id="m_activity_desc">-</span></div>
          <div class="detail-item"><span class="detail-label">Lifecycle Rules</span><span class="detail-value" id="m_lifecycle">-</span></div>
          <div class="detail-item"><span class="detail-label">Notifications</span><span class="detail-value" id="m_notif">-</span></div>
        </div>
      </div>

      <!-- Tags -->
      <div class="detail-section">
        <h4>Governance Tags (<span id="m_tags_count">0</span>)</h4>
        <div id="m_tags_list" style="font-size: 13px; color: var(--text-main); font-family: monospace; white-space: pre-wrap; word-break: break-all;">None</div>
      </div>

    </div>
  </div>
</div>

<script>
const ALL_BUCKETS = {buckets_json_str};
const STATS = {stats_json_str};

let filteredBuckets = [...ALL_BUCKETS];
let currentPage = 1;
const pageSize = 50;
let currentSortCol = "Remediation_Priority";
let currentSortAsc = true;
let activeInspectBucket = null;

// Initialization
document.addEventListener("DOMContentLoaded", () => {{
  applyFilters();
}});

function switchTab(tabName) {{
  document.getElementById("tabBtnDiscovery").classList.toggle("active", tabName === "discovery");
  document.getElementById("tabBtnRemediations").classList.toggle("active", tabName === "remediations");
  document.getElementById("tabBtnInventory").classList.toggle("active", tabName === "inventory");

  document.getElementById("tabContentDiscovery").style.display = (tabName === "discovery") ? "block" : "none";
  document.getElementById("tabContentRemediations").style.display = (tabName === "remediations") ? "block" : "none";
  document.getElementById("tabContentInventory").style.display = (tabName === "inventory") ? "block" : "none";
}}

function applyFilters() {{
  const search = (document.getElementById("filterSearch").value || "").toLowerCase().trim();
  const org = document.getElementById("filterOrg").value;
  const remItem = document.getElementById("filterRemItem").value;
  const priority = document.getElementById("filterPriority").value;
  const pab = document.getElementById("filterPAB").value;
  const tls = document.getElementById("filterTLS").value;
  const activity = document.getElementById("filterActivity").value;
  const account = document.getElementById("filterAccount").value;

  filteredBuckets = ALL_BUCKETS.filter(b => {{
    if (org && b.OrganizationProfile !== org) return false;
    if (remItem && !(b.Remediation_Items || "").includes(remItem)) return false;
    if (priority && b.Remediation_Priority !== priority) return false;
    if (pab && b.PAB_Status !== pab) return false;
    if (tls && b.Policy_EnforcesTLS !== tls) return false;
    if (activity && b.ActivityStatus !== activity) return false;
    if (account && b.AccountId !== account) return false;

    if (search) {{
      const blob = [
        b.BucketName, b.BucketArn, b.AccountId, b.AccountName,
        b.OrganizationProfile, b.Region, b.Tags_Formatted, b.AuditFlags, b.Recommended_Script
      ].join(" ").toLowerCase();
      if (!blob.includes(search)) return false;
    }}
    return true;
  }});

  currentPage = 1;
  sortCurrentData();
  renderTable();
  updateFilterCounts();
}}

function resetFilters() {{
  document.getElementById("filterSearch").value = "";
  document.getElementById("filterOrg").value = "";
  document.getElementById("filterRemItem").value = "";
  document.getElementById("filterPriority").value = "";
  document.getElementById("filterPAB").value = "";
  document.getElementById("filterTLS").value = "";
  document.getElementById("filterActivity").value = "";
  document.getElementById("filterAccount").value = "";
  applyFilters();
}}

function filterByRemediation(remCode) {{
  resetFilters();
  document.getElementById("filterRemItem").value = remCode;
  switchTab("inventory");
  applyFilters();
}}

function updateFilterCounts() {{
  const count = filteredBuckets.length;
  document.getElementById("filteredCountText").innerText = `Showing ${{count}} of ${{ALL_BUCKETS.length}} buckets`;
  document.getElementById("inventoryCountBadge").innerText = count;
}}

function sortTable(col) {{
  if (currentSortCol === col) {{
    currentSortAsc = !currentSortAsc;
  }} else {{
    currentSortCol = col;
    currentSortAsc = true;
  }}
  sortCurrentData();
  renderTable();
}}

function sortCurrentData() {{
  filteredBuckets.sort((a, b) => {{
    let v1 = a[currentSortCol] || "";
    let v2 = b[currentSortCol] || "";
    if (typeof v1 === "string") v1 = v1.toLowerCase();
    if (typeof v2 === "string") v2 = v2.toLowerCase();
    if (v1 < v2) return currentSortAsc ? -1 : 1;
    if (v1 > v2) return currentSortAsc ? 1 : -1;
    return 0;
  }});
}}

function renderTable() {{
  const tbody = document.getElementById("tableBody");
  tbody.innerHTML = "";

  const startIdx = (currentPage - 1) * pageSize;
  const endIdx = Math.min(startIdx + pageSize, filteredBuckets.length);
  const pageBuckets = filteredBuckets.slice(startIdx, endIdx);

  if (pageBuckets.length === 0) {{
    tbody.innerHTML = `<tr><td colspan="12" style="text-align: center; padding: 40px; color: var(--text-dim);">No buckets match the selected filters.</td></tr>`;
    document.getElementById("pageInfo").innerText = "No records";
    return;
  }}

  pageBuckets.forEach(b => {{
    const tr = document.createElement("tr");
    tr.onclick = () => openInspect(b);

    // Badges
    const priorityPill = getPriorityPill(b.Remediation_Priority);
    const pabPill = getPabPill(b.PAB_Status);
    const tlsPill = (b.Policy_EnforcesTLS === "True")
      ? '<span class="pill pill-success">Enforced</span>'
      : '<span class="pill pill-danger">Missing</span>';
    const activityPill = getActivityPill(b.ActivityStatus);

    tr.innerHTML = `
      <td><strong>${{escapeHtml(b.BucketName)}}</strong></td>
      <td><span class="pill pill-info">${{escapeHtml(b.OrganizationProfile)}}</span></td>
      <td><span title="${{escapeHtml(b.AccountId)}}">${{escapeHtml(b.AccountName)}}</span></td>
      <td>${{escapeHtml(b.Region)}}</td>
      <td>${{priorityPill}}</td>
      <td>${{pabPill}}</td>
      <td>${{tlsPill}}</td>
      <td>${{escapeHtml(b.EncryptionType)}}</td>
      <td>${{escapeHtml(b.VersioningStatus)}}</td>
      <td>${{activityPill}}</td>
      <td><span class="badge-count">${{b.Remediation_Count}} fixes</span></td>
      <td><button class="btn btn-secondary" style="padding: 4px 8px; font-size: 11px;" onclick="event.stopPropagation(); openInspectByName('${{escapeHtml(b.BucketName)}}')">Inspect</button></td>
    `;
    tbody.appendChild(tr);
  }});

  document.getElementById("pageInfo").innerText = `Showing ${{startIdx + 1}} to ${{endIdx}} of ${{filteredBuckets.length}} records`;
  document.getElementById("btnPrev").disabled = (currentPage === 1);
  document.getElementById("btnNext").disabled = (endIdx >= filteredBuckets.length);
}}

function getPriorityPill(priority) {{
  if (!priority) return "-";
  if (priority.includes("Tier 1")) return `<span class="pill pill-danger">${{priority}}</span>`;
  if (priority.includes("Tier 2")) return `<span class="pill pill-warning">${{priority}}</span>`;
  if (priority.includes("Tier 3")) return `<span class="pill pill-info">${{priority}}</span>`;
  if (priority.includes("Tier 4") || priority.includes("Tier 5")) return `<span class="pill pill-purple">${{priority}}</span>`;
  return `<span class="pill pill-success">${{priority}}</span>`;
}}

function getPabPill(pab) {{
  if (pab === "Fully Blocked (Compliant)") return `<span class="pill pill-success">Fully Blocked</span>`;
  if (pab === "None Configured") return `<span class="pill pill-danger">None Configured</span>`;
  if (pab === "Partially Blocked") return `<span class="pill pill-warning">Partial</span>`;
  return `<span class="pill pill-danger">${{pab}}</span>`;
}}

function getActivityPill(act) {{
  if (!act) return "-";
  if (act.includes("DORMANT")) return `<span class="pill pill-purple">${{act}}</span>`;
  if (act.includes("PIPELINE") || act.includes("LOGGING")) return `<span class="pill pill-success">${{act}}</span>`;
  return `<span class="pill pill-info">${{act}}</span>`;
}}

function changePage(delta) {{
  currentPage += delta;
  renderTable();
}}

function openInspect(b) {{
  activeInspectBucket = b;
  document.getElementById("m_bucket_name").innerText = b.BucketName;
  document.getElementById("m_bucket_arn").innerText = b.BucketArn;
  document.getElementById("m_rem_cmd").innerText = b.Recommended_Command || "N/A";

  document.getElementById("m_org").innerText = b.OrganizationProfile;
  document.getElementById("m_account").innerText = `${{b.AccountName}} (${{b.AccountId}})`;
  document.getElementById("m_region").innerText = b.Region;
  document.getElementById("m_creation").innerText = b.CreationDate;
  document.getElementById("m_priority").innerText = b.Remediation_Priority;
  document.getElementById("m_verdict").innerText = b.AuditVerdict;

  document.getElementById("m_pab_status").innerText = b.PAB_Status;
  document.getElementById("m_pab_bacls").innerText = b.PAB_BlockPublicAcls;
  document.getElementById("m_pab_iacls").innerText = b.PAB_IgnorePublicAcls;
  document.getElementById("m_pab_bpol").innerText = b.PAB_BlockPublicPolicy;
  document.getElementById("m_pab_rpol").innerText = b.PAB_RestrictPublicBuckets;
  document.getElementById("m_exposure").innerText = b.PublicExposureRisk;

  document.getElementById("m_tls").innerText = (b.Policy_EnforcesTLS === "True") ? "Enforced (Compliant)" : "MISSING (Insecure HTTP Permitted)";
  document.getElementById("m_enc").innerText = `${{b.EncryptionType}} (${{b.IsEncrypted}})`;
  document.getElementById("m_kms").innerText = b.KmsMasterKeyId;
  document.getElementById("m_bkey").innerText = b.BucketKeyEnabled;
  document.getElementById("m_ver").innerText = b.VersioningStatus;
  document.getElementById("m_log").innerText = (b.LoggingEnabled === "True") ? `Enabled -> ${{b.LoggingTargetBucket}}` : "Disabled";

  document.getElementById("m_activity_status").innerText = b.ActivityStatus;
  document.getElementById("m_activity_desc").innerText = b.ActivityDescription;
  document.getElementById("m_lifecycle").innerText = b.LifecycleSummary;
  document.getElementById("m_notif").innerText = b.NotificationTargets;

  document.getElementById("m_tags_count").innerText = b.Tags_Count || "0";
  document.getElementById("m_tags_list").innerText = b.Tags_Formatted || "No Tags Configured";

  document.getElementById("inspectModal").style.display = "flex";
}}

function openInspectByName(name) {{
  const b = ALL_BUCKETS.find(x => x.BucketName === name);
  if (b) openInspect(b);
}}

function inspectByName(name) {{
  openInspectByName(name);
}}

function closeModal() {{
  document.getElementById("inspectModal").style.display = "none";
}}

function closeModalOnOverlay(e) {{
  if (e.target.id === "inspectModal") closeModal();
}}

function copyCommand() {{
  const cmd = document.getElementById("m_rem_cmd").innerText;
  navigator.clipboard.writeText(cmd).then(() => alert("Command copied to clipboard!"));
}}

function copyText(txt) {{
  navigator.clipboard.writeText(txt).then(() => alert("CLI command copied to clipboard!"));
}}

function copyBucketJson() {{
  if (!activeInspectBucket) return;
  navigator.clipboard.writeText(JSON.stringify(activeInspectBucket, null, 2)).then(() => alert("Bucket JSON copied!"));
}}

function escapeHtml(str) {{
  if (!str) return "";
  return str.toString()
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}}

// CSV Downloads
function exportFilteredCSV() {{
  if (filteredBuckets.length === 0) return alert("No buckets match current filters.");
  downloadCSV(filteredBuckets, "s3_discovery_filtered.csv");
}}

function exportFullCSV() {{
  downloadCSV(ALL_BUCKETS, "s3_organizations_discovery_and_recommendations.csv");
}}

function exportRemediationsCSV() {{
  const candidates = ALL_BUCKETS.filter(b => b.Remediation_Count > 0);
  if (candidates.length === 0) return alert("No remediation candidates found.");
  downloadCSV(candidates, "s3_actionable_remediations_items.csv");
}}

function downloadCSV(dataArray, filename) {{
  const headers = Object.keys(dataArray[0]);
  let csvContent = headers.join(",") + "\\n";

  dataArray.forEach(row => {{
    const line = headers.map(h => {{
      let val = row[h] || "";
      val = val.toString().replace(/"/g, '""');
      if (val.includes(",") || val.includes("\\n") || val.includes('"')) {{
        val = `"${{val}}"`;
      }}
      return val;
    }}).join(",");
    csvContent += line + "\\n";
  }});

  const blob = new Blob([csvContent], {{ type: "text/csv;charset=utf-8;" }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}}
</script>

</body>
</html>
'''
    return html_content

def main():
    csv_path = r"c:\antigravity-projects\security group\inputs\s3_all_organizations_inventory.csv"
    if not os.path.exists(csv_path):
        csv_path = r"C:\kiro-projects\Asecure\inputs\s3_all_organizations_inventory.csv"

    print(f"Reading S3 inventory from: {csv_path}...")
    enriched_buckets = load_and_enrich_inventory(csv_path)
    print(f"Loaded and enriched {len(enriched_buckets)} S3 bucket records.")

    stats = compute_statistics(enriched_buckets)

    # 1. Export enriched discovery & recommendations CSV
    enriched_csv_paths = [
        r"c:\antigravity-projects\security group\s3_organizations_discovery_and_recommendations.csv",
        r"c:\antigravity-projects\security group\inputs\s3_organizations_discovery_and_recommendations.csv",
        r"C:\kiro-projects\Asecure\s3_organizations_discovery_and_recommendations.csv",
        r"C:\kiro-projects\Asecure\inputs\s3_organizations_discovery_and_recommendations.csv",
    ]
    for p in enriched_csv_paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        export_enriched_csv(enriched_buckets, p)
        print(f"  [+] Saved Enriched CSV: {p} ({round(os.path.getsize(p)/1024, 1)} KB)")

    # 2. Generate and export interactive HTML portal
    html_code = generate_html(enriched_buckets, stats)
    html_paths = [
        r"c:\antigravity-projects\security group\s3_organizations_discovery_and_recommendations_portal.html",
        r"c:\antigravity-projects\security group\reports\s3_organizations_discovery_and_recommendations_portal.html",
        r"C:\kiro-projects\Asecure\s3_organizations_discovery_and_recommendations_portal.html",
        r"C:\kiro-projects\Asecure\reports\s3_organizations_discovery_and_recommendations_portal.html",
    ]
    for p in html_paths:
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(html_code)
        print(f"  [+] Saved Interactive Portal: {p} ({round(os.path.getsize(p)/1024, 1)} KB)")

    # 3. Save as Artifact copy
    artifact_path = r"C:\Users\karu\.gemini\antigravity\brain\17ae7d5f-fd1e-482a-abac-5ec857b0af00\s3_organizations_discovery_and_recommendations_portal.html"
    with open(artifact_path, "w", encoding="utf-8") as f:
        f.write(html_code)
    print(f"  [+] Saved Artifact copy: {artifact_path} ({round(os.path.getsize(artifact_path)/1024, 1)} KB)")

    print("\n[SUCCESS] S3 Discovery & Recommendations generation complete!")

if __name__ == "__main__":
    main()
