#!/usr/bin/env python3
"""
Generator for Enterprise Multi-Organization S3 Security Posture & Inventory Portal
Reads inputs/s3_all_organizations_inventory.csv and compiles a 100% self-contained,
offline-compatible, searchable, filterable HTML portal with dynamic CSV exports.
"""

import os
import sys
import csv
import json
from collections import Counter, defaultdict

def load_data(csv_path):
    buckets = []
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
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
                "public": 0
            }
        account_map[acc_id]["count"] += 1
        if b.get("AuditVerdict") == "HIGH_RISK":
            account_map[acc_id]["high_risk"] += 1
        if b.get("IsPublic") == "True":
            account_map[acc_id]["public"] += 1

    encrypted_count = sum(1 for b in buckets if b.get("IsEncrypted") == "True")
    pab_full_count = sum(1 for b in buckets if b.get("PAB_Status") == "Fully Blocked (Compliant)")
    tls_enforced_count = sum(1 for b in buckets if b.get("Policy_EnforcesTLS") == "True")
    versioning_count = sum(1 for b in buckets if b.get("VersioningStatus") == "Enabled")
    logging_count = sum(1 for b in buckets if b.get("LoggingEnabled") == "True")

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
        "region_counts": dict(region_counts),
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

def generate_html(buckets, stats):
    # Prepare JSON serializable bucket list
    buckets_json_str = json.dumps(buckets)
    stats_json_str = json.dumps(stats)

    html_content = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AWS S3 Multi-Organization Security Posture & Inventory Portal</title>
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

    /* Container */
    .container {{
      max-width: 1600px;
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
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }}

    .header-left {{
      display: flex;
      align-items: center;
      gap: 16px;
    }}

    .logo-badge {{
      width: 52px;
      height: 52px;
      background: linear-gradient(135deg, #2563eb, #0284c7);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-weight: 800;
      font-size: 24px;
      box-shadow: 0 4px 14px rgba(37, 99, 235, 0.35);
    }}

    .header-title h1 {{
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.02em;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .header-title p {{
      color: var(--text-muted);
      font-size: 14px;
      margin-top: 2px;
    }}

    .header-actions {{
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}

    .btn {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 9px 16px;
      border-radius: 8px;
      font-size: 13.5px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s ease;
      border: 1px solid transparent;
      text-decoration: none;
    }}

    .btn-primary {{
      background: #2563eb;
      color: #fff;
    }}
    .btn-primary:hover {{
      background: #1d4ed8;
      box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
    }}

    .btn-secondary {{
      background: var(--bg-card);
      border-color: var(--border);
      color: var(--text-main);
    }}
    .btn-secondary:hover {{
      background: var(--bg-card-hover);
      border-color: var(--text-dim);
    }}

    .btn-danger {{
      background: var(--danger-bg);
      border-color: var(--danger);
      color: #fca5a5;
    }}
    .btn-danger:hover {{
      background: rgba(239, 68, 68, 0.25);
    }}

    /* Critical Alert Banner */
    .critical-banner {{
      background: linear-gradient(90deg, rgba(239, 68, 68, 0.18) 0%, rgba(220, 38, 38, 0.08) 100%);
      border: 1px solid rgba(239, 68, 68, 0.4);
      border-left: 5px solid var(--danger);
      border-radius: 10px;
      padding: 16px 20px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }}

    .critical-content {{
      display: flex;
      align-items: center;
      gap: 14px;
    }}

    .critical-icon {{
      width: 38px;
      height: 38px;
      border-radius: 50%;
      background: var(--danger);
      display: flex;
      align-items: center;
      justify-content: center;
      color: #fff;
      font-size: 20px;
      font-weight: bold;
      flex-shrink: 0;
      animation: pulse-ring 2s infinite;
    }}

    @keyframes pulse-ring {{
      0% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.6); }}
      70% {{ box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }}
      100% {{ box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }}
    }}

    .critical-text h3 {{
      font-size: 15px;
      font-weight: 700;
      color: #fca5a5;
    }}
    .critical-text p {{
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 2px;
    }}

    /* Executive KPI Grid */
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}

    .kpi-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 18px 20px;
      position: relative;
      overflow: hidden;
      transition: transform 0.2s, border-color 0.2s;
    }}
    .kpi-card:hover {{
      transform: translateY(-2px);
      border-color: #3b82f6;
    }}

    .kpi-card::before {{
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
    }}
    .kpi-total::before {{ background: #38bdf8; }}
    .kpi-high::before {{ background: var(--danger); }}
    .kpi-medium::before {{ background: var(--warning); }}
    .kpi-low::before {{ background: var(--info); }}
    .kpi-compliant::before {{ background: var(--success); }}

    .kpi-label {{
      font-size: 12.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--text-dim);
      margin-bottom: 6px;
    }}

    .kpi-value-row {{
      display: flex;
      align-items: baseline;
      gap: 8px;
    }}

    .kpi-value {{
      font-size: 30px;
      font-weight: 800;
      color: #fff;
      line-height: 1.1;
    }}

    .kpi-subtext {{
      font-size: 13px;
      color: var(--text-muted);
    }}

    .kpi-pct-badge {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 700;
      margin-left: auto;
    }}

    /* Secondary Posture Strip */
    .posture-strip {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}

    .posture-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px 18px;
    }}

    .posture-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
      font-size: 13px;
      font-weight: 600;
    }}

    .progress-bar-bg {{
      background: #1e293b;
      height: 8px;
      border-radius: 4px;
      overflow: hidden;
      margin-bottom: 6px;
    }}

    .progress-bar-fill {{
      height: 100%;
      border-radius: 4px;
      transition: width 0.6s ease;
    }}

    .posture-meta {{
      display: flex;
      justify-content: space-between;
      font-size: 11.5px;
      color: var(--text-dim);
    }}

    /* Visual Dashboard Charts Section */
    .charts-row {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
      margin-bottom: 24px;
    }}

    @media (max-width: 900px) {{
      .charts-row {{
        grid-template-columns: 1fr;
      }}
    }}

    .chart-box {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
    }}

    .chart-title {{
      font-size: 14.5px;
      font-weight: 700;
      margin-bottom: 16px;
      color: var(--text-main);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }}

    /* Filter Toolbar */
    .filter-section {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 24px;
    }}

    .filter-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-top: 14px;
    }}

    .search-row {{
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
    }}

    .search-input-wrap {{
      flex: 1;
      min-width: 280px;
      position: relative;
    }}

    .search-input {{
      width: 100%;
      padding: 10px 14px 10px 38px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 8px;
      color: #fff;
      font-size: 14px;
      outline: none;
      transition: border-color 0.2s;
    }}
    .search-input:focus {{
      border-color: var(--border-focus);
      box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.25);
    }}

    .search-icon {{
      position: absolute;
      left: 12px;
      top: 50%;
      transform: translateY(-50%);
      color: var(--text-dim);
      pointer-events: none;
    }}

    .filter-group {{
      display: flex;
      flex-direction: column;
      gap: 4px;
    }}

    .filter-label {{
      font-size: 11.5px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      color: var(--text-dim);
    }}

    .select-input {{
      width: 100%;
      padding: 8px 10px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-main);
      font-size: 13px;
      outline: none;
      cursor: pointer;
    }}
    .select-input:focus {{
      border-color: var(--border-focus);
    }}

    .filter-meta-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 16px;
      padding-top: 14px;
      border-top: 1px solid rgba(255, 255, 255, 0.05);
      flex-wrap: wrap;
      gap: 12px;
    }}

    .results-count {{
      font-size: 13.5px;
      font-weight: 600;
      color: var(--accent);
    }}

    /* Table Container */
    .table-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
    }}

    .table-wrapper {{
      width: 100%;
      overflow-x: auto;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }}

    thead th {{
      background: #0e1526;
      color: var(--text-muted);
      font-weight: 600;
      font-size: 11.5px;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      cursor: pointer;
      user-select: none;
      white-space: nowrap;
    }}
    thead th:hover {{
      color: #fff;
    }}

    tbody tr {{
      border-bottom: 1px solid var(--border);
      transition: background 0.15s;
    }}
    tbody tr:hover {{
      background: var(--bg-card-hover);
    }}

    tbody td {{
      padding: 12px 14px;
      vertical-align: middle;
      color: var(--text-main);
    }}

    .bucket-name-cell {{
      font-weight: 600;
      color: #fff;
      display: flex;
      flex-direction: column;
      gap: 2px;
    }}
    .bucket-arn {{
      font-size: 11px;
      color: var(--text-dim);
      font-family: monospace;
      word-break: break-all;
    }}

    /* Badges */
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 11.5px;
      font-weight: 700;
      white-space: nowrap;
    }}

    .badge-high {{
      background: var(--danger-bg);
      color: #fca5a5;
      border: 1px solid var(--danger);
    }}
    .badge-medium {{
      background: var(--warning-bg);
      color: #fde047;
      border: 1px solid var(--warning);
    }}
    .badge-low {{
      background: var(--info-bg);
      color: #93c5fd;
      border: 1px solid var(--info);
    }}
    .badge-compliant {{
      background: var(--success-bg);
      color: #6ee7b7;
      border: 1px solid var(--success);
    }}

    .badge-pill {{
      border-radius: 9999px;
    }}

    .badge-green {{
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
    }}
    .badge-red {{
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
    }}
    .badge-yellow {{
      background: rgba(245, 158, 11, 0.15);
      color: #fbbf24;
    }}
    .badge-gray {{
      background: rgba(148, 163, 184, 0.15);
      color: #94a3b8;
    }}

    .btn-inspect {{
      padding: 5px 10px;
      font-size: 12px;
      border-radius: 6px;
      background: #1e293b;
      border: 1px solid var(--border);
      color: #38bdf8;
      cursor: pointer;
      font-weight: 600;
      transition: all 0.2s;
    }}
    .btn-inspect:hover {{
      background: #0284c7;
      color: #fff;
      border-color: #0284c7;
    }}

    /* Pagination */
    .pagination-bar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 20px;
      border-top: 1px solid var(--border);
      flex-wrap: wrap;
      gap: 12px;
    }}

    .page-controls {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}

    .page-btn {{
      padding: 6px 12px;
      border-radius: 6px;
      background: var(--bg-input);
      border: 1px solid var(--border);
      color: var(--text-main);
      font-size: 12.5px;
      cursor: pointer;
      font-weight: 600;
    }}
    .page-btn:hover:not(:disabled) {{
      background: #2563eb;
      color: #fff;
    }}
    .page-btn:disabled {{
      opacity: 0.4;
      cursor: not-allowed;
    }}
    .page-btn.active {{
      background: #2563eb;
      color: #fff;
      border-color: #2563eb;
    }}

    /* Modal / Drawer */
    .modal-overlay {{
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.75);
      backdrop-filter: blur(4px);
      z-index: 1000;
      display: none;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }}

    .modal-card {{
      background: #111827;
      border: 1px solid var(--border);
      border-radius: 14px;
      width: 100%;
      max-width: 900px;
      max-height: 90vh;
      display: flex;
      flex-direction: column;
      box-shadow: 0 20px 40px rgba(0,0,0,0.6);
      overflow: hidden;
    }}

    .modal-header {{
      padding: 18px 24px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: #0f172a;
    }}

    .modal-header h2 {{
      font-size: 18px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .modal-close {{
      background: none;
      border: none;
      font-size: 24px;
      color: var(--text-dim);
      cursor: pointer;
      line-height: 1;
    }}
    .modal-close:hover {{
      color: #fff;
    }}

    .modal-body {{
      padding: 24px;
      overflow-y: auto;
      flex: 1;
    }}

    .modal-grid {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 18px;
    }}

    @media (max-width: 700px) {{
      .modal-grid {{
        grid-template-columns: 1fr;
      }}
    }}

    .modal-section {{
      background: #1a2234;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
    }}

    .modal-section-title {{
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--accent);
      margin-bottom: 12px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.06);
      padding-bottom: 6px;
    }}

    .prop-row {{
      display: flex;
      justify-content: space-between;
      align-items: baseline;
      padding: 5px 0;
      font-size: 13px;
      border-bottom: 1px dotted rgba(255, 255, 255, 0.05);
    }}
    .prop-row:last-child {{
      border-bottom: none;
    }}

    .prop-label {{
      color: var(--text-dim);
      font-weight: 500;
    }}

    .prop-val {{
      color: #fff;
      font-weight: 600;
      text-align: right;
      max-width: 60%;
      word-break: break-word;
    }}

    .raw-box {{
      background: #0a0f1d;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 10px;
      font-family: monospace;
      font-size: 12px;
      color: #cbd5e1;
      max-height: 180px;
      overflow-y: auto;
      white-space: pre-wrap;
      word-break: break-all;
      margin-top: 8px;
    }}

    .modal-footer {{
      padding: 14px 24px;
      border-top: 1px solid var(--border);
      display: flex;
      justify-content: flex-end;
      gap: 12px;
      background: #0f172a;
    }}
  </style>
</head>
<body>

<div class="container">

  <!-- Header -->
  <header class="header">
    <div class="header-left">
      <div class="logo-badge">S3</div>
      <div class="header-title">
        <h1>AWS Multi-Organization S3 Security Posture Portal</h1>
        <p>Comprehensive security audit, encryption, public exposure perimeter, and tags across <strong>{stats['total_accounts']} Accounts</strong> in <strong>3 AWS Organizations</strong></p>
      </div>
    </div>
    <div class="header-actions">
      <button class="btn btn-secondary" onclick="exportFilteredCSV()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
        Download Filtered CSV
      </button>
      <button class="btn btn-primary" onclick="exportFullCSV()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
        Download Full Inventory CSV ({stats['total']})
      </button>
      <button class="btn btn-secondary" onclick="window.print()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 6 2 18 2 18 9"></polyline><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path><rect x="6" y="14" width="12" height="8"></rect></svg>
        Print / PDF
      </button>
    </div>
  </header>

  <!-- Critical High-Risk Alert Banner (if any) -->
  <div class="critical-banner">
    <div class="critical-content">
      <div class="critical-icon">!</div>
      <div class="critical-text">
        <h3>Critical Finding: 1 Public S3 Bucket Detected by Bucket Policy</h3>
        <p>Bucket <strong>appdevlab-migration-data</strong> (Account: 371016420106 / RUS-AWS-EXT-LAB-APPDEV) has Public Access Block disabled and permits unrestricted public policy access.</p>
      </div>
    </div>
    <button class="btn btn-danger" onclick="filterHighRiskOnly()">Isolate High Risk Bucket</button>
  </div>

  <!-- Executive KPI Grid -->
  <div class="kpi-grid">
    <div class="kpi-card kpi-total">
      <div class="kpi-label">Total S3 Buckets</div>
      <div class="kpi-value-row">
        <div class="kpi-value">{stats['total']}</div>
        <div class="kpi-subtext">across 3 Orgs</div>
      </div>
    </div>
    <div class="kpi-card kpi-high">
      <div class="kpi-label">High Risk Exposure</div>
      <div class="kpi-value-row">
        <div class="kpi-value" style="color: #f87171;">{stats['high_risk_count']}</div>
        <div class="kpi-subtext">Public Exposure</div>
        <span class="kpi-pct-badge badge-red">Critical</span>
      </div>
    </div>
    <div class="kpi-card kpi-medium">
      <div class="kpi-label">Medium Risk</div>
      <div class="kpi-value-row">
        <div class="kpi-value" style="color: #fbbf24;">{stats['medium_risk_count']}</div>
        <div class="kpi-subtext">Missing TLS / PAB</div>
        <span class="kpi-pct-badge badge-yellow">{round(stats['medium_risk_count'] / stats['total'] * 100, 1)}%</span>
      </div>
    </div>
    <div class="kpi-card kpi-low">
      <div class="kpi-label">Low Risk</div>
      <div class="kpi-value-row">
        <div class="kpi-value" style="color: #93c5fd;">{stats['low_risk_count']}</div>
        <div class="kpi-subtext">Missing Log/Version</div>
        <span class="kpi-pct-badge badge-gray">{round(stats['low_risk_count'] / stats['total'] * 100, 1)}%</span>
      </div>
    </div>
    <div class="kpi-card kpi-compliant">
      <div class="kpi-label">Fully Compliant</div>
      <div class="kpi-value-row">
        <div class="kpi-value" style="color: #34d399;">{stats['compliant_count']}</div>
        <div class="kpi-subtext">Zero Deviations</div>
        <span class="kpi-pct-badge badge-green">{round(stats['compliant_count'] / stats['total'] * 100, 1)}%</span>
      </div>
    </div>
  </div>

  <!-- Posture Strip -->
  <div class="posture-strip">
    <div class="posture-card">
      <div class="posture-header">
        <span>Server-Side Encryption</span>
        <span style="color: #34d399;">{stats['encrypted_pct']}%</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" style="width: {stats['encrypted_pct']}%; background: #10b981;"></div>
      </div>
      <div class="posture-meta">
        <span>{stats['encrypted_count']} of {stats['total']} encrypted</span>
        <span>AES256: {stats['enc_counts'].get('AES256', 0)} | KMS: {stats['enc_counts'].get('aws:kms', 0)}</span>
      </div>
    </div>

    <div class="posture-card">
      <div class="posture-header">
        <span>Public Access Block (PAB)</span>
        <span style="color: #38bdf8;">{stats['pab_full_pct']}%</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" style="width: {stats['pab_full_pct']}%; background: #38bdf8;"></div>
      </div>
      <div class="posture-meta">
        <span>{stats['pab_full_count']} fully blocked</span>
        <span>Unblocked: {stats['pab_counts'].get('None Configured', 0)}</span>
      </div>
    </div>

    <div class="posture-card">
      <div class="posture-header">
        <span>TLS / HTTPS Enforced</span>
        <span style="color: #fbbf24;">{stats['tls_enforced_pct']}%</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" style="width: {stats['tls_enforced_pct']}%; background: #f59e0b;"></div>
      </div>
      <div class="posture-meta">
        <span>{stats['tls_enforced_count']} enforcing Deny</span>
        <span>Missing TLS Deny: {stats['tls_counts'].get('False', 0)}</span>
      </div>
    </div>

    <div class="posture-card">
      <div class="posture-header">
        <span>Bucket Versioning</span>
        <span style="color: #94a3b8;">{stats['versioning_pct']}%</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" style="width: {stats['versioning_pct']}%; background: #64748b;"></div>
      </div>
      <div class="posture-meta">
        <span>{stats['versioning_count']} active</span>
        <span>Disabled: {stats['version_counts'].get('Disabled', 0)}</span>
      </div>
    </div>

    <div class="posture-card">
      <div class="posture-header">
        <span>Server Access Logging</span>
        <span style="color: #8b5cf6;">{stats['logging_pct']}%</span>
      </div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" style="width: {stats['logging_pct']}%; background: #8b5cf6;"></div>
      </div>
      <div class="posture-meta">
        <span>{stats['logging_count']} logging targets</span>
        <span>Disabled: {stats['logging_counts'].get('False', 0)}</span>
      </div>
    </div>
  </div>

  <!-- Visual Dashboard Charts Row -->
  <div class="charts-row">
    <!-- Chart 1: Organization Distribution -->
    <div class="chart-box">
      <div class="chart-title">
        <span>Buckets by Organization</span>
        <span style="font-size: 12px; color: var(--text-dim);">3 AWS Organizations</span>
      </div>
      <div style="display: flex; flex-direction: column; gap: 12px;">
        <div>
          <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px;">
            <span><strong>RUS-IOC</strong> (679414842598 - Internal Ops)</span>
            <span style="font-weight: 700; color: #38bdf8;">{stats['org_counts'].get('rus-ioc', 0)} buckets ({round(stats['org_counts'].get('rus-ioc', 0)/stats['total']*100, 1)}%)</span>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: {round(stats['org_counts'].get('rus-ioc', 0)/stats['total']*100, 1)}%; background: #0284c7;"></div></div>
        </div>
        <div>
          <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px;">
            <span><strong>RUS-EXT</strong> (908140080081 - External)</span>
            <span style="font-weight: 700; color: #f59e0b;">{stats['org_counts'].get('rus-ext', 0)} buckets ({round(stats['org_counts'].get('rus-ext', 0)/stats['total']*100, 1)}%)</span>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: {round(stats['org_counts'].get('rus-ext', 0)/stats['total']*100, 1)}%; background: #f59e0b;"></div></div>
        </div>
        <div>
          <div style="display: flex; justify-content: space-between; font-size: 13px; margin-bottom: 4px;">
            <span><strong>CCCS</strong> (743683883393 - Canada / International)</span>
            <span style="font-weight: 700; color: #10b981;">{stats['org_counts'].get('cccs', 0)} buckets ({round(stats['org_counts'].get('cccs', 0)/stats['total']*100, 1)}%)</span>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: {round(stats['org_counts'].get('cccs', 0)/stats['total']*100, 1)}%; background: #10b981;"></div></div>
        </div>
      </div>
    </div>

    <!-- Chart 2: Top Accounts Concentration -->
    <div class="chart-box">
      <div class="chart-title">
        <span>Top Accounts by Bucket Volume</span>
        <span style="font-size: 12px; color: var(--text-dim);">Top 5 of {stats['total_accounts']} Accounts</span>
      </div>
      <div style="display: flex; flex-direction: column; gap: 10px;">
'''

    top_5_accs = stats['accounts'][:5]
    max_acc_buckets = top_5_accs[0]['count'] if top_5_accs else 1
    for acc in top_5_accs:
        pct = round(acc['count'] / max_acc_buckets * 100, 1)
        html_content += f'''
        <div>
          <div style="display: flex; justify-content: space-between; font-size: 12.5px; margin-bottom: 3px;">
            <span><strong>{acc['name']}</strong> ({acc['id']}) - <span style="color: var(--text-dim);">{acc['org']}</span></span>
            <span style="font-weight: 700;">{acc['count']} buckets</span>
          </div>
          <div class="progress-bar-bg"><div class="progress-bar-fill" style="width: {pct}%; background: #8b5cf6;"></div></div>
        </div>
'''

    html_content += f'''
      </div>
    </div>
  </div>

  <!-- Interactive Filters Toolbar -->
  <div class="filter-section">
    <div class="search-row">
      <div class="search-input-wrap">
        <svg class="search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"></circle><line x1="21" y1="21" x2="16.65" y2="16.65"></line></svg>
        <input type="text" id="globalSearch" class="search-input" placeholder="Search across bucket name, ARN, account name, ID, tags, owner..." oninput="applyFilters()">
      </div>
      <button class="btn btn-secondary" onclick="resetFilters()">Reset All Filters</button>
    </div>

    <div class="filter-grid">
      <div class="filter-group">
        <label class="filter-label" for="filterOrg">Organization</label>
        <select id="filterOrg" class="select-input" onchange="applyFilters()">
          <option value="">All Organizations ({stats['total']})</option>
          <option value="rus-ext">RUS-EXT ({stats['org_counts'].get('rus-ext', 0)})</option>
          <option value="rus-ioc">RUS-IOC ({stats['org_counts'].get('rus-ioc', 0)})</option>
          <option value="cccs">CCCS ({stats['org_counts'].get('cccs', 0)})</option>
        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterVerdict">Audit Verdict</label>
        <select id="filterVerdict" class="select-input" onchange="applyFilters()">
          <option value="">All Verdicts</option>
          <option value="HIGH_RISK">High Risk ({stats['high_risk_count']})</option>
          <option value="MEDIUM_RISK">Medium Risk ({stats['medium_risk_count']})</option>
          <option value="LOW_RISK">Low Risk ({stats['low_risk_count']})</option>
          <option value="COMPLIANT">Compliant ({stats['compliant_count']})</option>
        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterExposure">Public Exposure</label>
        <select id="filterExposure" class="select-input" onchange="applyFilters()">
          <option value="">All Exposures</option>
          <option value="PUBLIC_BY_POLICY">Public By Policy ({stats['public_counts'].get('PUBLIC_BY_POLICY', 0)})</option>
          <option value="SECURE">Secure ({stats['public_counts'].get('SECURE', 0)})</option>
        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterTLS">TLS Enforcement</label>
        <select id="filterTLS" class="select-input" onchange="applyFilters()">
          <option value="">All TLS States</option>
          <option value="True">TLS Enforced ({stats['tls_counts'].get('True', 0)})</option>
          <option value="False">Missing TLS Policy ({stats['tls_counts'].get('False', 0)})</option>
        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterPAB">Public Access Block (PAB)</label>
        <select id="filterPAB" class="select-input" onchange="applyFilters()">
          <option value="">All PAB States</option>
          <option value="Fully Blocked (Compliant)">Fully Blocked ({stats['pab_counts'].get('Fully Blocked (Compliant)', 0)})</option>
          <option value="None Configured">None Configured ({stats['pab_counts'].get('None Configured', 0)})</option>
        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterEncryption">Encryption Type</label>
        <select id="filterEncryption" class="select-input" onchange="applyFilters()">
          <option value="">All Encryption</option>
          <option value="AES256">AES256 ({stats['enc_counts'].get('AES256', 0)})</option>
          <option value="aws:kms">aws:kms ({stats['enc_counts'].get('aws:kms', 0)})</option>
        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterVersioning">Versioning</label>
        <select id="filterVersioning" class="select-input" onchange="applyFilters()">
          <option value="">All Versioning</option>
          <option value="Enabled">Enabled ({stats['version_counts'].get('Enabled', 0)})</option>
          <option value="Disabled">Disabled ({stats['version_counts'].get('Disabled', 0)})</option>
          <option value="Suspended">Suspended ({stats['version_counts'].get('Suspended', 0)})</option>
        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterLogging">Access Logging</label>
        <select id="filterLogging" class="select-input" onchange="applyFilters()">
          <option value="">All Logging</option>
          <option value="True">Logging Enabled ({stats['logging_counts'].get('True', 0)})</option>
          <option value="False">Logging Disabled ({stats['logging_counts'].get('False', 0)})</option>
        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterRegion">Region</label>
        <select id="filterRegion" class="select-input" onchange="applyFilters()">
          <option value="">All Regions</option>
'''
    for reg, cnt in sorted(stats['region_counts'].items(), key=lambda x: x[1], reverse=True):
        html_content += f'          <option value="{reg}">{reg} ({cnt})</option>\n'

    html_content += f'''        </select>
      </div>

      <div class="filter-group">
        <label class="filter-label" for="filterAccount">Account Filter</label>
        <select id="filterAccount" class="select-input" onchange="applyFilters()">
          <option value="">All {stats['total_accounts']} Accounts</option>
'''
    for acc in stats['accounts']:
        html_content += f'          <option value="{acc["id"]}">{acc["name"]} ({acc["count"]})</option>\n'

    html_content += f'''        </select>
      </div>
    </div>

    <div class="filter-meta-bar">
      <div id="resultsCount" class="results-count">Showing {stats['total']} of {stats['total']} buckets</div>
      <div style="font-size: 12px; color: var(--text-dim);">Click column headers to sort &bull; Click any row or Inspect button for all 47 metadata fields</div>
    </div>
  </div>

  <!-- Data Table Card -->
  <div class="table-card">
    <div class="table-wrapper">
      <table id="s3Table">
        <thead>
          <tr>
            <th onclick="sortTable(0)">Verdict &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(1)">Bucket Name & ARN &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(2)">Org & Account &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(3)">Region &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(4)">Public Exposure &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(5)">PAB Status &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(6)">TLS Deny &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(7)">Encryption &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(8)">Versioning &#x25B4;&#x25BE;</th>
            <th onclick="sortTable(9)">Logging &#x25B4;&#x25BE;</th>
            <th style="text-align: center;">Action</th>
          </tr>
        </thead>
        <tbody id="tableBody">
          <!-- Populated by JavaScript -->
        </tbody>
      </table>
    </div>

    <!-- Pagination Bar -->
    <div class="pagination-bar">
      <div style="display: flex; align-items: center; gap: 8px;">
        <span style="font-size: 13px; color: var(--text-dim);">Show per page:</span>
        <select id="pageSizeSelect" class="select-input" style="width: auto; padding: 4px 8px;" onchange="changePageSize()">
          <option value="25" selected>25</option>
          <option value="50">50</option>
          <option value="100">100</option>
          <option value="all">All ({stats['total']})</option>
        </select>
      </div>
      <div id="paginationControls" class="page-controls">
        <!-- Pagination buttons -->
      </div>
    </div>
  </div>

</div>

<!-- Modal Inspection Drawer -->
<div id="inspectModal" class="modal-overlay" onclick="closeModalOnOverlay(event)">
  <div class="modal-card">
    <div class="modal-header">
      <h2>
        <span id="modalVerdictBadge" class="badge badge-high">VERDICT</span>
        <span id="modalBucketTitle">Bucket Name</span>
      </h2>
      <button class="modal-close" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-body">
      <div class="modal-grid">
        
        <!-- General Identity -->
        <div class="modal-section">
          <div class="modal-section-title">Core Identity & Scope</div>
          <div class="prop-row"><span class="prop-label">Bucket ARN</span><span id="m_arn" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Region</span><span id="m_region" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Creation Date</span><span id="m_created" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Organization Profile</span><span id="m_org" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Master Org ID</span><span id="m_orgid" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Account Name</span><span id="m_accname" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Account ID</span><span id="m_accid" class="prop-val"></span></div>
        </div>

        <!-- Security & Perimeter -->
        <div class="modal-section">
          <div class="modal-section-title">Public Perimeter & Access Blocks</div>
          <div class="prop-row"><span class="prop-label">Public Exposure Risk</span><span id="m_risk" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Is Public Flag</span><span id="m_ispublic" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">PAB Overall Status</span><span id="m_pabstatus" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Block Public ACLs</span><span id="m_pab_bpacls" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Ignore Public ACLs</span><span id="m_pab_ipacls" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Block Public Policy</span><span id="m_pab_bppolicy" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Restrict Public Buckets</span><span id="m_pab_rpb" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Object Ownership</span><span id="m_ownership" class="prop-val"></span></div>
        </div>

        <!-- Transport & Encryption -->
        <div class="modal-section">
          <div class="modal-section-title">Encryption & Transport Security</div>
          <div class="prop-row"><span class="prop-label">Is Encrypted</span><span id="m_encrypted" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Encryption Type</span><span id="m_enctype" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">KMS Master Key ID</span><span id="m_kmskey" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Bucket Key Enabled</span><span id="m_bkey" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Enforces TLS / HTTPS</span><span id="m_tls" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Bucket Policy Statements</span><span id="m_polcount" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Policy Is Public</span><span id="m_polpublic" class="prop-val"></span></div>
        </div>

        <!-- Governance & Lifecycle -->
        <div class="modal-section">
          <div class="modal-section-title">Lifecycle & Governance</div>
          <div class="prop-row"><span class="prop-label">Versioning Status</span><span id="m_versioning" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">MFA Delete</span><span id="m_mfadelete" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Object Lock Active</span><span id="m_objlock" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Server Access Logging</span><span id="m_logging" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Logging Target</span><span id="m_logtarget" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Lifecycle Rules</span><span id="m_lifecycle" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Replication</span><span id="m_replication" class="prop-val"></span></div>
          <div class="prop-row"><span class="prop-label">Event Notifications</span><span id="m_events" class="prop-val"></span></div>
        </div>

      </div>

      <!-- Audit Flags & Findings -->
      <div style="margin-top: 18px;">
        <div class="modal-section">
          <div class="modal-section-title">Detected Audit Deviations & Risk Flags</div>
          <div id="m_flags_list" style="display: flex; flex-wrap: wrap; gap: 6px; padding-top: 4px;"></div>
        </div>
      </div>

      <!-- Formatted Tags -->
      <div style="margin-top: 18px;">
        <div class="modal-section">
          <div class="modal-section-title">Resource Tags (<span id="m_tagscount">0</span>)</div>
          <div id="m_tags_container" style="display: flex; flex-wrap: wrap; gap: 6px; padding-top: 4px;"></div>
          <div class="raw-box" id="m_tags_raw"></div>
        </div>
      </div>

    </div>
    <div class="modal-footer">
      <button class="btn btn-secondary" onclick="copyBucketJson()">Copy JSON</button>
      <button class="btn btn-primary" onclick="closeModal()">Close Details</button>
    </div>
  </div>
</div>

<script>
// Raw dataset embedded
const ALL_BUCKETS = {buckets_json_str};
let filteredBuckets = [...ALL_BUCKETS];
let currentPage = 1;
let pageSize = 25;
let currentSortCol = 0;
let currentSortAsc = true;
let activeInspectBucket = null;

// On load initialize table
document.addEventListener("DOMContentLoaded", () => {{
  applyFilters();
}});

function renderTable() {{
  const tbody = document.getElementById("tableBody");
  tbody.innerHTML = "";

  const total = filteredBuckets.length;
  const startIdx = pageSize === "all" ? 0 : (currentPage - 1) * pageSize;
  const endIdx = pageSize === "all" ? total : Math.min(startIdx + pageSize, total);

  const pageData = filteredBuckets.slice(startIdx, endIdx);

  if (pageData.length === 0) {{
    tbody.innerHTML = `<tr><td colspan="11" style="text-align: center; padding: 40px; color: var(--text-dim);">No S3 buckets match your current search and filter criteria.</td></tr>`;
    renderPagination(0);
    return;
  }}

  pageData.forEach((b) => {{
    const tr = document.createElement("tr");

    // Verdict badge
    let vClass = "badge-low";
    if (b.AuditVerdict === "HIGH_RISK") vClass = "badge-high";
    else if (b.AuditVerdict === "MEDIUM_RISK") vClass = "badge-medium";
    else if (b.AuditVerdict === "COMPLIANT") vClass = "badge-compliant";

    // Public exposure badge
    let expBadge = `<span class="badge badge-green">SECURE</span>`;
    if (b.PublicExposureRisk === "PUBLIC_BY_POLICY") {{
      expBadge = `<span class="badge badge-high badge-pill" style="animation: pulse-ring 2s infinite;">PUBLIC POLICY</span>`;
    }}

    // PAB
    let pabBadge = `<span class="badge badge-green">Blocked</span>`;
    if (b.PAB_Status === "None Configured") {{
      pabBadge = `<span class="badge badge-red">Unblocked</span>`;
    }} else if (b.PAB_Status.includes("AccessDenied")) {{
      pabBadge = `<span class="badge badge-gray">Denied</span>`;
    }}

    // TLS
    const tlsBadge = b.Policy_EnforcesTLS === "True" 
      ? `<span class="badge badge-green">Enforced</span>` 
      : `<span class="badge badge-yellow">Missing Deny</span>`;

    // Encryption
    let encBadge = `<span class="badge badge-green">${{b.EncryptionType}}</span>`;
    if (b.EncryptionType === "aws:kms") {{
      encBadge = `<span class="badge badge-low">KMS${{b.BucketKeyEnabled === 'True' ? ' (Keyed)' : ''}}</span>`;
    }} else if (b.EncryptionType.includes("AccessDenied")) {{
      encBadge = `<span class="badge badge-gray">Denied</span>`;
    }}

    // Versioning
    const verBadge = b.VersioningStatus === "Enabled" 
      ? `<span class="badge badge-green">Enabled</span>`
      : `<span class="badge badge-gray">${{b.VersioningStatus}}</span>`;

    // Logging
    const logBadge = b.LoggingEnabled === "True"
      ? `<span class="badge badge-green">Active</span>`
      : `<span class="badge badge-gray">Off</span>`;

    tr.innerHTML = `
      <td><span class="badge ${{vClass}}">${{b.AuditVerdict}}</span></td>
      <td>
        <div class="bucket-name-cell">
          <span>${{b.BucketName}}</span>
          <span class="bucket-arn">${{b.BucketArn}}</span>
        </div>
      </td>
      <td>
        <div style="font-weight: 600;">${{b.AccountName}}</div>
        <div style="font-size: 11px; color: var(--text-dim);">${{b.AccountId}} &bull; <strong style="color: var(--accent);">${{b.OrganizationProfile}}</strong></div>
      </td>
      <td><span style="font-family: monospace; font-size: 12px;">${{b.Region}}</span></td>
      <td>${{expBadge}}</td>
      <td>${{pabBadge}}</td>
      <td>${{tlsBadge}}</td>
      <td>${{encBadge}}</td>
      <td>${{verBadge}}</td>
      <td>${{logBadge}}</td>
      <td style="text-align: center;">
        <button class="btn-inspect" onclick="openModal('${{b.BucketName}}')">Inspect</button>
      </td>
    `;
    tbody.appendChild(tr);
  }});

  renderPagination(total);
}}

function renderPagination(total) {{
  const container = document.getElementById("paginationControls");
  container.innerHTML = "";

  if (pageSize === "all" || total <= pageSize) {{
    return;
  }}

  const totalPages = Math.ceil(total / pageSize);

  // Prev button
  const prevBtn = document.createElement("button");
  prevBtn.className = "page-btn";
  prevBtn.innerText = "« Prev";
  prevBtn.disabled = currentPage === 1;
  prevBtn.onclick = () => {{ currentPage--; renderTable(); }};
  container.appendChild(prevBtn);

  // Page Numbers
  let startP = Math.max(1, currentPage - 2);
  let endP = Math.min(totalPages, currentPage + 2);

  if (startP > 1) {{
    const p1 = document.createElement("button");
    p1.className = "page-btn";
    p1.innerText = "1";
    p1.onclick = () => {{ currentPage = 1; renderTable(); }};
    container.appendChild(p1);
    if (startP > 2) {{
      const span = document.createElement("span");
      span.innerText = "...";
      span.style.color = "var(--text-dim)";
      container.appendChild(span);
    }}
  }}

  for (let p = startP; p <= endP; p++) {{
    const pBtn = document.createElement("button");
    pBtn.className = "page-btn" + (p === currentPage ? " active" : "");
    pBtn.innerText = p;
    pBtn.onclick = () => {{ currentPage = p; renderTable(); }};
    container.appendChild(pBtn);
  }}

  if (endP < totalPages) {{
    if (endP < totalPages - 1) {{
      const span = document.createElement("span");
      span.innerText = "...";
      span.style.color = "var(--text-dim)";
      container.appendChild(span);
    }}
    const pEnd = document.createElement("button");
    pEnd.className = "page-btn";
    pEnd.innerText = totalPages;
    pEnd.onclick = () => {{ currentPage = totalPages; renderTable(); }};
    container.appendChild(pEnd);
  }}

  // Next button
  const nextBtn = document.createElement("button");
  nextBtn.className = "page-btn";
  nextBtn.innerText = "Next »";
  nextBtn.disabled = currentPage === totalPages;
  nextBtn.onclick = () => {{ currentPage++; renderTable(); }};
  container.appendChild(nextBtn);
}}

function changePageSize() {{
  const val = document.getElementById("pageSizeSelect").value;
  pageSize = val === "all" ? "all" : parseInt(val, 10);
  currentPage = 1;
  renderTable();
}}

function applyFilters() {{
  const query = document.getElementById("globalSearch").value.toLowerCase().trim();
  const org = document.getElementById("filterOrg").value;
  const verdict = document.getElementById("filterVerdict").value;
  const exposure = document.getElementById("filterExposure").value;
  const tls = document.getElementById("filterTLS").value;
  const pab = document.getElementById("filterPAB").value;
  const enc = document.getElementById("filterEncryption").value;
  const version = document.getElementById("filterVersioning").value;
  const logging = document.getElementById("filterLogging").value;
  const region = document.getElementById("filterRegion").value;
  const account = document.getElementById("filterAccount").value;

  filteredBuckets = ALL_BUCKETS.filter((b) => {{
    if (org && b.OrganizationProfile !== org) return false;
    if (verdict && b.AuditVerdict !== verdict) return false;
    if (exposure && b.PublicExposureRisk !== exposure) return false;
    if (tls && b.Policy_EnforcesTLS !== tls) return false;
    if (pab && !b.PAB_Status.includes(pab)) return false;
    if (enc && b.EncryptionType !== enc) return false;
    if (version && b.VersioningStatus !== version) return false;
    if (logging && b.LoggingEnabled !== logging) return false;
    if (region && b.Region !== region) return false;
    if (account && b.AccountId !== account) return false;

    if (query) {{
      const match = (
        b.BucketName.toLowerCase().includes(query) ||
        b.BucketArn.toLowerCase().includes(query) ||
        b.AccountName.toLowerCase().includes(query) ||
        b.AccountId.toLowerCase().includes(query) ||
        b.AuditFlags.toLowerCase().includes(query) ||
        b.Tags_Formatted.toLowerCase().includes(query)
      );
      if (!match) return false;
    }}

    return true;
  }});

  currentPage = 1;
  document.getElementById("resultsCount").innerText = `Showing ${{filteredBuckets.length}} of ${{ALL_BUCKETS.length}} buckets`;
  renderTable();
}}

function resetFilters() {{
  document.getElementById("globalSearch").value = "";
  document.getElementById("filterOrg").value = "";
  document.getElementById("filterVerdict").value = "";
  document.getElementById("filterExposure").value = "";
  document.getElementById("filterTLS").value = "";
  document.getElementById("filterPAB").value = "";
  document.getElementById("filterEncryption").value = "";
  document.getElementById("filterVersioning").value = "";
  document.getElementById("filterLogging").value = "";
  document.getElementById("filterRegion").value = "";
  document.getElementById("filterAccount").value = "";
  applyFilters();
}}

function filterHighRiskOnly() {{
  resetFilters();
  document.getElementById("filterVerdict").value = "HIGH_RISK";
  applyFilters();
}}

function sortTable(colIdx) {{
  if (currentSortCol === colIdx) {{
    currentSortAsc = !currentSortAsc;
  }} else {{
    currentSortCol = colIdx;
    currentSortAsc = true;
  }}

  const keys = [
    "AuditVerdict",
    "BucketName",
    "AccountName",
    "Region",
    "PublicExposureRisk",
    "PAB_Status",
    "Policy_EnforcesTLS",
    "EncryptionType",
    "VersioningStatus",
    "LoggingEnabled"
  ];

  const sortKey = keys[colIdx];

  filteredBuckets.sort((a, b) => {{
    let valA = a[sortKey] || "";
    let valB = b[sortKey] || "";

    let comp = valA.localeCompare(valB, undefined, {{ numeric: true }});
    return currentSortAsc ? comp : -comp;
  }});

  renderTable();
}}

// Modal Inspection Drawer Logic
function openModal(bucketName) {{
  const b = ALL_BUCKETS.find(x => x.BucketName === bucketName);
  if (!b) return;

  activeInspectBucket = b;

  document.getElementById("modalBucketTitle").innerText = b.BucketName;
  const vb = document.getElementById("modalVerdictBadge");
  vb.innerText = b.AuditVerdict;
  vb.className = "badge " + (
    b.AuditVerdict === "HIGH_RISK" ? "badge-high" :
    b.AuditVerdict === "MEDIUM_RISK" ? "badge-medium" :
    b.AuditVerdict === "COMPLIANT" ? "badge-compliant" : "badge-low"
  );

  document.getElementById("m_arn").innerText = b.BucketArn;
  document.getElementById("m_region").innerText = b.Region;
  document.getElementById("m_created").innerText = b.CreationDate;
  document.getElementById("m_org").innerText = b.OrganizationProfile;
  document.getElementById("m_orgid").innerText = b.OrganizationId;
  document.getElementById("m_accname").innerText = b.AccountName;
  document.getElementById("m_accid").innerText = b.AccountId;

  document.getElementById("m_risk").innerHTML = b.PublicExposureRisk === "PUBLIC_BY_POLICY"
    ? `<span class="badge badge-high">PUBLIC_BY_POLICY</span>`
    : `<span class="badge badge-green">SECURE</span>`;
  document.getElementById("m_ispublic").innerText = b.IsPublic;
  document.getElementById("m_pabstatus").innerText = b.PAB_Status;
  document.getElementById("m_pab_bpacls").innerText = b.PAB_BlockPublicAcls;
  document.getElementById("m_pab_ipacls").innerText = b.PAB_IgnorePublicAcls;
  document.getElementById("m_pab_bppolicy").innerText = b.PAB_BlockPublicPolicy;
  document.getElementById("m_pab_rpb").innerText = b.PAB_RestrictPublicBuckets;
  document.getElementById("m_ownership").innerText = b.ObjectOwnership;

  document.getElementById("m_encrypted").innerText = b.IsEncrypted;
  document.getElementById("m_enctype").innerText = b.EncryptionType;
  document.getElementById("m_kmskey").innerText = b.KmsMasterKeyId;
  document.getElementById("m_bkey").innerText = b.BucketKeyEnabled;
  document.getElementById("m_tls").innerHTML = b.Policy_EnforcesTLS === "True"
    ? `<span class="badge badge-green">Enforces TLS Deny</span>`
    : `<span class="badge badge-yellow">Missing TLS Deny</span>`;
  document.getElementById("m_polcount").innerText = b.Policy_StatementsCount;
  document.getElementById("m_polpublic").innerText = b.Policy_IsPublic;

  document.getElementById("m_versioning").innerText = b.VersioningStatus;
  document.getElementById("m_mfadelete").innerText = b.MfaDelete;
  document.getElementById("m_objlock").innerText = b.ObjectLockEnabled;
  document.getElementById("m_logging").innerText = b.LoggingEnabled;
  document.getElementById("m_logtarget").innerText = b.LoggingTargetBucket !== "N/A" ? `${{b.LoggingTargetBucket}} (${{b.LoggingTargetPrefix}})` : "None";
  document.getElementById("m_lifecycle").innerText = b.HasLifecycleRules === "True" ? `${{b.LifecycleRuleCount}} rule(s) - ${{b.LifecycleSummary}}` : "None";
  document.getElementById("m_replication").innerText = b.ReplicationEnabled === "True" ? b.ReplicationDestinations : "Disabled";
  document.getElementById("m_events").innerText = b.HasEventNotifications === "True" ? b.NotificationTargets : "None";

  // Flags list
  const flagsContainer = document.getElementById("m_flags_list");
  flagsContainer.innerHTML = "";
  if (b.AuditFlags && b.AuditFlags !== "None") {{
    const flags = b.AuditFlags.split("; ");
    flags.forEach(f => {{
      const span = document.createElement("span");
      span.className = "badge badge-yellow";
      if (f.includes("PUBLIC")) span.className = "badge badge-high";
      span.innerText = f;
      flagsContainer.appendChild(span);
    }});
  }} else {{
    flagsContainer.innerHTML = `<span class="badge badge-green">Zero Risk Deviations (COMPLIANT)</span>`;
  }}

  // Tags
  document.getElementById("m_tagscount").innerText = b.Tags_Count;
  const tagsContainer = document.getElementById("m_tags_container");
  tagsContainer.innerHTML = "";
  if (b.Tags_Formatted && b.Tags_Formatted !== "None" && b.Tags_Formatted !== "empty") {{
    const tags = b.Tags_Formatted.split("; ");
    tags.forEach(t => {{
      const span = document.createElement("span");
      span.className = "badge badge-gray";
      span.style.fontFamily = "monospace";
      span.innerText = t;
      tagsContainer.appendChild(span);
    }});
  }} else {{
    tagsContainer.innerHTML = `<span style="color: var(--text-dim); font-size: 13px;">No Tags Configured</span>`;
  }}

  // Raw JSON
  try {{
    const parsed = JSON.parse(b.Tags_JSON);
    document.getElementById("m_tags_raw").innerText = JSON.stringify(parsed, null, 2);
  }} catch(e) {{
    document.getElementById("m_tags_raw").innerText = b.Tags_JSON || "{{}}";
  }}

  document.getElementById("inspectModal").style.display = "flex";
}}

function closeModal() {{
  document.getElementById("inspectModal").style.display = "none";
}}

function closeModalOnOverlay(e) {{
  if (e.target.id === "inspectModal") {{
    closeModal();
  }}
}}

function copyBucketJson() {{
  if (!activeInspectBucket) return;
  navigator.clipboard.writeText(JSON.stringify(activeInspectBucket, null, 2)).then(() => {{
    alert("Bucket details JSON copied to clipboard!");
  }});
}}

// CSV Download Utilities
function exportFilteredCSV() {{
  if (filteredBuckets.length === 0) {{
    alert("No buckets to export with current filters.");
    return;
  }}
  downloadCSV(filteredBuckets, "s3_filtered_inventory.csv");
}}

function exportFullCSV() {{
  downloadCSV(ALL_BUCKETS, "s3_all_organizations_inventory.csv");
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

    print(f"Reading S3 inventory data from: {csv_path}...")
    buckets = load_data(csv_path)
    print(f"Loaded {len(buckets)} S3 bucket records.")

    stats = compute_statistics(buckets)
    print("Generating standalone interactive HTML report...")
    html_code = generate_html(buckets, stats)

    # Destination paths
    destinations = [
        r"c:\antigravity-projects\security group\s3_organizations_security_inventory_portal.html",
        r"c:\antigravity-projects\security group\reports\s3_organizations_security_inventory_portal.html",
        r"C:\kiro-projects\Asecure\s3_organizations_security_inventory_portal.html",
        r"C:\kiro-projects\Asecure\reports\s3_organizations_security_inventory_portal.html",
    ]

    for dest in destinations:
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(html_code)
        print(f"  [+] Saved HTML portal: {dest} ({round(os.path.getsize(dest)/1024, 1)} KB)")

    # Also save as an artifact
    artifact_path = r"C:\Users\karu\.gemini\antigravity\brain\17ae7d5f-fd1e-482a-abac-5ec857b0af00\s3_organizations_security_inventory_portal.html"
    with open(artifact_path, "w", encoding="utf-8") as f:
        f.write(html_code)
    print(f"  [+] Saved Artifact copy: {artifact_path} ({round(os.path.getsize(artifact_path)/1024, 1)} KB)")

    print("\n[SUCCESS] S3 Security Inventory Portal generation complete!")

if __name__ == "__main__":
    main()
