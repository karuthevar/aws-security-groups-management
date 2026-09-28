#!/usr/bin/env python3
"""
AWS Enterprise Executive Portal Builder
Generates a standalone, leadership-grade HTML portal illustrating current security findings,
strategic implementation order based on complexity vs. impact, account concentration,
interactive findings drill-down, and continuous guardrails.
NO TIMELINES - Strictly prioritized by Complexity, Downtime Impact, and Risk Reduction.
"""

import os
import json
from collections import Counter, defaultdict

def build_portal():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root_dir = os.path.dirname(script_dir)
    report_json_path = os.path.join(root_dir, "reports", "09 28 26", "consolidated_enterprise_compliance_report.json")
    
    if not os.path.exists(report_json_path):
        print(f"Error: {report_json_path} not found.")
        return

    with open(report_json_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    # 1. Metrics Calculation
    total_findings = len(findings)
    zero_wins = [x for x in findings if x.get("RemediationImpact") == "ZERO_IMPACT_QUICK_WIN" and x.get("Status") == "NON_COMPLIANT"]
    low_impact = [x for x in findings if x.get("RemediationImpact") == "LOW_IMPACT_CONFIG" and x.get("Status") == "NON_COMPLIANT"]
    criticals = [x for x in findings if x.get("Severity") == "CRITICAL" and x.get("Status") == "NON_COMPLIANT"]
    highs = [x for x in findings if x.get("Severity") == "HIGH" and x.get("Status") == "NON_COMPLIANT"]
    mediums = [x for x in findings if x.get("Severity") == "MEDIUM" and x.get("Status") == "NON_COMPLIANT"]
    lows = [x for x in findings if x.get("Severity") == "LOW" and x.get("Status") == "NON_COMPLIANT"]
    compliant = [x for x in findings if x.get("Status") == "COMPLIANT"]

    # 2. Account Breakdown
    accounts_data = defaultdict(lambda: {"total": 0, "zero_wins": 0, "critical": 0, "high": 0, "medium": 0, "name": ""})
    for f in findings:
        aid = f.get("AccountId")
        accounts_data[aid]["total"] += 1
        accounts_data[aid]["name"] = f.get("AccountName", aid)
        if f.get("RemediationImpact") == "ZERO_IMPACT_QUICK_WIN":
            accounts_data[aid]["zero_wins"] += 1
        if f.get("Severity") == "CRITICAL":
            accounts_data[aid]["critical"] += 1
        elif f.get("Severity") == "HIGH":
            accounts_data[aid]["high"] += 1
        elif f.get("Severity") == "MEDIUM":
            accounts_data[aid]["medium"] += 1

    sorted_accounts = sorted(accounts_data.items(), key=lambda x: x[1]["total"], reverse=True)

    # Compact JSON for findings explorer
    compact_findings = []
    for f in findings:
        compact_findings.append({
            "AccountId": f.get("AccountId"),
            "AccountName": f.get("AccountName"),
            "Region": f.get("Region"),
            "Domain": f.get("Domain"),
            "RuleName": f.get("RuleName"),
            "Severity": f.get("Severity"),
            "RemediationImpact": f.get("RemediationImpact"),
            "ResourceId": f.get("ResourceId"),
            "Description": f.get("Description"),
            "RemediationCLI": f.get("RemediationCLI"),
            "ImpactRationale": f.get("ImpactRationale")
        })

    portal_dir = os.path.join(root_dir, "portal")
    os.makedirs(portal_dir, exist_ok=True)
    out_html = os.path.join(portal_dir, "index.html")

    payload_json = json.dumps(compact_findings)

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AWS Cloud Security & Governance Executive Briefing</title>
    <style>
        :root {{
            --bg-body: #0b0f19;
            --bg-card: #111827;
            --bg-card-hover: #1f2937;
            --bg-surface: #1e293b;
            --text-main: #f9fafb;
            --text-muted: #9ca3af;
            --text-dim: #6b7280;
            --border: #374151;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-green: #10b981;
            --accent-amber: #f59e0b;
            --accent-red: #ef4444;
            --shadow-card: 0 10px 25px -5px rgba(0, 0, 0, 0.4), 0 8px 10px -6px rgba(0, 0, 0, 0.4);
        }}

        body.light-theme {{
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --bg-card-hover: #f1f5f9;
            --bg-surface: #f1f5f9;
            --text-main: #0f172a;
            --text-muted: #475569;
            --text-dim: #94a3b8;
            --border: #e2e8f0;
            --shadow-card: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
        }}

        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background-color: var(--bg-body);
            color: var(--text-main);
            line-height: 1.6;
            transition: background-color 0.25s, color 0.25s;
        }}

        /* Navigation Bar */
        .navbar {{
            position: sticky;
            top: 0;
            z-index: 100;
            background: rgba(17, 24, 39, 0.9);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            padding: 14px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        body.light-theme .navbar {{ background: rgba(255, 255, 255, 0.9); }}
        .nav-brand {{
            display: flex;
            align-items: center;
            gap: 12px;
            font-size: 1.15rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .shield-icon {{
            background: linear-gradient(135deg, #06b6d4, #3b82f6);
            width: 32px;
            height: 32px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #fff;
            font-weight: 900;
            font-size: 1rem;
        }}
        .nav-links {{
            display: flex;
            align-items: center;
            gap: 20px;
            list-style: none;
        }}
        .nav-links a {{
            color: var(--text-muted);
            text-decoration: none;
            font-size: 0.875rem;
            font-weight: 500;
            transition: color 0.15s;
        }}
        .nav-links a:hover {{ color: var(--accent-cyan); }}
        .nav-actions {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .btn {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 16px;
            border-radius: 8px;
            font-size: 0.85rem;
            font-weight: 600;
            cursor: pointer;
            border: none;
            transition: all 0.2s;
            text-decoration: none;
        }}
        .btn-primary {{
            background: linear-gradient(135deg, #06b6d4, #2563eb);
            color: #fff;
        }}
        .btn-primary:hover {{ opacity: 0.95; transform: translateY(-1px); }}
        .btn-outline {{
            background: transparent;
            color: var(--text-main);
            border: 1px solid var(--border);
        }}
        .btn-outline:hover {{ background: var(--bg-surface); }}

        /* Main Container */
        .container {{
            max-width: 1280px;
            margin: 0 auto;
            padding: 32px 24px;
        }}

        /* Hero Executive Summary Header */
        .hero {{
            padding: 32px 0 24px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 32px;
        }}
        .hero-badge {{
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(6, 182, 212, 0.12);
            border: 1px solid rgba(6, 182, 212, 0.3);
            color: var(--accent-cyan);
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 16px;
        }}
        .hero-title {{
            font-size: 2.3rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            line-height: 1.2;
            margin-bottom: 12px;
            background: linear-gradient(135deg, #ffffff 30%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        body.light-theme .hero-title {{
            background: linear-gradient(135deg, #0f172a 30%, #475569 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .hero-desc {{
            color: var(--text-muted);
            font-size: 1.05rem;
            max-width: 900px;
        }}

        /* KPI Stat Cards Grid */
        .kpi-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 36px;
        }}
        .kpi-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            position: relative;
            overflow: hidden;
            box-shadow: var(--shadow-card);
            transition: transform 0.2s, border-color 0.2s;
        }}
        .kpi-card:hover {{
            transform: translateY(-2px);
            border-color: #64748b;
        }}
        .kpi-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
        }}
        .kpi-card.cyan::before {{ background: var(--accent-cyan); }}
        .kpi-card.red::before {{ background: var(--accent-red); }}
        .kpi-card.amber::before {{ background: var(--accent-amber); }}
        .kpi-card.blue::before {{ background: var(--accent-blue); }}
        .kpi-card.purple::before {{ background: var(--accent-purple); }}

        .kpi-label {{
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
        }}
        .kpi-value {{
            font-size: 2.2rem;
            font-weight: 800;
            line-height: 1.1;
            margin: 8px 0 4px;
        }}
        .kpi-card.cyan .kpi-value {{ color: var(--accent-cyan); }}
        .kpi-card.red .kpi-value {{ color: var(--accent-red); }}
        .kpi-card.amber .kpi-value {{ color: var(--accent-amber); }}
        .kpi-card.blue .kpi-value {{ color: var(--accent-blue); }}
        .kpi-card.purple .kpi-value {{ color: var(--accent-purple); }}
        .kpi-subtext {{
            font-size: 0.78rem;
            color: var(--text-dim);
        }}

        /* Section Headers */
        .section-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 1px solid var(--border);
            flex-wrap: wrap;
            gap: 12px;
        }}
        .section-header h2 {{
            font-size: 1.45rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .section-header p {{
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 4px;
        }}

        /* 2x2 Strategic Matrix Grid */
        .matrix-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            grid-template-rows: auto auto;
            gap: 16px;
            margin-bottom: 40px;
        }}
        .matrix-quadrant {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            position: relative;
            box-shadow: var(--shadow-card);
        }}
        .quadrant-tag {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 12px;
        }}
        .tag-q1 {{ background: rgba(6, 182, 212, 0.15); color: var(--accent-cyan); border: 1px solid rgba(6, 182, 212, 0.3); }}
        .tag-q2 {{ background: rgba(59, 130, 246, 0.15); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.3); }}
        .tag-q3 {{ background: rgba(245, 158, 11, 0.15); color: var(--accent-amber); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .tag-q4 {{ background: rgba(139, 92, 246, 0.15); color: var(--accent-purple); border: 1px solid rgba(139, 92, 246, 0.3); }}

        .quadrant-title {{
            font-size: 1.15rem;
            font-weight: 700;
            margin-bottom: 8px;
        }}
        .quadrant-desc {{
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-bottom: 16px;
        }}
        .quadrant-items {{
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }}
        .quadrant-item {{
            display: flex;
            align-items: flex-start;
            gap: 10px;
            font-size: 0.85rem;
            padding: 10px 14px;
            background: var(--bg-surface);
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        .item-icon {{
            font-size: 1.1rem;
            line-height: 1.2;
        }}
        .item-content strong {{ color: var(--text-main); }}
        .item-content p {{ color: var(--text-muted); font-size: 0.78rem; margin-top: 2px; }}

        /* Implementation Order Cards */
        .order-container {{
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin-bottom: 40px;
        }}
        .order-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            display: grid;
            grid-template-columns: 80px 1fr auto;
            gap: 24px;
            align-items: center;
            box-shadow: var(--shadow-card);
            transition: transform 0.2s;
        }}
        .order-card:hover {{ transform: translateX(4px); }}
        .order-badge {{ text-align: center; }}
        .order-num {{
            font-size: 1.7rem;
            font-weight: 900;
            line-height: 1;
        }}
        .order-card.tier1 .order-num {{ color: var(--accent-red); }}
        .order-card.tier2 .order-num {{ color: var(--accent-cyan); }}
        .order-card.tier3 .order-num {{ color: var(--accent-blue); }}
        .order-card.tier4 .order-num {{ color: var(--accent-purple); }}

        .order-label {{
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-dim);
            margin-top: 4px;
        }}
        .order-info h3 {{
            font-size: 1.15rem;
            font-weight: 700;
            margin-bottom: 6px;
        }}
        .order-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            margin-bottom: 8px;
            font-size: 0.8rem;
        }}
        .meta-pill {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            color: var(--text-muted);
        }}
        .meta-pill.safe {{
            color: var(--accent-green);
            font-weight: 600;
        }}
        .order-details {{
            font-size: 0.85rem;
            color: var(--text-muted);
        }}
        .order-cta {{ text-align: right; }}

        /* Account Table */
        .account-table-wrap {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--shadow-card);
            margin-bottom: 40px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            text-align: left;
        }}
        th {{
            background: var(--bg-surface);
            padding: 12px 16px;
            font-weight: 600;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border);
            text-transform: uppercase;
            font-size: 0.72rem;
            letter-spacing: 0.05em;
        }}
        td {{
            padding: 14px 16px;
            border-bottom: 1px solid var(--border);
            color: var(--text-main);
        }}
        tr:last-child td {{ border-bottom: none; }}
        tr:hover td {{ background: var(--bg-card-hover); }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
        }}
        .badge-red {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; }}
        .badge-cyan {{ background: rgba(6, 182, 212, 0.15); color: #06b6d4; }}
        .badge-blue {{ background: rgba(59, 130, 246, 0.15); color: #3b82f6; }}
        .badge-amber {{ background: rgba(245, 158, 11, 0.15); color: #f59e0b; }}

        /* Findings Explorer Section */
        .explorer-controls {{
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-bottom: 16px;
            background: var(--bg-card);
            border: 1px solid var(--border);
            padding: 16px;
            border-radius: 12px;
        }}
        .explorer-controls select, .explorer-controls input {{
            background: var(--bg-surface);
            border: 1px solid var(--border);
            color: var(--text-main);
            padding: 8px 14px;
            border-radius: 8px;
            font-size: 0.85rem;
            outline: none;
        }}
        .explorer-controls input {{ flex: 1; min-width: 200px; }}

        /* Modal Dialog */
        .modal {{
            display: none;
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: rgba(0, 0, 0, 0.75);
            backdrop-filter: blur(4px);
            z-index: 200;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }}
        .modal.active {{ display: flex; }}
        .modal-card {{
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            max-width: 700px;
            width: 100%;
            padding: 24px;
            box-shadow: 0 25px 50px -12px rgba(0,0,0,0.5);
            max-height: 90vh;
            overflow-y: auto;
        }}
        .modal-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 16px;
            border-bottom: 1px solid var(--border);
            padding-bottom: 12px;
        }}
        .modal-header h3 {{ font-size: 1.25rem; font-weight: 700; }}
        .close-btn {{
            background: transparent; border: none; font-size: 1.5rem; color: var(--text-muted); cursor: pointer;
        }}
        pre.code-block {{
            background: #090d16;
            border: 1px solid var(--border);
            padding: 14px;
            border-radius: 8px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.8rem;
            color: #38bdf8;
            overflow-x: auto;
            margin: 10px 0 16px;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        /* Print Mode */
        @media print {{
            .navbar, .btn, .nav-actions, .explorer-controls {{ display: none !important; }}
            body {{ background: #fff !important; color: #000 !important; }}
            .container {{ max-width: 100% !important; padding: 0 !important; }}
            .matrix-grid, .kpi-grid {{ gap: 8px !important; }}
            .kpi-card, .matrix-quadrant, .order-card {{ border: 1px solid #ccc !important; box-shadow: none !important; }}
        }}

        @media (max-width: 768px) {{
            .matrix-grid {{ grid-template-columns: 1fr; }}
            .order-card {{ grid-template-columns: 1fr; text-align: left; }}
            .order-cta {{ text-align: left; }}
        }}
    </style>
</head>
<body>

    <!-- Executive Top Navbar -->
    <nav class="navbar">
        <div class="nav-brand">
            <div class="shield-icon">🛡️</div>
            <div>
                <div>AWS Cloud Security & Governance Executive Briefing</div>
                <div style="font-size: 0.72rem; color: var(--text-dim); font-weight: 400;">Executive Strategic Briefing • 4 Accounts Audited</div>
            </div>
        </div>
        <ul class="nav-links">
            <li><a href="#summary">Overview</a></li>
            <li><a href="#matrix">Impact Matrix</a></li>
            <li><a href="#order">Implementation Order</a></li>
            <li><a href="#accounts">Account Breakdown</a></li>
            <li><a href="#explorer">Live Findings</a></li>
            <li><a href="#guardrails">Prevention (SCPs)</a></li>
        </ul>
        <div class="nav-actions">
            <button class="btn btn-outline" onclick="toggleTheme()">🌓 Theme</button>
            <button class="btn btn-primary" onclick="window.print()">📄 Export PDF Briefing</button>
        </div>
    </nav>

    <div class="container">

        <!-- Executive Hero Header -->
        <section class="hero" id="summary">
            <div class="hero-badge">Executive Security Briefing • Current Assessment</div>
            <h1 class="hero-title">Cloud Infrastructure Security & Remediation Roadmap</h1>
            <p class="hero-desc">
                Comprehensive security evaluation conducted across 4 AWS Organization accounts. 
                This roadmap prioritizes <strong>Zero-Impact Quick Wins</strong>—actions that deliver immediate perimeter hardening, ransomware defense, and compliance adherence with <strong>100% zero workload disruption</strong>.
            </p>
        </section>

        <!-- KPI Executive Stat Cards -->
        <div class="kpi-grid">
            <div class="kpi-card purple">
                <div class="kpi-label">Total Checks Evaluated</div>
                <div class="kpi-value">{total_findings:,}</div>
                <div class="kpi-subtext">Across 4 Accounts & 170+ Security Rules</div>
            </div>
            <div class="kpi-card cyan">
                <div class="kpi-label">Zero-Impact Quick Wins</div>
                <div class="kpi-value">{len(zero_wins):,}</div>
                <div class="kpi-subtext">18.6% of gaps resolved with 0 Downtime</div>
            </div>
            <div class="kpi-card red">
                <div class="kpi-label">Critical Perimeter Gaps</div>
                <div class="kpi-value">{len(criticals):,}</div>
                <div class="kpi-subtext">Account-level S3 Public Access Disabled</div>
            </div>
            <div class="kpi-card amber">
                <div class="kpi-label">High Severity Fixes</div>
                <div class="kpi-value">{len(highs):,}</div>
                <div class="kpi-subtext">EBS Encryption, S3 TLS In-Transit</div>
            </div>
            <div class="kpi-card blue">
                <div class="kpi-label">Telemetry & CIS Alarms</div>
                <div class="kpi-value">{len(mediums):,}</div>
                <div class="kpi-subtext">VPC Flow Logs & CloudWatch Audit Rules</div>
            </div>
        </div>

        <!-- Section 1: Complexity vs. Impact Matrix -->
        <div class="section-header" id="matrix">
            <div>
                <h2>Strategic Implementation Matrix</h2>
                <p>Categorization of required remediations by Operational Complexity vs. Security Risk Reduction.</p>
            </div>
            <span class="hero-badge">Priority Model: High Impact & Low Friction First</span>
        </div>

        <div class="matrix-grid">
            <!-- Q1: High Impact, Low Complexity (DO FIRST) -->
            <div class="matrix-quadrant" style="border-top: 4px solid var(--accent-cyan);">
                <span class="quadrant-tag tag-q1">Quadrant 1 • Execute First (Low Complexity / High Impact)</span>
                <div class="quadrant-title">Zero-Impact Quick Wins</div>
                <p class="quadrant-desc">Highest ROI actions. 0 downtime on running workloads. Safe metadata flags and unused resource isolations.</p>
                <ul class="quadrant-items">
                    <li class="quadrant-item">
                        <span class="item-icon">🔒</span>
                        <div class="item-content">
                            <strong>S3 Account-Level Block Public Access (2 Accounts)</strong>
                            <p>Global safety net preventing 100% of accidental bucket leaks with zero HTTPS traffic disruption.</p>
                        </div>
                    </li>
                    <li class="quadrant-item">
                        <span class="item-icon">🛡️</span>
                        <div class="item-content">
                            <strong>Default Security Group Ingress Revocation (30 SGs)</strong>
                            <p>Default SGs cannot be deleted. Revoking ingress isolates them cleanly without affecting workload SGs.</p>
                        </div>
                    </li>
                    <li class="quadrant-item">
                        <span class="item-icon">🔑</span>
                        <div class="item-content">
                            <strong>EBS Default Encryption Enforcement (70 Regions)</strong>
                            <p>Transparently encrypts all future EBS volumes using KMS with zero impact on running EC2 instances.</p>
                        </div>
                    </li>
                    <li class="quadrant-item">
                        <span class="item-icon">📦</span>
                        <div class="item-content">
                            <strong>S3 Bucket Versioning Activation (106 Buckets)</strong>
                            <p>Protects mission-critical data from ransomware, overwrites, or accidental deletions with zero latency.</p>
                        </div>
                    </li>
                </ul>
            </div>

            <!-- Q2: High Impact, Medium Complexity -->
            <div class="matrix-quadrant" style="border-top: 4px solid var(--accent-blue);">
                <span class="quadrant-tag tag-q2">Quadrant 2 • Core Security (Medium Complexity / High Impact)</span>
                <div class="quadrant-title">Foundational Network & Data Security</div>
                <p class="quadrant-desc">Requires targeted policy updates and traffic telemetry deployment across cloud environments.</p>
                <ul class="quadrant-items">
                    <li class="quadrant-item">
                        <span class="item-icon">🌐</span>
                        <div class="item-content">
                            <strong>S3 In-Transit SSL Enforcement (142 Buckets)</strong>
                            <p>Attach bucket policy denying non-HTTPS (aws:SecureTransport: false) calls; authentic clients unaffected.</p>
                        </div>
                    </li>
                    <li class="quadrant-item">
                        <span class="item-icon">📡</span>
                        <div class="item-content">
                            <strong>VPC Flow Logs Telemetry Activation (28 VPCs)</strong>
                            <p>Enables full IP traffic flow logs to CloudWatch for continuous threat detection and forensics.</p>
                        </div>
                    </li>
                    <li class="quadrant-item">
                        <span class="item-icon">🔐</span>
                        <div class="item-content">
                            <strong>CloudTrail KMS CMK Key Rotation (36 Trails)</strong>
                            <p>Upgrades audit trail storage from default AWS-managed keys to customer-managed KMS CMKs with annual rotation.</p>
                        </div>
                    </li>
                </ul>
            </div>

            <!-- Q3: Low Complexity, Medium Impact -->
            <div class="matrix-quadrant" style="border-top: 4px solid var(--accent-amber);">
                <span class="quadrant-tag tag-q3">Quadrant 3 • Operational Hygiene (Low Complexity / Medium Impact)</span>
                <div class="quadrant-title">Governance & Storage Hygiene</div>
                <p class="quadrant-desc">Immediate billing optimization and credential policy hardening.</p>
                <ul class="quadrant-items">
                    <li class="quadrant-item">
                        <span class="item-icon">👤</span>
                        <div class="item-content">
                            <strong>IAM Password Policy Hardening (4 Accounts)</strong>
                            <p>Enforces 14-char length and 24-password reuse. Applies automatically on next user password renewal.</p>
                        </div>
                    </li>
                    <li class="quadrant-item">
                        <span class="item-icon">🛠️</span>
                        <div class="item-content">
                            <strong>Dedicated IAM Support Roles (4 Accounts)</strong>
                            <p>Provisions AWSSupportRole for controlled, audited AWS technical support incident response.</p>
                        </div>
                    </li>
                    <li class="quadrant-item">
                        <span class="item-icon">📉</span>
                        <div class="item-content">
                            <strong>CloudWatch Log Retention Caps (Cost Savings)</strong>
                            <p>Caps retention to 90 days on uncapped log groups to halt infinite log storage billing accruals.</p>
                        </div>
                    </li>
                </ul>
            </div>

            <!-- Q4: Strategic Prevention -->
            <div class="matrix-quadrant" style="border-top: 4px solid var(--accent-purple);">
                <span class="quadrant-tag tag-q4">Quadrant 4 • Permanent Lockdown (Strategic Guardrails)</span>
                <div class="quadrant-title">Continuous Prevention & Detection</div>
                <p class="quadrant-desc">Deploy organization-wide policy barriers preventing future creation of non-compliant resources.</p>
                <ul class="quadrant-items">
                    <li class="quadrant-item">
                        <span class="item-icon">🏛️</span>
                        <div class="item-content">
                            <strong>AWS Service Control Policies (5 SCP Guardrails)</strong>
                            <p>Blocks disabling S3 public access block, creating unencrypted EBS volumes, or stopping CloudTrail.</p>
                        </div>
                    </li>
                    <li class="quadrant-item">
                        <span class="item-icon">📋</span>
                        <div class="item-content">
                            <strong>AWS Config Conformance Pack Baseline</strong>
                            <p>Deploys continuous automated auditing across all active accounts with automated remediation triggers.</p>
                        </div>
                    </li>
                </ul>
            </div>
        </div>

        <!-- Section 2: Order of Implementation Based on Complexity & Impact -->
        <div class="section-header" id="order">
            <div>
                <h2>Order of Implementation (Based on Complexity & Impact)</h2>
                <p>Structured implementation sequence prioritized strictly by operational complexity, workload downtime impact, and security posture uplift.</p>
            </div>
            <span class="hero-badge">Priority Principle: Zero-Downtime High-Impact First</span>
        </div>

        <div class="order-container">
            <!-- Tier 1 -->
            <div class="order-card tier1">
                <div class="order-badge">
                    <div class="order-num">01</div>
                    <div class="order-label">Stage 01</div>
                </div>
                <div class="order-info">
                    <h3>Critical Perimeter Shield: Account-Level S3 BPA</h3>
                    <div class="order-meta">
                        <span class="meta-pill">🔧 Complexity: <strong>Minimal (1 Action per Root)</strong></span>
                        <span class="meta-pill safe">⚡ Downtime: <strong>100% Zero Workload Impact</strong></span>
                        <span class="meta-pill" style="color:var(--accent-red);">🛡️ Risk Impact: <strong>Critical Risk Elimination</strong></span>
                        <span class="meta-pill">🎯 Scope: <strong>Accounts 679414842598 & 908140080081</strong></span>
                    </div>
                    <p class="order-details">
                        Closes the 2 Critical audit findings. Applies universal S3 Account Public Access Block to ensure no current or future S3 bucket can ever be inadvertently exposed to the internet.
                    </p>
                </div>
                <div class="order-cta">
                    <button class="btn btn-outline" onclick="showRemediation('p0')">View CLI Commands</button>
                </div>
            </div>

            <!-- Tier 2 -->
            <div class="order-card tier2">
                <div class="order-badge">
                    <div class="order-num">02</div>
                    <div class="order-label">Stage 02</div>
                </div>
                <div class="order-info">
                    <h3>Zero-Impact Quick Wins Campaign (248 Actions)</h3>
                    <div class="order-meta">
                        <span class="meta-pill">🔧 Complexity: <strong>Low (Automated Scriptable)</strong></span>
                        <span class="meta-pill safe">⚡ Downtime: <strong>100% Zero Workload Impact</strong></span>
                        <span class="meta-pill" style="color:var(--accent-cyan);">🛡️ Risk Impact: <strong>18.6% Immediate Posture Lift</strong></span>
                        <span class="meta-pill">🎯 Scope: <strong>All 4 Accounts</strong></span>
                    </div>
                    <p class="order-details">
                        Revokes inbound rules on 30 Default Security Groups, activates EBS Default Encryption across 70 regions, enables S3 Versioning on 106 buckets, and aligns IAM Password Policies.
                    </p>
                </div>
                <div class="order-cta">
                    <button class="btn btn-outline" onclick="showRemediation('p1')">View CLI Commands</button>
                </div>
            </div>

            <!-- Tier 3 -->
            <div class="order-card tier3">
                <div class="order-badge">
                    <div class="order-num">03</div>
                    <div class="order-label">Stage 03</div>
                </div>
                <div class="order-info">
                    <h3>Foundational Telemetry & In-Transit Encryption</h3>
                    <div class="order-meta">
                        <span class="meta-pill">🔧 Complexity: <strong>Moderate (Policy Configuration)</strong></span>
                        <span class="meta-pill safe">⚡ Downtime: <strong>Non-Breaking Configuration</strong></span>
                        <span class="meta-pill" style="color:var(--accent-blue);">🛡️ Risk Impact: <strong>Complete Traffic Telemetry</strong></span>
                        <span class="meta-pill">🎯 Scope: <strong>All 4 Accounts</strong></span>
                    </div>
                    <p class="order-details">
                        Enforces TLS/HTTPS bucket policies across 142 S3 buckets, activates VPC Flow Logs across 28 VPCs, and provisions 840 CIS CloudWatch metric filters and alarm subscriptions.
                    </p>
                </div>
                <div class="order-cta">
                    <button class="btn btn-outline" onclick="showRemediation('p2')">View Telemetry Plan</button>
                </div>
            </div>

            <!-- Tier 4 -->
            <div class="order-card tier4">
                <div class="order-badge">
                    <div class="order-num">04</div>
                    <div class="order-label">Stage 04</div>
                </div>
                <div class="order-info">
                    <h3>Enterprise Guardrails & Continuous Compliance (SCPs)</h3>
                    <div class="order-meta">
                        <span class="meta-pill">🔧 Complexity: <strong>Low-Moderate (Org Policy Attachment)</strong></span>
                        <span class="meta-pill safe">⚡ Downtime: <strong>Zero Service Interruption</strong></span>
                        <span class="meta-pill" style="color:var(--accent-purple);">🛡️ Risk Impact: <strong>100% Regression Prevention</strong></span>
                        <span class="meta-pill">🎯 Scope: <strong>AWS Organizations Root</strong></span>
                    </div>
                    <p class="order-details">
                        Deploys Service Control Policies to the Organization Root to block non-compliant resource creation permanently, and activates AWS Config Conformance Pack for continuous automated audit reporting.
                    </p>
                </div>
                <div class="order-cta">
                    <button class="btn btn-outline" onclick="showRemediation('p3')">View SCP Policies</button>
                </div>
            </div>
        </div>

        <!-- Section 3: Account-by-Account Breakdown -->
        <div class="section-header" id="accounts">
            <div>
                <h2>Account Concentration & Risk Prioritization</h2>
                <p>Prioritizing remediations in high-density accounts yields the fastest posture improvement.</p>
            </div>
        </div>

        <div class="account-table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Account ID</th>
                        <th>Account Name</th>
                        <th>Total Checks</th>
                        <th>Zero-Impact Wins</th>
                        <th>Critical</th>
                        <th>High</th>
                        <th>Medium</th>
                        <th>Recommended Next Step</th>
                    </tr>
                </thead>
                <tbody>
"""

    for aid, a in sorted_accounts:
        crit_badge = f'<span class="badge badge-red">{a["critical"]}</span>' if a["critical"] > 0 else '<span style="color:var(--text-dim);">0</span>'
        high_badge = f'<span class="badge badge-amber">{a["high"]}</span>' if a["high"] > 0 else '0'
        zw_badge = f'<span class="badge badge-cyan">{a["zero_wins"]} Quick Wins</span>'
        
        step = "Deploy S3 BPA + Default SG Revoke" if a["critical"] > 0 else "Default SG Revoke + EBS Default Encryption"
        
        html_template += f"""
                    <tr>
                        <td style="font-family: monospace; font-weight: 700; color: #38bdf8;">{aid}</td>
                        <td><strong>{a["name"]}</strong></td>
                        <td><strong>{a["total"]}</strong></td>
                        <td>{zw_badge}</td>
                        <td>{crit_badge}</td>
                        <td>{high_badge}</td>
                        <td>{a["medium"]}</td>
                        <td><span style="font-size:0.8rem; color:var(--text-muted);">{step}</span></td>
                    </tr>
        """

    html_template += f"""
                </tbody>
            </table>
        </div>

        <!-- Section 4: Interactive Findings Explorer -->
        <div class="section-header" id="explorer">
            <div>
                <h2>Interactive Findings Explorer (1,336 Evaluated Checks)</h2>
                <p>Filter by domain, account, severity, or impact to inspect specific resource findings and remediations.</p>
            </div>
            <div style="font-size: 0.85rem; color: var(--text-dim);" id="filteredCount">Showing 1,336 findings</div>
        </div>

        <div class="explorer-controls">
            <input type="text" id="searchInput" placeholder="Search resource ID, rule name, or CLI..." oninput="filterTable()">
            <select id="domainSelect" onchange="filterTable()">
                <option value="">All Domains</option>
                <option value="Logging">Logging & Monitoring (878)</option>
                <option value="Storage">Storage & Backup (390)</option>
                <option value="Network">Network & Perimeter (58)</option>
                <option value="IAM">IAM & Governance (10)</option>
            </select>
            <select id="accountSelect" onchange="filterTable()">
                <option value="">All Accounts</option>
                <option value="908140080081">RUS-AWS-EXT-ROOTADMINs (908140080081)</option>
                <option value="191952776710">Account-191952776710</option>
                <option value="679414842598">RicohRootAcct (679414842598)</option>
                <option value="599434579961">Account-599434579961</option>
            </select>
            <select id="impactSelect" onchange="filterTable()">
                <option value="">All Impacts</option>
                <option value="ZERO_IMPACT_QUICK_WIN">Zero-Impact Quick Wins Only (248)</option>
                <option value="LOW_IMPACT_CONFIG">Low-Impact Config</option>
            </select>
            <select id="severitySelect" onchange="filterTable()">
                <option value="">All Severities</option>
                <option value="CRITICAL">Critical (2)</option>
                <option value="HIGH">High (240)</option>
                <option value="MEDIUM">Medium (1,088)</option>
                <option value="LOW">Low (6)</option>
            </select>
        </div>

        <div class="account-table-wrap" style="max-height: 520px; overflow-y: auto;">
            <table>
                <thead style="position: sticky; top: 0; z-index: 10;">
                    <tr>
                        <th>Domain</th>
                        <th>Rule Name</th>
                        <th>Severity</th>
                        <th>Impact</th>
                        <th>Resource ID</th>
                        <th>Account / Region</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="findingsBody">
                    <!-- Populated by JavaScript -->
                </tbody>
            </table>
        </div>

        <!-- Section 5: Continuous Guardrails & Prevention (SCPs) -->
        <div class="section-header" id="guardrails" style="margin-top: 40px;">
            <div>
                <h2>Automated Continuous Guardrails (SCPs & AWS Config)</h2>
                <p>Prevent future infrastructure from violating enterprise security baselines.</p>
            </div>
        </div>

        <div class="matrix-grid" style="grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));">
            <div class="matrix-quadrant">
                <span class="quadrant-tag tag-q1">Preventive Guardrail</span>
                <div class="quadrant-title">S3 Data Protection SCP</div>
                <p class="quadrant-desc"><code>controls/scps/scp_guardrail_s3.json</code></p>
                <p style="font-size: 0.85rem; color: var(--text-muted);">
                    Denies any attempt to disable S3 Account Block Public Access, blocks non-SSL HTTP calls, and rejects unencrypted object uploads at the AWS Organization boundary.
                </p>
            </div>
            <div class="matrix-quadrant">
                <span class="quadrant-tag tag-q2">Preventive Guardrail</span>
                <div class="quadrant-title">Encryption at Rest SCP</div>
                <p class="quadrant-desc"><code>controls/scps/scp_guardrail_encryption.json</code></p>
                <p style="font-size: 0.85rem; color: var(--text-muted);">
                    Denies disabling default EBS encryption, prevents launching unencrypted EBS volumes or unencrypted RDS databases, and blocks unauthorized KMS key deletions.
                </p>
            </div>
            <div class="matrix-quadrant">
                <span class="quadrant-tag tag-q4">Continuous Detection</span>
                <div class="quadrant-title">AWS Config Conformance Pack</div>
                <p class="quadrant-desc"><code>controls/config_rules/conformance_pack_security_baseline.yaml</code></p>
                <p style="font-size: 0.85rem; color: var(--text-muted);">
                    Provides 24/7 automated compliance tracking against all 170+ rules with automatic evaluation whenever resources are created or modified.
                </p>
            </div>
        </div>

    </div>

    <!-- Remediation Detail Modal -->
    <div class="modal" id="remModal">
        <div class="modal-card">
            <div class="modal-header">
                <h3 id="modalTitle">Remediation Action Plan</h3>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <p id="modalDesc" style="font-size: 0.88rem; color: var(--text-muted); margin-bottom: 12px;"></p>
            <div style="font-size: 0.75rem; font-weight: 700; text-transform: uppercase; color: var(--text-dim); margin-top: 10px;">Executive Business Rationale:</div>
            <p id="modalRationale" style="font-size: 0.85rem; color: var(--accent-cyan); margin: 4px 0 14px;"></p>
            <div style="display: flex; justify-content: space-between; align-items: center;">
                <div style="font-size: 0.75rem; font-weight: 700; text-transform: uppercase; color: var(--text-dim);">AWS CLI Copy-Paste Execution:</div>
                <button class="btn btn-outline" style="padding: 4px 10px; font-size: 0.75rem;" onclick="copyModalCli()">📋 Copy Command</button>
            </div>
            <pre class="code-block" id="modalCli"></pre>
            <div style="text-align: right; margin-top: 16px;">
                <button class="btn btn-outline" onclick="closeModal()">Close</button>
            </div>
        </div>
    </div>

    <script>
        const FINDINGS_DATA = {payload_json};

        function toggleTheme() {{
            document.body.classList.toggle('light-theme');
        }}

        const REM_DATA = {{
            p0: {{
                title: "Stage 01: Critical S3 Block Public Access (P0)",
                desc: "Executes across Management accounts. 100% Zero Downtime. Protects all current and future S3 buckets from accidental public leaks.",
                rationale: "Zero workload downtime. Universal safety net preventing 100% of accidental bucket leaks across the entire account.",
                cli: `# Apply to Account 679414842598\\naws s3control put-public-access-block --account-id 679414842598 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true\\n\\n# Apply to Account 908140080081\\naws s3control put-public-access-block --account-id 908140080081 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true`
            }},
            p1: {{
                title: "Stage 02: Zero-Impact Quick Wins (248 Actions)",
                desc: "Executes 100% safe isolations and security toggles with zero downtime on running workloads.",
                rationale: "Default SGs cannot be deleted; revoking ingress isolates them cleanly. EBS default encryption transparently protects future volumes with zero disruption.",
                cli: `# 1. Enable EBS Default Encryption across all active regions\\nfor reg in us-east-1 us-east-2 us-west-1 us-west-2 eu-west-1 eu-central-1 ap-northeast-1; do\\n  aws ec2 enable-ebs-encryption-by-default --region $reg\\ndone\\n\\n# 2. Revoke default Security Group ingress rules (Isolates default SGs)\\naws ec2 revoke-security-group-ingress --group-id <default_sg_id> --protocol -1 --port -1 --source-group <default_sg_id> --region <region>\\n\\n# 3. Enforce IAM Enterprise Password Policy\\naws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24`
            }},
            p2: {{
                title: "Stage 03: Telemetry & In-Transit Encryption",
                desc: "Safe configuration of VPC Flow Logs and TLS bucket policies without interrupting traffic.",
                rationale: "Enables continuous network packet forensics and guarantees all object transfers use cryptographic TLS tunnels.",
                cli: `# 1. Enable VPC Flow Logs for network traffic visibility\\naws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc_id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flow-logs/<vpc_id>\\n\\n# 2. Attach Deny-Non-SSL S3 Bucket Policy\\naws s3api put-bucket-policy --bucket <bucket_name> --policy file://deny_non_ssl_policy.json`
            }},
            p3: {{
                title: "Stage 04: Continuous Guardrails & SCP Deployment",
                desc: "Deploy organization guardrails to permanently eliminate security regressions.",
                rationale: "Automated continuous guardrails ensure security gains are locked in permanently and block shadow IT creation.",
                cli: `# 1. Deploy AWS Organizations Service Control Policy\\naws organizations create-policy --name EnforceS3Security --type SERVICE_CONTROL_POLICY --content file://controls/scps/scp_guardrail_s3.json\\n\\n# 2. Deploy AWS Config Organization Conformance Pack\\naws configservice put-organization-conformance-pack --organization-conformance-pack-name EnterpriseSecurityBaseline --template-body file://controls/config_rules/conformance_pack_security_baseline.yaml`
            }}
        }};

        function showRemediation(key) {{
            const data = REM_DATA[key];
            if (!data) return;
            document.getElementById('modalTitle').innerText = data.title;
            document.getElementById('modalDesc').innerText = data.desc;
            document.getElementById('modalRationale').innerText = data.rationale || '';
            document.getElementById('modalCli').innerText = data.cli;
            document.getElementById('remModal').classList.add('active');
        }}

        function showFindingDetail(idx) {{
            const f = currentFindings[idx];
            if (!f) return;
            document.getElementById('modalTitle').innerText = f.RuleName;
            document.getElementById('modalDesc').innerText = `${{f.Description}} (Resource: ${{f.ResourceId}})`;
            document.getElementById('modalRationale').innerText = f.ImpactRationale || 'Safe operational remediation.';
            document.getElementById('modalCli').innerText = f.RemediationCLI || 'No CLI required.';
            document.getElementById('remModal').classList.add('active');
        }}

        function copyModalCli() {{
            const cliText = document.getElementById('modalCli').innerText;
            navigator.clipboard.writeText(cliText).then(() => {{
                alert('Remediation command copied to clipboard!');
            }});
        }}

        function closeModal() {{
            document.getElementById('remModal').classList.remove('active');
        }}

        window.onclick = function(e) {{
            if (e.target.classList.contains('modal')) closeModal();
        }};

        // Findings Explorer Logic
        let currentFindings = [];
        function filterTable() {{
            const q = (document.getElementById('searchInput').value || '').toLowerCase();
            const dom = document.getElementById('domainSelect').value;
            const acc = document.getElementById('accountSelect').value;
            const imp = document.getElementById('impactSelect').value;
            const sev = document.getElementById('severitySelect').value;

            currentFindings = FINDINGS_DATA.filter(f => {{
                if (dom && f.Domain !== dom) return false;
                if (acc && f.AccountId !== acc) return false;
                if (imp && f.RemediationImpact !== imp) return false;
                if (sev && f.Severity !== sev) return false;
                if (q) {{
                    const match = (f.RuleName || '').toLowerCase().includes(q) ||
                                  (f.ResourceId || '').toLowerCase().includes(q) ||
                                  (f.RemediationCLI || '').toLowerCase().includes(q) ||
                                  (f.AccountId || '').toLowerCase().includes(q);
                    if (!match) return false;
                }}
                return true;
            }});

            document.getElementById('filteredCount').innerText = `Showing ${{currentFindings.length.toLocaleString()}} of ${{FINDINGS_DATA.length.toLocaleString()}} findings`;
            renderTable();
        }}

        function renderTable() {{
            const tbody = document.getElementById('findingsBody');
            tbody.innerHTML = '';

            const slice = currentFindings.slice(0, 150);
            if (slice.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding: 24px; color: var(--text-dim);">No matching findings found.</td></tr>';
                return;
            }}

            slice.forEach((f, idx) => {{
                const tr = document.createElement('tr');
                const sevBadge = f.Severity === 'CRITICAL' ? 'badge-red' : (f.Severity === 'HIGH' ? 'badge-amber' : 'badge-blue');
                const impBadge = f.RemediationImpact === 'ZERO_IMPACT_QUICK_WIN' ? 'badge-cyan' : 'badge-blue';
                const impText = f.RemediationImpact === 'ZERO_IMPACT_QUICK_WIN' ? 'Zero-Impact Win' : 'Low-Impact';

                tr.innerHTML = `
                    <td><strong>${{f.Domain}}</strong></td>
                    <td>${{f.RuleName}}</td>
                    <td><span class="badge ${{sevBadge}}">${{f.Severity}}</span></td>
                    <td><span class="badge ${{impBadge}}">${{impText}}</span></td>
                    <td style="font-family:monospace; color:#38bdf8;">${{f.ResourceId}}</td>
                    <td>${{f.AccountName || f.AccountId}}<br/><small style="color:var(--text-dim);">${{f.Region}}</small></td>
                    <td><button class="btn btn-outline" style="padding:4px 8px; font-size:0.75rem;" onclick="showFindingDetail(${{idx}})">Details</button></td>
                `;
                tbody.appendChild(tr);
            }});
        }}

        window.onload = function() {{
            filterTable();
        }};
    </script>
</body>
</html>
"""

    with open(out_html, "w", encoding="utf-8") as f:
        f.write(html_template)

    # Also save to conversation artifacts directory for in-chat/IDE viewing
    artifact_dir = r"C:\Users\karu\.gemini\antigravity\brain\17ae7d5f-fd1e-482a-abac-5ec857b0af00"
    artifact_html = os.path.join(artifact_dir, "executive_leadership_portal.html")
    with open(artifact_html, "w", encoding="utf-8") as f:
        f.write(html_template)

    print(f"Executive Leadership Portal successfully regenerated without timelines:")
    print(f"  Local Workspace: {out_html}")
    print(f"  Artifact Copy:   {artifact_html}")

if __name__ == "__main__":
    build_portal()
