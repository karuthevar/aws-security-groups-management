---
name: aws-security-compliance-governance
description: >-
  Enterprise runbooks, audit standards, risk-prioritization frameworks, and safe remediation automation for AWS multi-account security compliance. Enforces execution from the AWS Organization Management (Root) account or CloudShell, cross-account role traversal, strict zero-timeline prioritization (driven strictly by zero-downtime impact and complexity), dual JSON/HTML offline reporting, three-tier preventive guardrails (SCPs and AWS Config conformance packs), and non-destructive dry-run remediation with automatic backup and rollback.
---

# AWS Enterprise Security Compliance & Governance Skill

This skill codifies end-to-end procedures, architectural standards, runbooks, and scripts for auditing, prioritizing, remediating, and preventing security misconfigurations across multi-account AWS Organizations.

---

## ⚡ Quick Reference

| Action / Capability | Script / Artifact | Target Environment | Documentation |
| :--- | :--- | :--- | :--- |
| **All-in-One Org Audit** | [`audit_all_domains.sh`](file:///c:/antigravity-projects/security%20group/audit_all_domains.sh) | **Org Root (Management) Account** | [Architecture Standard](./references/org-cloudshell-architecture.md) |
| **Network & TGW Audit** | [`audit_network.sh`](file:///c:/antigravity-projects/security%20group/audit_network.sh) | Org Root / CloudShell | [Architecture Standard](./references/org-cloudshell-architecture.md) |
| **Transit Gateway Auto-Accept Fix** | [`disable_tgw_auto_accept.sh`](file:///c:/antigravity-projects/security%20group/disable_tgw_auto_accept.sh) | Org Root / CloudShell | [Remediation Playbook](./references/remediation-safety-playbook.md) |
| **Unattached SG Cleanup & Backup** | [`cleanup_security_groups.sh`](file:///c:/antigravity-projects/security%20group/cleanup_security_groups.sh) | Org Root / CloudShell | [Remediation Playbook](./references/remediation-safety-playbook.md) |
| **Security Group Rollback** | [`restore_security_groups.sh`](file:///c:/antigravity-projects/security%20group/restore_security_groups.sh) | Org Root / CloudShell | [Remediation Playbook](./references/remediation-safety-playbook.md) |
| **Report Consolidation** | [`consolidate-reports.py`](./scripts/consolidate-reports.py) | Local or CloudShell | [Executive Portal Spec](./references/executive-portal-spec.md) |
| **Executive Leadership Portal** | [`portal/index.html`](file:///c:/antigravity-projects/security%20group/portal/index.html) | Local Browser (Offline) | [Executive Portal Spec](./references/executive-portal-spec.md) |
| **Continuous Compliance Pack** | [`conformance_pack_security_baseline.yaml`](file:///c:/antigravity-projects/security%20group/controls/config_rules/conformance_pack_security_baseline.yaml) | AWS Config (Org-wide) | [Preventive Guardrails](./references/preventive-guardrails-spec.md) |
| **Organization SCP Guardrails** | [`controls/scps/`](file:///c:/antigravity-projects/security%20group/controls/scps/) | AWS Organizations Root / OU | [Preventive Guardrails](./references/preventive-guardrails-spec.md) |

---

## 🏛️ The Five Core Governance Principles

### 1. Strictly Zero Timelines
**NEVER** introduce calendar dates, days, weeks, or time estimates into audit reports, remediation roadmaps, or leadership portals.
Prioritization is strictly calculated on:
* **Downtime & Operational Impact**: `ZERO_IMPACT_QUICK_WIN` (100% Zero Downtime) vs `LOW_IMPACT_REVIEW` vs `HIGH_RISK_PLANNED_WINDOW`.
* **Implementation Complexity**: Low, Medium, High.
* **Security Posture Uplift**: Critical, High, Medium, Low.
*(Refer to [Impact Classification Matrix](./references/impact-classification-matrix.md) for full breakdown).*

### 2. Multi-Account Root Execution
All tools execute directly from the **AWS Organization Management (Root) Account** (typically AWS CloudShell) and traverse member accounts using cross-account IAM role assumption:
* Priority 1: `OrganizationAccountAccessRole`
* Priority 2: `AWSControlTowerExecution`
* Priority 3: `AdministratorAccess`

### 3. Dual-Format Offline Reporting
Every audit run automatically generates:
* Machine-readable JSON in `reports/` for programmatic processing.
* Fully self-contained, interactive HTML dashboards in `reports/` with embedded CSS and SVGs (zero external CDN calls, works 100% offline).

### 4. Safe Remediation with Rollback Backups
Remediation scripts default to `--dry-run`. Modifications require explicit `--execute` and interactive `CONFIRM` input. Before touching any resource, full configuration state is archived to `backups/` and a restoration script is provided.

### 5. Triple-Layer Defense-in-Depth
Every remediated issue must have:
1. **Preventive Guardrail**: Organization SCP blocking non-compliant API calls.
2. **Detective Control**: AWS Config managed rule in the baseline Conformance Pack.
3. **Automated Scanner / Fixer**: Script to audit and remediate across all accounts.

---

## 📋 Standard Runbooks

### Runbook 1: Executing Full Organization Audit (CloudShell)
To scan all active member accounts and regions across all five security domains (Network, IAM, Storage, Database, Logging/Monitoring):
```bash
# 1. Run all audits in a single invocation:
./audit_all_domains.sh

# 2. Or run individual domains independently:
./audit_network.sh
./audit_iam.sh
./audit_storage.sh
./audit_databases.sh
./audit_logging_monitoring.sh
```

### Runbook 2: Remediating Transit Gateway Auto-Accept Across Org
To eliminate cross-account trust risks by disabling `AutoAcceptSharedAttachments` (100% Zero Workload Downtime):
```bash
# Step 1: Preview affected Transit Gateways across all accounts/regions (Dry Run)
./disable_tgw_auto_accept.sh

# Step 2: Apply remediation with interactive confirmation
./disable_tgw_auto_accept.sh --execute

# Step 3: Or run non-interactively for specific accounts
./disable_tgw_auto_accept.sh --execute --yes --accounts 111122223333,444455556666
```

### Runbook 3: Consolidating Reports & Generating Executive Portal
To roll up multiple audit reports into a single consolidated view and launch the leadership portal:
```bash
# 1. Consolidate raw JSON reports into a single manifest:
python scripts/consolidate-reports.py --reports-dir ./reports --output ./reports/consolidated_audit_report.json

# 2. Build the self-contained leadership portal:
python scripts/build_executive_portal.py --reports-dir ./reports --output ./portal/index.html

# 3. View the portal locally on your laptop:
open portal/index.html   # On macOS
start portal/index.html  # On Windows
```

### Runbook 4: Deploying Preventive Organization Guardrails
To prevent future creation of non-compliant resources:
```bash
# 1. Deploy continuous AWS Config conformance pack org-wide:
aws configservice put-organization-conformance-pack \
    --organization-conformance-pack-name OrgSecurityBaseline \
    --template-body file://controls/config_rules/conformance_pack_security_baseline.yaml

# 2. Attach SCP guardrails to target Organizational Units (OUs):
aws organizations create-policy \
    --name SCPGuardrailNetwork \
    --type SERVICE_CONTROL_POLICY \
    --content file://controls/scps/scp_guardrail_network.json
```

---

## 🔒 Git & Data Hygiene Checklist
Before committing any changes to Git:
* [x] Verify `.gitignore` ignores `reports/`, `backups/`, `.tmp_raw*`, `*.html`, and credentials.
* [x] Ensure no actual AWS infrastructure JSON exports or account vulnerability dumps are staged.
* [x] Validate all automated test suites:
  ```bash
  bash test/run_tests.sh
  ```
