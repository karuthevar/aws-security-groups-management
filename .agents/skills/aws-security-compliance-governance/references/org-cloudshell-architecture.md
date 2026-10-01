# Multi-Account Organization & CloudShell Architecture Standard

## 1. AWS Organization Root Execution Model

Enterprise governance scripts must be designed to execute from the **AWS Organization Management (Root) Account** (typically within **AWS CloudShell**). This eliminates the need to configure local credentials, manage bastion hosts, or distribute sensitive API keys.

```text
+-------------------------------------------------------------+
|             AWS Organization Management Account             |
|                   (CloudShell Environment)                  |
|                                                             |
|   1. Discover Active Member Accounts via Organizations API  |
|   2. Iterate Accounts & AWS Regions                        |
+------------------------------+------------------------------+
                               |
            Assume IAM Role via sts:AssumeRole
                               |
       +-----------------------+-----------------------+
       |                                               |
       v                                               v
+-------------------------------+       +-------------------------------+
|     Member Account A          |       |     Member Account B          |
|  (Core Infrastructure / Net)  |       |     (Workload / Prod App)     |
|                               |       |                               |
|  - Role: OrgAccountAccessRole |       |  - Role: AWSControlTowerExec  |
|  - Regional Scans / Audits    |       |  - Regional Scans / Audits    |
|  - Local Remediation API      |       |  - Local Remediation API      |
+-------------------------------+       +-------------------------------+
```

---

## 2. Dynamic Account Discovery & Role Assumption

### Account Discovery
Never hardcode AWS account IDs or account counts. Dynamically discover all active accounts:
```bash
get_organization_accounts() {
    local specific_accounts="$1"
    if [[ -n "${specific_accounts}" ]]; then
        # Parse comma-separated list
        echo "${specific_accounts}" | tr ',' '\n' | jq -R '{Id: ., Name: "ExplicitTarget"}' | jq -s .
        return 0
    fi

    # Query active accounts from AWS Organizations
    aws organizations list-accounts \
        --query 'Accounts[?Status==`ACTIVE`].[Id,Name]' \
        --output json 2>/dev/null | jq '[.[] | {Id: .[0], Name: .[1]}]'
}
```

### Resilient Role Assumption Fallback Chain
Different accounts in an enterprise may have been provisioned through AWS Organizations, AWS Control Tower, or manual account invitations. The script must cycle through a fallback array:
```bash
FALLBACK_ROLES=(
    "OrganizationAccountAccessRole"
    "AWSControlTowerExecution"
    "AdministratorAccess"
)

assume_account_role() {
    local target_acc="$1"
    local role_name="$2"
    local session_name="${3:-GovernanceSession}"

    if [[ "${target_acc}" == "${CURRENT_ACCOUNT_ID}" ]]; then
        clear_assumed_role
        return 0
    fi

    local creds
    creds=$(aws sts assume-role \
        --role-arn "arn:aws:iam::${target_acc}:role/${role_name}" \
        --role-session-name "${session_name}" \
        --duration-seconds 3600 \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text 2>/dev/null)

    if [[ -n "${creds}" ]]; then
        export AWS_ACCESS_KEY_ID=$(echo "${creds}" | awk '{print $1}')
        export AWS_SECRET_ACCESS_KEY=$(echo "${creds}" | awk '{print $2}')
        export AWS_SESSION_TOKEN=$(echo "${creds}" | awk '{print $3}')
        return 0
    fi
    return 1
}
```

---

## 3. CloudShell Compatibility Standards

AWS CloudShell provides a pre-authenticated Amazon Linux 2023 environment. All governance tools must conform to these environment rules:

### 1. Pure Standard Tooling
* **Permitted**: Bash (4.x+), `jq`, Python 3 standard library (`json`, `html`, `sys`, `pathlib`, `urllib`, `collections`).
* **Forbidden**: External Python packages requiring `pip install` (e.g. `requests`, `pandas`, `boto3` outside standard system path). Scripts must run immediately upon cloning.

### 2. Zero External CDN Dependencies
* CloudShell sessions, corporate laptops, or VPC endpoints may block external CDNs (`cdnjs.cloudflare.com`, `cdn.tailwindcss.com`, `fonts.googleapis.com`).
* **Rule**: All generated HTML dashboards must embed CSS directly (`<style>`), use embedded SVG vector icons directly, and bundle vanilla JavaScript for interactive filtering.

### 3. Dual-Format Reporting (JSON + HTML)
Every audit and remediation run must generate:
1. `reports/<domain>_audit_<timestamp>.json`: Machine-readable raw dataset for programmatic pipelines.
2. `reports/<domain>_audit_<timestamp>.html`: Fully self-contained, interactive executive dashboard with search, filtering, and summary metrics.

---

## 4. Multi-Account Consolidation Pattern

When auditing multi-account estates, each domain should generate account-specific findings and write them to a structured consolidation schema:

```json
[
  {
    "AccountId": "111122223333",
    "AccountName": "Network-Hub",
    "Region": "us-east-1",
    "Domain": "Network",
    "RuleId": "TGW_AUTO_ACCEPT_SHARED_ATTACHMENTS_DISABLED",
    "RuleTitle": "EC2 Transit Gateway Auto Cross-Account Attachment Disabled",
    "Severity": "HIGH",
    "Status": "NON_COMPLIANT",
    "ResourceId": "tgw-0123456789abcdef0",
    "ResourceType": "AWS::EC2::TransitGateway",
    "RemediationImpact": "ZERO_IMPACT_QUICK_WIN",
    "RemediationComplexity": "LOW",
    "RemediationCommand": "aws ec2 modify-transit-gateway --transit-gateway-id tgw-0123456789abcdef0 --options AutoAcceptSharedAttachments=disable --region us-east-1",
    "PreventiveConfigRule": "transit-gateway-auto-approval-check",
    "PreventiveSCP": "DenyUnapprovedTransitGatewayModification",
    "DowntimeDetails": "100% Zero Workload Downtime. Disabling auto-acceptance does not affect existing attachments or active traffic."
  }
]
```
