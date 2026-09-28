#!/usr/bin/env bash
# ==============================================================================
# AWS Enterprise Security & Compliance Assessment Suite
# Script: audit_all.sh
# Purpose: Master runner executing security & compliance audits across 7 domains
#          (IAM, Network, Logging, Storage, Compute, Databases, Encryption).
#          Consolidates all findings into a unified interactive HTML dashboard
#          and emphasizes Zero-Impact Quick Wins with exact CLI & SCP guardrails.
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

ROLE_NAME="${ROLE_NAME:-OrganizationAccountAccessRole}"
SPECIFIC_ACCOUNTS=""
SPECIFIC_REGIONS=""
OUTPUT_DIR="${SCRIPT_DIR}/reports"
GENERATE_HTML=true
MODULES="iam,network,logging,storage,compute,database,encryption"

show_help() {
    cat << EOF
AWS Enterprise Security Assessment Master Suite
Executes comprehensive compliance and security audits across AWS Organization accounts.

USAGE:
    ./audit_all.sh [OPTIONS]

OPTIONS:
    -m, --modules <MOD,MOD...>  Comma-separated list of audit domains to execute:
                                [iam, network, logging, storage, compute, database, encryption]
                                Default: all domains.
    -r, --role-name <ROLE>      IAM Role to assume in member accounts.
                                Default: OrganizationAccountAccessRole
    -a, --accounts <ID,ID...>   Comma-separated list of target Account IDs.
                                Default: All ACTIVE accounts in AWS Organization.
    -g, --regions <REG,REG...>  Comma-separated list of AWS Regions to scan.
                                Default: All enabled regions in each account.
    -o, --output-dir <DIR>      Output directory for consolidated reports.
                                Default: ./reports
    --no-html                   Skip generating unified interactive HTML dashboard.
    -h, --help                  Show this help message.

INDIVIDUAL MODULE RUNNERS:
    ./audit_iam.sh                    IAM, Root Account & Password Policies
    ./audit_network.sh                VPC Flow Logs, Unattached EIPs, NACLs, SGs
    ./audit_logging_monitoring.sh     CloudTrail, CloudWatch & CIS Alarms
    ./audit_storage_backup.sh         S3 BPA, SSL, Versioning, Unattached EBS
    ./audit_compute.sh                EC2 Stale Stopped Instances (>30 Days)
    ./audit_databases.sh              RDS Deletion Protection & DynamoDB PITR
    ./audit_encryption_security.sh    KMS Rotation, GuardDuty, Security Hub, ECR, ELB

EXAMPLES:
    # Run full assessment across entire AWS Organization
    ./audit_all.sh

    # Run only IAM and Network modules on specific accounts
    ./audit_all.sh --modules iam,network --accounts 111122223333,444455556666

    # Run in specific regions
    ./audit_all.sh --regions us-east-1,us-west-2

EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--modules|--module) MODULES="$2"; shift 2 ;;
        -r|--role|--role-name) ROLE_NAME="$2"; shift 2 ;;
        -a|--accounts) SPECIFIC_ACCOUNTS="$2"; shift 2 ;;
        -g|--regions|--region) SPECIFIC_REGIONS="$2"; shift 2 ;;
        -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --no-html) GENERATE_HTML=false; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

log_header "AWS Enterprise Security & Compliance Assessment Suite"
check_prerequisites

mkdir -p "${OUTPUT_DIR}"

MASTER_JSON="${OUTPUT_DIR}/enterprise_compliance_report.json"
MASTER_HTML="${OUTPUT_DIR}/enterprise_compliance_report.html"

# Discover account & region summary
ACCOUNTS_JSON=$(get_organization_accounts "${SPECIFIC_ACCOUNTS}")
ACCOUNT_COUNT=$(echo "${ACCOUNTS_JSON}" | jq '. | length')

IFS=',' read -ra MOD_LIST <<< "${MODULES}"
log_info "Selected Audit Domains: ${MODULES}"
log_info "Target Accounts: ${ACCOUNT_COUNT}"

# Common argument flags to pass down to modules
CHILD_ARGS=("-o" "${OUTPUT_DIR}" "-r" "${ROLE_NAME}")
[[ -n "${SPECIFIC_ACCOUNTS}" ]] && CHILD_ARGS+=("-a" "${SPECIFIC_ACCOUNTS}")
[[ -n "${SPECIFIC_REGIONS}" ]] && CHILD_ARGS+=("-g" "${SPECIFIC_REGIONS}")

# Execute each selected module
MODULE_JSON_FILES=()

for mod in "${MOD_LIST[@]}"; do
    mod=$(echo "$mod" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')
    case "$mod" in
        iam)
            log_header "Executing IAM Audit Module..."
            bash "${SCRIPT_DIR}/audit_iam.sh" "${CHILD_ARGS[@]}" || true
            MODULE_JSON_FILES+=("${OUTPUT_DIR}/compliance_report_iam.json")
            ;;
        network)
            log_header "Executing Network Audit Module..."
            bash "${SCRIPT_DIR}/audit_network.sh" "${CHILD_ARGS[@]}" || true
            MODULE_JSON_FILES+=("${OUTPUT_DIR}/compliance_report_network.json")
            ;;
        logging)
            log_header "Executing Logging & Monitoring Audit Module..."
            bash "${SCRIPT_DIR}/audit_logging_monitoring.sh" "${CHILD_ARGS[@]}" || true
            MODULE_JSON_FILES+=("${OUTPUT_DIR}/compliance_report_logging.json")
            ;;
        storage)
            log_header "Executing Storage & Backup Audit Module..."
            bash "${SCRIPT_DIR}/audit_storage_backup.sh" "${CHILD_ARGS[@]}" || true
            MODULE_JSON_FILES+=("${OUTPUT_DIR}/compliance_report_storage.json")
            ;;
        compute)
            log_header "Executing Compute Audit Module..."
            bash "${SCRIPT_DIR}/audit_compute.sh" "${CHILD_ARGS[@]}" || true
            MODULE_JSON_FILES+=("${OUTPUT_DIR}/compliance_report_compute.json")
            ;;
        database|databases)
            log_header "Executing Databases Audit Module..."
            bash "${SCRIPT_DIR}/audit_databases.sh" "${CHILD_ARGS[@]}" || true
            MODULE_JSON_FILES+=("${OUTPUT_DIR}/compliance_report_databases.json")
            ;;
        encryption|security)
            log_header "Executing Encryption & Security Tooling Audit Module..."
            bash "${SCRIPT_DIR}/audit_encryption_security.sh" "${CHILD_ARGS[@]}" || true
            MODULE_JSON_FILES+=("${OUTPUT_DIR}/compliance_report_encryption.json")
            ;;
        *)
            log_warn "Unknown audit domain '${mod}', skipping."
            ;;
    esac
done

# Consolidate all module findings
log_step "Consolidating all assessment findings into master report..."
CONSOLIDATED_JSON="[]"
for jf in "${MODULE_JSON_FILES[@]}"; do
    if [[ -f "$jf" ]]; then
        CONSOLIDATED_JSON=$(echo "${CONSOLIDATED_JSON}" | jq --slurpfile f "$jf" '. + $f[0]')
    fi
done

echo "${CONSOLIDATED_JSON}" | jq . > "${MASTER_JSON}"

TOTAL_CHECKS=$(jq '. | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
ZERO_WINS=$(jq '[.[] | select(.RemediationImpact == "ZERO_IMPACT_QUICK_WIN" and .Status == "NON_COMPLIANT")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
LOW_IMPACT=$(jq '[.[] | select(.RemediationImpact == "LOW_IMPACT_CONFIG" and .Status == "NON_COMPLIANT")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
MED_IMPACT=$(jq '[.[] | select(.RemediationImpact == "MEDIUM_IMPACT_OPERATIONAL" and .Status == "NON_COMPLIANT")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
HIGH_IMPACT=$(jq '[.[] | select(.RemediationImpact == "HIGH_IMPACT_ARCHITECTURAL" and .Status == "NON_COMPLIANT")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
CRITICALS=$(jq '[.[] | select(.Severity == "CRITICAL" and .Status == "NON_COMPLIANT")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
HIGHS=$(jq '[.[] | select(.Severity == "HIGH" and .Status == "NON_COMPLIANT")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
COMPLIANT=$(jq '[.[] | select(.Status == "COMPLIANT")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
REGIONS_DISCOVERED=$(jq '[.[].Region] | unique | length' "${MASTER_JSON}" 2>/dev/null || echo 1)

# Generate Unified Interactive HTML Dashboard
if [[ "${GENERATE_HTML}" == "true" ]]; then
    ${PYTHON_BIN:-python3} "${SCRIPT_DIR}/lib/compliance_reporter.py" "${MASTER_JSON}" "${MASTER_HTML}" "" "${ACCOUNT_COUNT}" "${REGIONS_DISCOVERED}"
fi

# Executive Console Summary
log_header "Enterprise Compliance & Security Assessment Summary"

printf "${COLOR_WHITE}%-36s : %s${COLOR_RESET}\n" "Total Accounts Evaluated" "${ACCOUNT_COUNT}"
printf "${COLOR_WHITE}%-36s : %s${COLOR_RESET}\n" "Total Unique Regions" "${REGIONS_DISCOVERED}"
printf "${COLOR_WHITE}%-36s : %s${COLOR_RESET}\n" "Total Security Checks Evaluated" "${TOTAL_CHECKS}"
echo "--------------------------------------------------------------------------------"
printf "${COLOR_CYAN}%-36s : %s${COLOR_RESET}  (Safe, 0 downtime, unattached/metadata fixes)\n" "Zero-Impact Quick Wins" "${ZERO_WINS}"
printf "${COLOR_BLUE}%-36s : %s${COLOR_RESET}  (Safe non-breaking service configurations)\n" "Low-Impact Config Improvements" "${LOW_IMPACT}"
printf "${COLOR_YELLOW}%-36s : %s${COLOR_RESET}  (Operational & credential updates)\n" "Medium-Impact Operational" "${MED_IMPACT}"
printf "${COLOR_MAGENTA}%-36s : %s${COLOR_RESET}  (Architectural & network alterations)\n" "High-Impact Architectural" "${HIGH_IMPACT}"
echo "--------------------------------------------------------------------------------"
printf "${COLOR_RED}%-36s : %s${COLOR_RESET}\n" "Critical Severity Findings" "${CRITICALS}"
printf "${COLOR_YELLOW}%-36s : %s${COLOR_RESET}\n" "High Severity Findings" "${HIGHS}"
printf "${COLOR_GREEN}%-36s : %s${COLOR_RESET}\n" "Compliant Controls" "${COMPLIANT}"

echo ""
log_success "Master Assessment Dataset: ${MASTER_JSON}"
if [[ "${GENERATE_HTML}" == "true" ]]; then
    log_success "Interactive HTML Dashboard: ${MASTER_HTML}"
    echo ""
    printf "${COLOR_CYAN}%s\n %s\n%s${COLOR_RESET}\n" \
        "--------------------------------------------------------------------------------" \
        "HOW TO DOWNLOAD AND VIEW THE MASTER REPORT IN AWS CLOUDSHELL" \
        "--------------------------------------------------------------------------------"
    printf "1. In AWS CloudShell, click the ${COLOR_WHITE}'Actions'${COLOR_RESET} menu in the top-right corner.\n"
    printf "2. Click ${COLOR_WHITE}'Download file'${COLOR_RESET}.\n"
    printf "3. In the input box, enter the full path to the dashboard:\n"
    printf "   ${COLOR_GREEN}%s${COLOR_RESET}\n" "${MASTER_HTML}"
    printf "4. Click ${COLOR_WHITE}'Download'${COLOR_RESET} and open the saved file in your web browser.\n"
    printf "${COLOR_CYAN}%s${COLOR_RESET}\n" "--------------------------------------------------------------------------------"
fi

echo ""
log_info "Continuous Compliance & Prevention Controls available in:"
log_info "  - Service Control Policies: controls/scps/"
log_info "  - AWS Config Conformance Pack: controls/config_rules/conformance_pack_security_baseline.yaml"

exit 0
