#!/usr/bin/env bash
# ==============================================================================
# AWS Enterprise Security Audit: Identity & Access Management (IAM)
# Script: audit_iam.sh
# Purpose: Audits AWS IAM against CIS & AWS Foundational Security benchmarks.
#          Identifies Zero-Impact Quick Wins (MFA, password policies, unassigned users)
#          and generates interactive HTML & JSON compliance reports.
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

ROLE_NAME="${ROLE_NAME:-OrganizationAccountAccessRole}"
FALLBACK_ROLES=("AWSControlTowerExecution" "AdministratorAccess" "OrganizationAccountAccessRole")
SPECIFIC_ACCOUNTS=""
OUTPUT_DIR="${SCRIPT_DIR}/reports"
GENERATE_HTML=true
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

show_help() {
    cat << EOF
AWS Enterprise Security Audit: IAM Domain
Scans AWS Organization accounts for IAM configuration risks and Zero-Impact quick wins.

USAGE:
    ./audit_iam.sh [OPTIONS]

OPTIONS:
    -r, --role-name <ROLE>      IAM Role to assume in member accounts.
                                Default: OrganizationAccountAccessRole
    -a, --accounts <ID,ID...>   Comma-separated list of target Account IDs.
                                Default: All ACTIVE accounts in AWS Organization.
    -o, --output-dir <DIR>      Output directory for reports.
                                Default: ./reports
    --no-html                   Skip generating interactive HTML dashboard.
    -h, --help                  Show this help message.

EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--role|--role-name) ROLE_NAME="$2"; shift 2 ;;
        -a|--accounts) SPECIFIC_ACCOUNTS="$2"; shift 2 ;;
        -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --no-html) GENERATE_HTML=false; shift ;;
        -h|--help) show_help; exit 0 ;;
        *) log_error "Unknown option: $1"; show_help; exit 1 ;;
    esac
done

cleanup() {
    clear_assumed_role
}
trap cleanup EXIT INT TERM

log_header "AWS Security Assessment: IAM & Governance Domain"
check_prerequisites

mkdir -p "${OUTPUT_DIR}"
RAW_TEMP_DIR="${OUTPUT_DIR}/.tmp_raw_iam_${TIMESTAMP}"
mkdir -p "${RAW_TEMP_DIR}"

REPORT_JSON="${OUTPUT_DIR}/compliance_report_iam.json"
REPORT_HTML="${OUTPUT_DIR}/compliance_report_iam.html"

log_step "Discovering target accounts..."
ACCOUNTS_JSON=$(get_organization_accounts "${SPECIFIC_ACCOUNTS}")
ACCOUNT_COUNT=$(echo "${ACCOUNTS_JSON}" | jq '. | length')

ALL_FINDINGS="[]"

for (( i=0; i<ACCOUNT_COUNT; i++ )); do
    ACCOUNT_ID=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Id")
    ACCOUNT_NAME=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Name")

    log_step "Evaluating IAM in Account: ${ACCOUNT_NAME} (${ACCOUNT_ID}) [Account $((i+1))/${ACCOUNT_COUNT}]..."

    # Assume role if necessary
    ASSUMED_OK=true
    if [[ "${ACCOUNT_ID}" != "${CURRENT_ACCOUNT_ID}" ]]; then
        ASSUMED=false
        for r in "${ROLE_NAME}" "${FALLBACK_ROLES[@]}"; do
            if assume_account_role "${ACCOUNT_ID}" "${r}" "IAMAuditSession"; then
                log_info "Successfully assumed role ${r} in ${ACCOUNT_ID}"
                ASSUMED=true
                break
            fi
        done
        if [[ "${ASSUMED}" != "true" ]]; then
            log_warn "Could not assume role in account ${ACCOUNT_ID}. Skipping."
            continue
        fi
    fi

    # Query IAM data
    IN_ORG=true
    if ! aws organizations describe-organization >/dev/null 2>&1; then
        IN_ORG=false
    fi

    PASSWORD_POLICY=$(aws iam get-account-password-policy --query 'PasswordPolicy' --output json 2>/dev/null || echo "{}")
    ACCOUNT_SUMMARY=$(aws iam get-account-summary --query 'SummaryMap' --output json 2>/dev/null || echo "{}")

    # IAM Users details
    RAW_USERS=$(aws iam list-users --query 'Users[].[UserName,CreateDate,PasswordLastUsed]' --output json 2>/dev/null || echo "[]")
    ENRICHED_USERS="[]"
    USER_NAMES=$(echo "${RAW_USERS}" | jq -r '.[][0]' 2>/dev/null || true)
    
    for uname in ${USER_NAMES}; do
        [[ -z "$uname" ]] && continue
        MFA_DEV=$(aws iam list-mfa-devices --user-name "$uname" --query 'MFADevices' --output json 2>/dev/null || echo "[]")
        MFA_COUNT=$(echo "${MFA_DEV}" | jq '. | length')
        HAS_MFA=false
        [[ "$MFA_COUNT" -gt 0 ]] && HAS_MFA=true

        GROUPS=$(aws iam list-groups-for-user --user-name "$uname" --query 'Groups[].GroupName' --output json 2>/dev/null || echo "[]")
        INLINE_POLS=$(aws iam list-user-policies --user-name "$uname" --query 'PolicyNames' --output json 2>/dev/null || echo "[]")

        USER_OBJ=$(jq -n \
            --arg u "$uname" \
            --argjson mfa "$HAS_MFA" \
            --argjson grps "$GROUPS" \
            --argjson pols "$INLINE_POLS" \
            '{UserName: $u, MFAEnabled: $mfa, HasConsoleAccess: true, GroupList: $grps, UserPolicyList: $pols}')
        ENRICHED_USERS=$(echo "${ENRICHED_USERS}" | jq --argjson uobj "$USER_OBJ" '. + [$uobj]')
    done

    # Check Support Role
    HAS_SUPPORT=false
    if aws iam get-role --role-name AWSSupportRole >/dev/null 2>&1; then
        HAS_SUPPORT=true
    fi

    RAW_ACC_FILE="${RAW_TEMP_DIR}/${ACCOUNT_ID}_iam.json"
    jq -n \
        --argjson in_org "$IN_ORG" \
        --argjson pw "$PASSWORD_POLICY" \
        --argjson summary "$ACCOUNT_SUMMARY" \
        --argjson users "$ENRICHED_USERS" \
        --argjson support "$HAS_SUPPORT" \
        '{in_organization: $in_org, password_policy: $pw, account_summary: $summary, users: $users, has_support_role: $support}' > "${RAW_ACC_FILE}"

    # Run Compliance Engine
    FINDINGS=$(${PYTHON_BIN:-python3} "${SCRIPT_DIR}/lib/compliance_engine.py" iam "${RAW_ACC_FILE}" "${ACCOUNT_ID}" "${ACCOUNT_NAME}" "global" 2>/dev/null || echo "[]")
    ALL_FINDINGS=$(echo "${ALL_FINDINGS}" "${FINDINGS}" | jq -s '.[0] + .[1]')
done

rm -rf "${RAW_TEMP_DIR}"
echo "${ALL_FINDINGS}" | jq . > "${REPORT_JSON}"

ZERO_WINS=$(jq '[.[] | select(.RemediationImpact == "ZERO_IMPACT_QUICK_WIN" and .Status == "NON_COMPLIANT")] | length' "${REPORT_JSON}" 2>/dev/null || echo 0)
CRITICALS=$(jq '[.[] | select(.Severity == "CRITICAL" and .Status == "NON_COMPLIANT")] | length' "${REPORT_JSON}" 2>/dev/null || echo 0)
TOTAL_EVALS=$(jq '. | length' "${REPORT_JSON}" 2>/dev/null || echo 0)

if [[ "${GENERATE_HTML}" == "true" ]]; then
    ${PYTHON_BIN:-python3} "${SCRIPT_DIR}/lib/compliance_reporter.py" "${REPORT_JSON}" "${REPORT_HTML}" "" "${ACCOUNT_COUNT}" 1
fi

log_header "IAM Compliance Audit Complete"
printf "${COLOR_WHITE}%-32s : %s${COLOR_RESET}\n" "Total Accounts Scanned" "${ACCOUNT_COUNT}"
printf "${COLOR_WHITE}%-32s : %s${COLOR_RESET}\n" "Total Rules Evaluated" "${TOTAL_EVALS}"
printf "${COLOR_CYAN}%-32s : %s${COLOR_RESET}\n" "Zero-Impact Quick Wins" "${ZERO_WINS}"
printf "${COLOR_RED}%-32s : %s${COLOR_RESET}\n" "Critical Findings" "${CRITICALS}"

echo ""
log_success "Audit JSON:  ${REPORT_JSON}"
if [[ "${GENERATE_HTML}" == "true" ]]; then
    log_success "HTML Report: ${REPORT_HTML}"
    echo ""
    printf "${COLOR_CYAN}CloudShell Download: 'Actions' -> 'Download file' -> Enter:${COLOR_RESET} %s\n" "${REPORT_HTML}"
fi

exit 0
