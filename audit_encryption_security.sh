#!/usr/bin/env bash
# ==============================================================================
# AWS Enterprise Security Audit: Encryption, Tooling & Threat Detection
# Script: audit_encryption_security.sh
# Purpose: Audits KMS Key Rotation, GuardDuty, Security Hub, ECR Scan-on-Push/Immutability,
#          and Load Balancer Deletion Protection across accounts and regions.
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

ROLE_NAME="${ROLE_NAME:-OrganizationAccountAccessRole}"
FALLBACK_ROLES=("AWSControlTowerExecution" "AdministratorAccess" "OrganizationAccountAccessRole")
SPECIFIC_ACCOUNTS=""
SPECIFIC_REGIONS=""
OUTPUT_DIR="${SCRIPT_DIR}/reports"
GENERATE_HTML=true
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

show_help() {
    cat << EOF
AWS Enterprise Security Audit: Encryption & Security Services Domain
Scans AWS Organization accounts for KMS, GuardDuty, Security Hub, ECR, and ELB posture.

USAGE:
    ./audit_encryption_security.sh [OPTIONS]

OPTIONS:
    -r, --role-name <ROLE>      IAM Role to assume in member accounts.
                                Default: OrganizationAccountAccessRole
    -a, --accounts <ID,ID...>   Comma-separated list of target Account IDs.
                                Default: All ACTIVE accounts in AWS Organization.
    -g, --regions <REG,REG...>  Comma-separated list of AWS Regions to scan.
                                Default: All enabled regions in each account.
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
        -g|--regions|--region) SPECIFIC_REGIONS="$2"; shift 2 ;;
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

log_header "AWS Security Assessment: Encryption & Tooling Domain"
check_prerequisites

mkdir -p "${OUTPUT_DIR}"
RAW_TEMP_DIR="${OUTPUT_DIR}/.tmp_raw_enc_${TIMESTAMP}"
mkdir -p "${RAW_TEMP_DIR}"

REPORT_JSON="${OUTPUT_DIR}/compliance_report_encryption.json"
REPORT_HTML="${OUTPUT_DIR}/compliance_report_encryption.html"

log_step "Discovering target accounts..."
ACCOUNTS_JSON=$(get_organization_accounts "${SPECIFIC_ACCOUNTS}")
ACCOUNT_COUNT=$(echo "${ACCOUNTS_JSON}" | jq '. | length')

ALL_FINDINGS="[]"
TOTAL_REGIONS_COUNT=0

for (( i=0; i<ACCOUNT_COUNT; i++ )); do
    ACCOUNT_ID=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Id")
    ACCOUNT_NAME=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Name")

    log_step "Evaluating Encryption & Security Services in: ${ACCOUNT_NAME} (${ACCOUNT_ID}) [Account $((i+1))/${ACCOUNT_COUNT}]..."

    if [[ "${ACCOUNT_ID}" != "${CURRENT_ACCOUNT_ID}" ]]; then
        ASSUMED=false
        for r in "${ROLE_NAME}" "${FALLBACK_ROLES[@]}"; do
            if assume_account_role "${ACCOUNT_ID}" "${r}" "EncryptionAuditSession"; then
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

    REGIONS_JSON=$(get_account_regions "${SPECIFIC_REGIONS}")
    REGION_COUNT=$(echo "${REGIONS_JSON}" | jq '. | length')
    TOTAL_REGIONS_COUNT=$(( TOTAL_REGIONS_COUNT + REGION_COUNT ))

    for (( j=0; j<REGION_COUNT; j++ )); do
        REGION=$(echo "${REGIONS_JSON}" | jq -r ".[$j]")
        log_info "Scanning Region ${REGION} [${ACCOUNT_ID}]..."

        # 1. KMS Keys
        KMS_RAW=$(aws kms list-keys --region "${REGION}" --query 'Keys[].KeyId' --output json 2>/dev/null || echo "[]")
        KMS_LIST="[]"
        KEY_IDS=$(echo "${KMS_RAW}" | jq -r '.[]' 2>/dev/null || true)
        for kid in ${KEY_IDS}; do
            [[ -z "$kid" ]] && continue
            K_DESC=$(aws kms describe-key --key-id "$kid" --region "${REGION}" --query 'KeyMetadata.[KeyManager,KeyState]' --output json 2>/dev/null || echo '["UNKNOWN","UNKNOWN"]')
            K_MGR=$(echo "${K_DESC}" | jq -r '.[0]')
            if [[ "$K_MGR" == "CUSTOMER" ]]; then
                K_ROT=$(aws kms get-key-rotation-status --key-id "$kid" --region "${REGION}" --query 'KeyRotationEnabled' --output text 2>/dev/null || echo "false")
                ROT_ENABLED=false
                [[ "$K_ROT" == "true" ]] && ROT_ENABLED=true

                K_OBJ=$(jq -n --arg id "$kid" --arg mgr "$K_MGR" --argjson rot "$ROT_ENABLED" \
                    '{KeyId: $id, KeyManager: $mgr, KeyRotationEnabled: $rot}')
                KMS_LIST=$(echo "${KMS_LIST}" | jq --argjson kobj "$K_OBJ" '. + [$kobj]')
            fi
        done

        # 2. GuardDuty
        GD_DETECTORS=$(aws guardduty list-detectors --region "${REGION}" --query 'DetectorIds' --output json 2>/dev/null || echo "[]")
        GD_COUNT=$(echo "${GD_DETECTORS}" | jq '. | length')
        GD_ENABLED=false
        [[ "$GD_COUNT" -gt 0 ]] && GD_ENABLED=true

        # 3. Security Hub
        SH_DESC=$(aws securityhub describe-hub --region "${REGION}" --query 'HubArn' --output text 2>/dev/null || echo "")
        SH_ENABLED=false
        [[ -n "$SH_DESC" && "$SH_DESC" != "None" ]] && SH_ENABLED=true

        # 4. ECR Repositories
        ECR_RAW=$(aws ecr describe-repositories --region "${REGION}" --query 'repositories[].[repositoryName,imageScanningConfiguration.scanOnPush,imageTagMutability]' --output json 2>/dev/null || echo "[]")
        ECR_LIST=$(echo "${ECR_RAW}" | jq '[.[] | {repositoryName: .[0], imageScanningConfiguration: {scanOnPush: .[1]}, imageTagMutability: .[2]}]' 2>/dev/null || echo "[]")

        # 5. ELBv2 Deletion Protection
        ELB_RAW=$(aws elbv2 describe-load-balancers --region "${REGION}" --query 'LoadBalancers[].[LoadBalancerArn,LoadBalancerName]' --output json 2>/dev/null || echo "[]")
        ELB_LIST="[]"
        ELB_ARNS=$(echo "${ELB_RAW}" | jq -r '.[][0]' 2>/dev/null || true)
        for earn in ${ELB_ARNS}; do
            [[ -z "$earn" ]] && continue
            ename=$(echo "${ELB_RAW}" | jq -r --arg a "$earn" '.[] | select(.[0] == $a) | .[1]')
            DP_VAL=$(aws elbv2 describe-load-balancer-attributes --load-balancer-arn "$earn" --region "${REGION}" --query "Attributes[?Key=='deletion_protection.enabled'].Value" --output text 2>/dev/null || echo "false")
            DP_BOOL=false
            [[ "$DP_VAL" == "true" ]] && DP_BOOL=true

            ELB_OBJ=$(jq -n --arg arn "$earn" --arg name "$ename" --argjson dp "$DP_BOOL" \
                '{LoadBalancerArn: $arn, LoadBalancerName: $name, DeletionProtection: $dp}')
            ELB_LIST=$(echo "${ELB_LIST}" | jq --argjson eobj "$ELB_OBJ" '. + [$eobj]')
        done

        RAW_REG_FILE="${RAW_TEMP_DIR}/${ACCOUNT_ID}_${REGION}_enc.json"
        jq -n \
            --argjson kms "$KMS_LIST" \
            --argjson gd "$GD_ENABLED" \
            --argjson sh "$SH_ENABLED" \
            --argjson ecr "$ECR_LIST" \
            --argjson elb "$ELB_LIST" \
            '{kms_keys: $kms, guardduty_enabled: $gd, security_hub_enabled: $sh, ecr_repositories: $ecr, load_balancers: $elb}' > "${RAW_REG_FILE}"

        FINDINGS=$(${PYTHON_BIN:-python3} "${SCRIPT_DIR}/lib/compliance_engine.py" encryption "${RAW_REG_FILE}" "${ACCOUNT_ID}" "${ACCOUNT_NAME}" "${REGION}" 2>/dev/null || echo "[]")
        ALL_FINDINGS=$(echo "${ALL_FINDINGS}" "${FINDINGS}" | jq -s '.[0] + .[1]')
    done
done

rm -rf "${RAW_TEMP_DIR}"
echo "${ALL_FINDINGS}" | jq . > "${REPORT_JSON}"

ZERO_WINS=$(jq '[.[] | select(.RemediationImpact == "ZERO_IMPACT_QUICK_WIN" and .Status == "NON_COMPLIANT")] | length' "${REPORT_JSON}" 2>/dev/null || echo 0)
CRITICALS=$(jq '[.[] | select(.Severity == "CRITICAL" and .Status == "NON_COMPLIANT")] | length' "${REPORT_JSON}" 2>/dev/null || echo 0)
TOTAL_EVALS=$(jq '. | length' "${REPORT_JSON}" 2>/dev/null || echo 0)

if [[ "${GENERATE_HTML}" == "true" ]]; then
    ${PYTHON_BIN:-python3} "${SCRIPT_DIR}/lib/compliance_reporter.py" "${REPORT_JSON}" "${REPORT_HTML}" "" "${ACCOUNT_COUNT}" "${TOTAL_REGIONS_COUNT}"
fi

log_header "Encryption & Tooling Compliance Audit Complete"
printf "${COLOR_WHITE}%-32s : %s${COLOR_RESET}\n" "Total Accounts Scanned" "${ACCOUNT_COUNT}"
printf "${COLOR_WHITE}%-32s : %s${COLOR_RESET}\n" "Total Regions Evaluated" "${TOTAL_REGIONS_COUNT}"
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
