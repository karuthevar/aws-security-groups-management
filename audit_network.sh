#!/usr/bin/env bash
# ==============================================================================
# AWS Enterprise Security Audit: Network & Perimeter Security
# Script: audit_network.sh
# Purpose: Audits AWS VPC Flow Logs, Unattached EIPs, Unused NACLs, Default SGs,
#          and Insecure Ingress Rules across member accounts and regions.
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
AWS Enterprise Security Audit: Network Domain
Scans AWS Organization accounts for VPC, Security Group, and Network posture.

USAGE:
    ./audit_network.sh [OPTIONS]

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

log_header "AWS Security Assessment: Network & Perimeter Domain"
check_prerequisites

mkdir -p "${OUTPUT_DIR}"
RAW_TEMP_DIR="${OUTPUT_DIR}/.tmp_raw_net_${TIMESTAMP}"
mkdir -p "${RAW_TEMP_DIR}"

REPORT_JSON="${OUTPUT_DIR}/compliance_report_network.json"
REPORT_HTML="${OUTPUT_DIR}/compliance_report_network.html"

log_step "Discovering target accounts..."
ACCOUNTS_JSON=$(get_organization_accounts "${SPECIFIC_ACCOUNTS}")
ACCOUNT_COUNT=$(echo "${ACCOUNTS_JSON}" | jq '. | length')

ALL_FINDINGS="[]"
TOTAL_REGIONS_COUNT=0

for (( i=0; i<ACCOUNT_COUNT; i++ )); do
    ACCOUNT_ID=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Id")
    ACCOUNT_NAME=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Name")

    log_step "Evaluating Network in Account: ${ACCOUNT_NAME} (${ACCOUNT_ID}) [Account $((i+1))/${ACCOUNT_COUNT}]..."

    if [[ "${ACCOUNT_ID}" != "${CURRENT_ACCOUNT_ID}" ]]; then
        ASSUMED=false
        for r in "${ROLE_NAME}" "${FALLBACK_ROLES[@]}"; do
            if assume_account_role "${ACCOUNT_ID}" "${r}" "NetworkAuditSession"; then
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

        # 1. VPCs & Flow Logs
        VPCS=$(aws ec2 describe-vpcs --region "${REGION}" --query 'Vpcs[].[VpcId]' --output json 2>/dev/null || echo "[]")
        FLOW_LOGS=$(aws ec2 describe-flow-logs --region "${REGION}" --query 'FlowLogs[].[ResourceId,FlowLogStatus]' --output json 2>/dev/null || echo "[]")
        
        ENRICHED_VPCS="[]"
        VPC_IDS=$(echo "${VPCS}" | jq -r '.[][0]' 2>/dev/null || true)
        for vid in ${VPC_IDS}; do
            [[ -z "$vid" ]] && continue
            HAS_FLOW=$(echo "${FLOW_LOGS}" | jq --arg v "$vid" 'any(.[]; .[0] == $v and .[1] == "ACTIVE")')
            VPC_OBJ=$(jq -n --arg id "$vid" --argjson fl "$HAS_FLOW" '{VpcId: $id, FlowLogsEnabled: $fl}')
            ENRICHED_VPCS=$(echo "${ENRICHED_VPCS}" | jq --argjson vobj "$VPC_OBJ" '. + [$vobj]')
        done

        # 2. Elastic IPs
        EIPS=$(aws ec2 describe-addresses --region "${REGION}" --query 'Addresses[].[PublicIp,AllocationId,AssociationId,InstanceId]' --output json 2>/dev/null || echo "[]")
        FORMATTED_EIPS=$(echo "${EIPS}" | jq '[.[] | {PublicIp: .[0], AllocationId: .[1], AssociationId: .[2], InstanceId: .[3]}]' 2>/dev/null || echo "[]")

        # 3. NACLs
        NACLS=$(aws ec2 describe-network-acls --region "${REGION}" --query 'NetworkAcls[].[NetworkAclId,IsDefault,Associations]' --output json 2>/dev/null || echo "[]")
        FORMATTED_NACLS=$(echo "${NACLS}" | jq '[.[] | {NetworkAclId: .[0], IsDefault: .[1], Associations: .[2]}]' 2>/dev/null || echo "[]")

        # 4. Security Groups
        SGS=$(aws ec2 describe-security-groups --region "${REGION}" --query 'SecurityGroups[].[GroupId,GroupName,IpPermissions]' --output json 2>/dev/null || echo "[]")
        FORMATTED_SGS=$(echo "${SGS}" | jq '[.[] | {GroupId: .[0], GroupName: .[1], IpPermissions: .[2]}]' 2>/dev/null || echo "[]")

        # 5. Transit Gateways
        TGWS=$(aws ec2 describe-transit-gateways --region "${REGION}" --query 'TransitGateways[].[TransitGatewayId,Tags[?Key==`Name`].Value | [0],Options.AutoAcceptSharedAttachments]' --output json 2>/dev/null || echo "[]")
        FORMATTED_TGWS=$(echo "${TGWS}" | jq '[.[] | {TransitGatewayId: .[0], Name: .[1], Options: {AutoAcceptSharedAttachments: .[2]}}]' 2>/dev/null || echo "[]")

        RAW_REG_FILE="${RAW_TEMP_DIR}/${ACCOUNT_ID}_${REGION}_net.json"
        jq -n \
            --argjson vpcs "$ENRICHED_VPCS" \
            --argjson eips "$FORMATTED_EIPS" \
            --argjson nacls "$FORMATTED_NACLS" \
            --argjson sgs "$FORMATTED_SGS" \
            --argjson tgws "$FORMATTED_TGWS" \
            '{vpcs: $vpcs, elastic_ips: $eips, nacls: $nacls, security_groups: $sgs, transit_gateways: $tgws}' > "${RAW_REG_FILE}"

        FINDINGS=$(${PYTHON_BIN:-python3} "${SCRIPT_DIR}/lib/compliance_engine.py" network "${RAW_REG_FILE}" "${ACCOUNT_ID}" "${ACCOUNT_NAME}" "${REGION}" 2>/dev/null || echo "[]")
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

log_header "Network Compliance Audit Complete"
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
