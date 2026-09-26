#!/usr/bin/env bash
# ==============================================================================
# AWS Organization Security Group Audit Scanner
# Script: audit_security_groups.sh
# Purpose: Scans all AWS Security Groups across all AWS Organization member
#          accounts and enabled regions, evaluates threat exposures, identifies
#          unattached resources, and generates an interactive HTML security report.
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"
source "${SCRIPT_DIR}/lib/threat_engine.sh"
source "${SCRIPT_DIR}/lib/html_generator.sh"

# Default configuration values
ROLE_NAME="${ROLE_NAME:-OrganizationAccountAccessRole}"
FALLBACK_ROLES=("AWSControlTowerExecution" "AdministratorAccess" "OrganizationAccountAccessRole")
SPECIFIC_ACCOUNTS=""
SPECIFIC_REGIONS=""
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="${SCRIPT_DIR}/audit_results/${TIMESTAMP}"
GENERATE_HTML=true
MAX_PARALLEL=4

show_help() {
    cat << EOF
AWS Organization Security Group Audit Tool
Scans all member accounts and regions in an AWS Organization.

USAGE:
    ./audit_security_groups.sh [OPTIONS]

OPTIONS:
    -r, --role-name <ROLE>      IAM Role to assume in member accounts.
                                Default: OrganizationAccountAccessRole
    -a, --accounts <ID,ID...>   Comma-separated list of target Account IDs.
                                Default: Scans all ACTIVE accounts in the AWS Organization.
    -g, --regions <REG,REG...>  Comma-separated list of AWS Regions to scan.
                                Default: All enabled regions in each account.
    -o, --output-dir <DIR>      Output directory for JSON and HTML reports.
                                Default: ./audit_results/<timestamp>
        --no-html               Skip generating the interactive HTML dashboard.
    -h, --help                  Show this help message and exit.

EXAMPLES:
    # Scan all accounts and all regions in the AWS Organization
    ./audit_security_groups.sh

    # Scan with custom cross-account role
    ./audit_security_groups.sh --role-name AWSControlTowerExecution

    # Scan specific accounts in us-east-1 and us-west-2
    ./audit_security_groups.sh --accounts 111122223333,444455556666 --regions us-east-1,us-west-2

EOF
}

# Parse Command Line Arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -r|--role|--role-name)
            ROLE_NAME="$2"
            shift 2
            ;;
        -a|--accounts)
            SPECIFIC_ACCOUNTS="$2"
            shift 2
            ;;
        -g|--region|--regions)
            SPECIFIC_REGIONS="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --no-html)
            GENERATE_HTML=false
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown parameter: $1"
            show_help
            exit 1
            ;;
    esac
done

# Ensure clean exit on trap
cleanup() {
    clear_assumed_role
}
trap cleanup EXIT INT TERM

# Main Execution Flow
log_header "AWS Organization Security Group Audit Scanner"

# Step 1: Verify prerequisites & AWS access
check_prerequisites

# Step 2: Prepare output workspace
mkdir -p "${OUTPUT_DIR}"
RAW_TEMP_DIR="${OUTPUT_DIR}/.tmp_raw"
mkdir -p "${RAW_TEMP_DIR}"

MASTER_JSON="${OUTPUT_DIR}/security_audit_report.json"
MASTER_HTML="${OUTPUT_DIR}/security_audit_report.html"

# Step 3: Discover target accounts in Organization
log_step "Discovering target accounts in AWS Organization..."
ACCOUNTS_JSON=$(get_organization_accounts "${SPECIFIC_ACCOUNTS}")

ACCOUNT_COUNT=$(echo "${ACCOUNTS_JSON}" | jq '. | length')
if [[ "${ACCOUNT_COUNT}" -eq 0 ]]; then
    log_error "No active accounts found to scan."
    exit 1
fi

log_success "Found ${ACCOUNT_COUNT} target account(s) to scan."

# Initialize aggregated results list
echo "[]" > "${MASTER_JSON}"

TOTAL_SGS_FOUND=0
CRITICAL_THREATS=0
HIGH_THREATS=0
CAN_DELETE_COUNT=0
DEFAULT_SG_COUNT=0
ALL_REGIONS_SET=()

ACCOUNT_INDEX=0

# Loop through each account
while read -r account_obj; do
    ((ACCOUNT_INDEX++))
    ACC_ID=$(echo "${account_obj}" | jq -r '.Id')
    ACC_NAME=$(echo "${account_obj}" | jq -r '.Name')

    log_header "Account [${ACCOUNT_INDEX}/${ACCOUNT_COUNT}]: ${ACC_NAME} (${ACC_ID})"

    # Handle cross-account authentication
    ASSUME_SUCCESS=false
    if [[ "${ACC_ID}" == "${CURRENT_ACCOUNT_ID}" ]]; then
        log_info "Account ${ACC_ID} is the current caller account. Scanning directly."
        clear_assumed_role
        ASSUME_SUCCESS=true
    else
        log_info "Assuming role '${ROLE_NAME}' into account ${ACC_ID}..."
        if assume_account_role "${ACC_ID}" "${ROLE_NAME}" "SGAudit-${ACC_ID}"; then
            ASSUME_SUCCESS=true
            log_success "Successfully assumed role in account ${ACC_ID}."
        else
            log_warn "Failed to assume role '${ROLE_NAME}'. Testing fallback roles..."
            for fb_role in "${FALLBACK_ROLES[@]}"; do
                if [[ "${fb_role}" != "${ROLE_NAME}" ]]; then
                    log_info "Trying fallback role '${fb_role}' in account ${ACC_ID}..."
                    if assume_account_role "${ACC_ID}" "${fb_role}" "SGAudit-${ACC_ID}"; then
                        ASSUME_SUCCESS=true
                        log_success "Successfully assumed fallback role '${fb_role}'."
                        break
                    fi
                fi
            done
        fi
    fi

    if [[ "${ASSUME_SUCCESS}" != "true" ]]; then
        log_error "Skipping account ${ACC_ID}: Unable to assume cross-account IAM role. Ensure role exists and trust relationship allows access."
        continue
    fi

    # Query enabled regions for this account
    log_info "Retrieving enabled AWS regions for account ${ACC_ID}..."
    REGIONS_JSON=$(get_account_regions "${SPECIFIC_REGIONS}")
    REGION_LIST=($(echo "${REGIONS_JSON}" | jq -r '.[]'))
    log_info "Scanning ${#REGION_LIST[@]} region(s) in account ${ACC_ID}..."

    # Scan each region
    for REG in "${REGION_LIST[@]}"; do
        # Track unique regions
        if [[ ! " ${ALL_REGIONS_SET[@]} " =~ " ${REG} " ]]; then
            ALL_REGIONS_SET+=("${REG}")
        fi

        log_step "Scanning Account ${ACC_ID} | Region ${REG}..."

        SGS_FILE="${RAW_TEMP_DIR}/sgs_${ACC_ID}_${REG}.json"
        ENIS_FILE="${RAW_TEMP_DIR}/enis_${ACC_ID}_${REG}.json"
        ANALYZED_FILE="${RAW_TEMP_DIR}/analyzed_${ACC_ID}_${REG}.json"

        # 1. Fetch Security Groups (single call for whole region)
        if ! aws ec2 describe-security-groups --region "${REG}" --output json > "${SGS_FILE}" 2>/dev/null; then
            log_warn "Could not describe security groups in ${REG} (region might be disabled or unauthorized). Skipping."
            rm -f "${SGS_FILE}" "${ENIS_FILE}"
            continue
        fi

        SG_IN_REGION_COUNT=$(jq '.SecurityGroups | length' "${SGS_FILE}" 2>/dev/null || echo 0)
        if [[ "${SG_IN_REGION_COUNT}" -eq 0 ]]; then
            rm -f "${SGS_FILE}" "${ENIS_FILE}"
            continue
        fi

        # 2. Fetch Network Interfaces (single call for whole region)
        if ! aws ec2 describe-network-interfaces --region "${REG}" --output json > "${ENIS_FILE}" 2>/dev/null; then
            echo '{"NetworkInterfaces": []}' > "${ENIS_FILE}"
        fi

        # 3. Perform Threat & Attachment Analysis
        if analyze_region_data "${SGS_FILE}" "${ENIS_FILE}" "${ACC_ID}" "${ACC_NAME}" "${REG}" "${ANALYZED_FILE}"; then
            ANALYZED_COUNT=$(jq '. | length' "${ANALYZED_FILE}" 2>/dev/null || echo 0)
            if [[ "${ANALYZED_COUNT}" -gt 0 ]]; then
                log_info "Region ${REG}: Analyzed ${ANALYZED_COUNT} security group(s)."
                # Merge into master JSON
                jq -s '.[0] + .[1]' "${MASTER_JSON}" "${ANALYZED_FILE}" > "${MASTER_JSON}.tmp" && mv "${MASTER_JSON}.tmp" "${MASTER_JSON}"
            fi
        fi

        # Cleanup raw region files to save space
        rm -f "${SGS_FILE}" "${ENIS_FILE}" "${ANALYZED_FILE}"
    done

    # Reset credentials before next account
    clear_assumed_role

done < <(echo "${ACCOUNTS_JSON}" | jq -c '.[]')

# Remove raw temp dir
rm -rf "${RAW_TEMP_DIR}"

# Calculate summary metrics from master JSON
TOTAL_SGS_FOUND=$(jq '. | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
CRITICAL_THREATS=$(jq '[.[] | select(.MaxSeverity == "CRITICAL")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
HIGH_THREATS=$(jq '[.[] | select(.MaxSeverity == "HIGH")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
CAN_DELETE_COUNT=$(jq '[.[] | select(.Recommendation == "CAN_DELETE")] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
DEFAULT_SG_COUNT=$(jq '[.[] | select(.IsDefault == true)] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)
EXPOSED_COUNT=$(jq '[.[] | select(.IsExposedToInternet == true)] | length' "${MASTER_JSON}" 2>/dev/null || echo 0)

TOTAL_REGIONS_COUNT="${#ALL_REGIONS_SET[@]}"

# Step 4: Generate HTML Report
if [[ "${GENERATE_HTML}" == "true" ]]; then
    generate_html_report "${MASTER_JSON}" "${MASTER_HTML}" "${ACCOUNT_COUNT}" "${TOTAL_REGIONS_COUNT}"
fi

# Step 5: Executive Console Summary
log_header "Security Group Audit Complete"

printf "${COLOR_WHITE}%-32s : %s${COLOR_RESET}\n" "Total Accounts Scanned" "${ACCOUNT_COUNT}"
printf "${COLOR_WHITE}%-32s : %s${COLOR_RESET}\n" "Total Regions Evaluated" "${TOTAL_REGIONS_COUNT}"
printf "${COLOR_WHITE}%-32s : %s${COLOR_RESET}\n" "Total Security Groups Found" "${TOTAL_SGS_FOUND}"
printf "${COLOR_RED}%-32s : %s${COLOR_RESET}\n" "Critical Threat Exposures" "${CRITICAL_THREATS}"
printf "${COLOR_YELLOW}%-32s : %s${COLOR_RESET}\n" "High Threat Exposures" "${HIGH_THREATS}"
printf "${COLOR_MAGENTA}%-32s : %s${COLOR_RESET}\n" "Internet Exposed (0.0.0.0/0)" "${EXPOSED_COUNT}"
printf "${COLOR_GREEN}%-32s : %s${COLOR_RESET}\n" "Safe to Delete (Unattached)" "${CAN_DELETE_COUNT}"
printf "${COLOR_PURPLE}%-32s : %s${COLOR_RESET}\n" "Default SGs (Restrict Traffic)" "${DEFAULT_SG_COUNT}"

echo ""
log_success "Audit JSON Dataset:  ${MASTER_JSON}"
if [[ "${GENERATE_HTML}" == "true" ]]; then
    log_success "Interactive HTML:    ${MASTER_HTML}"
    log_info "Open '${MASTER_HTML}' in any web browser to view, filter, and export the audit results."
fi

if [[ "${CAN_DELETE_COUNT}" -gt 0 ]]; then
    echo ""
    log_warn "Part 2 Action Available: Found ${CAN_DELETE_COUNT} unattached security groups that can be safely cleaned up."
    log_info "To preview and safely back up/delete them, run:"
    log_info "    ./cleanup_security_groups.sh --audit-file \"${MASTER_JSON}\" --dry-run"
fi

exit 0
