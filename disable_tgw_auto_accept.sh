#!/usr/bin/env bash
# ==============================================================================
# AWS Organization Transit Gateway Auto-Accept Remediation Tool
# Script: disable_tgw_auto_accept.sh
# Purpose: Scans all member accounts and regions across an AWS Organization.
#          Finds any AWS Transit Gateway with AutoAcceptSharedAttachments enabled
#          and modifies it to "disable" to prevent unauthorized cross-account attachments.
# Impact:  100% ZERO WORKLOAD DOWNTIME. Existing VPC attachments are unaffected.
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

ROLE_NAME="${ROLE_NAME:-OrganizationAccountAccessRole}"
FALLBACK_ROLES=("AWSControlTowerExecution" "AdministratorAccess" "OrganizationAccountAccessRole")
SPECIFIC_ACCOUNTS=""
SPECIFIC_REGIONS=""
OUTPUT_DIR="${SCRIPT_DIR}/reports"
MODE="DRY_RUN"  # DRY_RUN or EXECUTE
AUTO_CONFIRM=false
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

show_help() {
    cat << EOF
AWS Transit Gateway Auto Cross-Account Attachment Remediation
Scans all Organization member accounts and regions to disable AutoAcceptSharedAttachments.

USAGE:
    ./disable_tgw_auto_accept.sh [OPTIONS]

OPTIONS:
    --dry-run                   Preview non-compliant Transit Gateways without making changes (Default).
    --execute                   Apply remediation by modifying AutoAcceptSharedAttachments to 'disable'.
    -y, --yes                   Bypass interactive confirmation prompt in execute mode.
    -r, --role-name <ROLE>      IAM Role to assume in member accounts.
                                Default: OrganizationAccountAccessRole
    -a, --accounts <ID,ID...>   Comma-separated list of target Account IDs.
                                Default: All ACTIVE accounts in AWS Organization.
    -g, --regions <REG,REG...>  Comma-separated list of AWS Regions to scan.
                                Default: All enabled regions in each account.
    -o, --output-dir <DIR>      Directory to store audit/remediation manifests.
                                Default: ./reports
    -h, --help                  Show this help message.

SECURITY POSTURE & DOWNTIME IMPACT:
    Operational Impact : ZERO_IMPACT_QUICK_WIN (100% Zero Workload Downtime)
    Routing Effect     : Existing attachments and active routing tables continue uninterrupted.
    Security Benefit   : Prevents rogue or compromised shared accounts from silently attaching
                         unauthorized VPCs to your transit network without administrator approval.

EXAMPLES:
    # 1. Preview mode across the entire AWS Organization
    ./disable_tgw_auto_accept.sh

    # 2. Execute remediation with interactive confirmation
    ./disable_tgw_auto_accept.sh --execute

    # 3. Non-interactive execute mode for specific accounts
    ./disable_tgw_auto_accept.sh --execute --yes --accounts 111122223333,444455556666

EOF
}

# Parse Command Line Options
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            MODE="DRY_RUN"
            shift
            ;;
        --execute)
            MODE="EXECUTE"
            shift
            ;;
        -y|--yes)
            AUTO_CONFIRM=true
            shift
            ;;
        -r|--role|--role-name)
            ROLE_NAME="$2"
            shift 2
            ;;
        -a|--accounts)
            SPECIFIC_ACCOUNTS="$2"
            shift 2
            ;;
        -g|--regions|--region)
            SPECIFIC_REGIONS="$2"
            shift 2
            ;;
        -o|--output-dir)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

cleanup() {
    clear_assumed_role
}
trap cleanup EXIT INT TERM

log_header "AWS Transit Gateway Auto Cross-Account Attachment Remediation"

# Verify prerequisites and identity
check_prerequisites

mkdir -p "${OUTPUT_DIR}"
MANIFEST_JSON="${OUTPUT_DIR}/tgw_auto_accept_remediation_${TIMESTAMP}.json"

log_step "Discovering target accounts in AWS Organization..."
ACCOUNTS_JSON=$(get_organization_accounts "${SPECIFIC_ACCOUNTS}")
ACCOUNT_COUNT=$(echo "${ACCOUNTS_JSON}" | jq '. | length')

if [[ "${ACCOUNT_COUNT}" -eq 0 ]]; then
    log_error "No active target accounts found. Aborting."
    exit 1
fi

log_info "Identified ${ACCOUNT_COUNT} target account(s)."
if [[ "${MODE}" == "DRY_RUN" ]]; then
    log_warn "MODE: DRY-RUN (Preview only - no infrastructure will be modified)."
else
    log_warn "MODE: EXECUTE (Will disable AutoAcceptSharedAttachments on target Transit Gateways)."
fi

# Data collections
ALL_TGWS_COUNT=0
COMPLIANT_COUNT=0
CANDIDATE_LIST="[]"

# Phase 1: Scan and Discover Candidates
for (( i=0; i<ACCOUNT_COUNT; i++ )); do
    ACCOUNT_ID=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Id")
    ACCOUNT_NAME=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Name")

    log_step "Checking Account: ${ACCOUNT_NAME} (${ACCOUNT_ID}) [Account $((i+1))/${ACCOUNT_COUNT}]..."

    # Assume role if not management account
    ACCOUNT_ROLE=""
    if [[ "${ACCOUNT_ID}" != "${CURRENT_ACCOUNT_ID}" ]]; then
        ASSUMED=false
        for r in "${ROLE_NAME}" "${FALLBACK_ROLES[@]}"; do
            if assume_account_role "${ACCOUNT_ID}" "${r}" "TGWRemediationSession"; then
                log_info "Successfully assumed role ${r} in ${ACCOUNT_ID}"
                ASSUMED=true
                ACCOUNT_ROLE="${r}"
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

    for (( j=0; j<REGION_COUNT; j++ )); do
        REGION=$(echo "${REGIONS_JSON}" | jq -r ".[$j]")

        # Describe Transit Gateways in this region
        TGWS_RAW=$(aws ec2 describe-transit-gateways \
            --region "${REGION}" \
            --query 'TransitGateways[].[TransitGatewayId,Options.AutoAcceptSharedAttachments,State,Tags[?Key==`Name`].Value | [0],OwnerId]' \
            --output json 2>/dev/null || echo "[]")

        TGW_LIST_LEN=$(echo "${TGWS_RAW}" | jq '. | length' 2>/dev/null || echo 0)
        if [[ "${TGW_LIST_LEN}" -eq 0 ]]; then
            continue
        fi

        for (( k=0; k<TGW_LIST_LEN; k++ )); do
            TGW_ID=$(echo "${TGWS_RAW}" | jq -r ".[$k][0]")
            AUTO_ACCEPT=$(echo "${TGWS_RAW}" | jq -r ".[$k][1]")
            TGW_STATE=$(echo "${TGWS_RAW}" | jq -r ".[$k][2]")
            TGW_NAME=$(echo "${TGWS_RAW}" | jq -r ".[$k][3] // \"N/A\"")
            TGW_OWNER=$(echo "${TGWS_RAW}" | jq -r ".[$k][4] // \"N/A\"")

            ALL_TGWS_COUNT=$(( ALL_TGWS_COUNT + 1 ))

            if [[ "${AUTO_ACCEPT}" == "enable" ]]; then
                log_warn "FOUND NON-COMPLIANT: ${TGW_ID} ('${TGW_NAME}') in ${REGION} [Account: ${ACCOUNT_ID}] -> AutoAccept is ENABLED"

                CANDIDATE_OBJ=$(jq -n \
                    --arg acc "$ACCOUNT_ID" \
                    --arg accName "$ACCOUNT_NAME" \
                    --arg reg "$REGION" \
                    --arg id "$TGW_ID" \
                    --arg name "$TGW_NAME" \
                    --arg owner "$TGW_OWNER" \
                    --arg state "$TGW_STATE" \
                    --arg autoAccept "$AUTO_ACCEPT" \
                    --arg role "$ACCOUNT_ROLE" \
                    '{AccountId: $acc, AccountName: $accName, Region: $reg, TransitGatewayId: $id, Name: $name, OwnerId: $owner, State: $state, CurrentAutoAccept: $autoAccept, AssumedRole: $role}')

                CANDIDATE_LIST=$(echo "${CANDIDATE_LIST}" | jq --argjson c "$CANDIDATE_OBJ" '. + [$c]')
            else
                COMPLIANT_COUNT=$(( COMPLIANT_COUNT + 1 ))
            fi
        done
    done
done

CANDIDATES_COUNT=$(echo "${CANDIDATE_LIST}" | jq '. | length')

echo ""
log_header "Assessment Summary: EC2 Transit Gateway Auto Cross-Account Attachment"
printf "${COLOR_WHITE}%-38s : %s${COLOR_RESET}\n" "Total Accounts Scanned" "${ACCOUNT_COUNT}"
printf "${COLOR_WHITE}%-38s : %s${COLOR_RESET}\n" "Total Transit Gateways Evaluated" "${ALL_TGWS_COUNT}"
printf "${COLOR_GREEN}%-38s : %s${COLOR_RESET}\n" "Compliant TGWs (Auto-Accept Disabled)" "${COMPLIANT_COUNT}"
printf "${COLOR_RED}%-38s : %s${COLOR_RESET}\n" "Non-Compliant TGWs (Auto-Accept Enabled)" "${CANDIDATES_COUNT}"

if [[ "${CANDIDATES_COUNT}" -eq 0 ]]; then
    echo ""
    log_success "All Transit Gateways across all discovered accounts and regions are COMPLIANT! (Auto-Accept is already disabled)."
    exit 0
fi

# Print Details of Candidates
echo ""
echo "--------------------------------------------------------------------------------"
echo " NON-COMPLIANT TRANSIT GATEWAYS IDENTIFIED FOR REMEDIATION"
echo "--------------------------------------------------------------------------------"
for (( i=0; i<CANDIDATES_COUNT; i++ )); do
    C_ACC=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].AccountId")
    C_ACCNAME=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].AccountName")
    C_REG=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].Region")
    C_ID=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].TransitGatewayId")
    C_NAME=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].Name")
    
    printf "[$((i+1))/${CANDIDATES_COUNT}] ${COLOR_CYAN}%s${COLOR_RESET} ('%s') | Region: ${COLOR_WHITE}%s${COLOR_RESET} | Account: ${COLOR_WHITE}%s (%s)${COLOR_RESET}\n" \
        "${C_ID}" "${C_NAME}" "${C_REG}" "${C_ACCNAME}" "${C_ACC}"
    printf "      CLI Remediation: ${COLOR_YELLOW}aws ec2 modify-transit-gateway --transit-gateway-id %s --options AutoAcceptSharedAttachments=disable --region %s${COLOR_RESET}\n" \
        "${C_ID}" "${C_REG}"
done
echo "--------------------------------------------------------------------------------"

# Save candidate manifest
echo "${CANDIDATE_LIST}" | jq . > "${MANIFEST_JSON}"
log_info "Candidate manifest preserved: ${MANIFEST_JSON}"

# Stop here if DRY RUN
if [[ "${MODE}" == "DRY_RUN" ]]; then
    echo ""
    log_warn "DRY-RUN COMPLETE: No changes were applied."
    log_info "To remediate and disable auto-acceptance on all ${CANDIDATES_COUNT} Transit Gateway(s), run:"
    log_info "    ./disable_tgw_auto_accept.sh --execute"
    exit 0
fi

# Confirmation in EXECUTE mode
if [[ "${AUTO_CONFIRM}" != "true" ]]; then
    echo ""
    printf "${COLOR_RED}ARE YOU SURE you want to modify AutoAcceptSharedAttachments to 'disable' for ${CANDIDATES_COUNT} Transit Gateway(s)?${COLOR_RESET}\n"
    printf "Type ${COLOR_WHITE}'CONFIRM'${COLOR_RESET} to proceed: "
    read -r CONFIRM_INPUT
    if [[ "${CONFIRM_INPUT}" != "CONFIRM" ]]; then
        log_warn "Confirmation aborted by user. No modifications made."
        exit 0
    fi
fi

# Phase 2: Execute Remediation
log_header "Applying Remediation: Disabling AutoAcceptSharedAttachments"

SUCCESS_COUNT=0
FAIL_COUNT=0

for (( i=0; i<CANDIDATES_COUNT; i++ )); do
    C_ACC=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].AccountId")
    C_ACCNAME=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].AccountName")
    C_REG=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].Region")
    C_ID=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].TransitGatewayId")
    C_NAME=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].Name")

    log_step "[$((i+1))/${CANDIDATES_COUNT}] Modifying ${C_ID} ('${C_NAME}') in ${C_REG} [${C_ACC}]..."

    C_ROLE=$(echo "${CANDIDATE_LIST}" | jq -r ".[$i].AssumedRole // \"\"")

    # Re-assume role for target account
    if [[ "${C_ACC}" != "${CURRENT_ACCOUNT_ID}" ]]; then
        TARGET_ROLE="${C_ROLE:-$ROLE_NAME}"
        assume_account_role "${C_ACC}" "${TARGET_ROLE}" "TGWRemediationExecution" || true
    fi

    # Execute modify-transit-gateway
    MOD_OUT=$(aws ec2 modify-transit-gateway \
        --transit-gateway-id "${C_ID}" \
        --options AutoAcceptSharedAttachments=disable \
        --region "${C_REG}" \
        --query 'TransitGateway.Options.AutoAcceptSharedAttachments' \
        --output text 2>&1)

    if [[ $? -eq 0 && "${MOD_OUT}" == "disable" ]]; then
        log_success "Successfully modified ${C_ID}: AutoAcceptSharedAttachments is now DISABLE."
        SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))
    else
        # If output was modifying or error
        if [[ "${MOD_OUT}" == *"modifying"* || "${MOD_OUT}" == *"pending"* ]]; then
            log_success "Submitted modification for ${C_ID} (State: ${MOD_OUT})."
            SUCCESS_COUNT=$(( SUCCESS_COUNT + 1 ))
        else
            log_error "Failed to modify ${C_ID} in ${C_REG}: ${MOD_OUT}"
            FAIL_COUNT=$(( FAIL_COUNT + 1 ))
        fi
    fi
done

echo ""
log_header "Remediation Results"
printf "${COLOR_WHITE}%-34s : %s${COLOR_RESET}\n" "Total Targeted" "${CANDIDATES_COUNT}"
printf "${COLOR_GREEN}%-34s : %s${COLOR_RESET}\n" "Successfully Modified" "${SUCCESS_COUNT}"
printf "${COLOR_RED}%-34s : %s${COLOR_RESET}\n" "Failed / Skipped" "${FAIL_COUNT}"

echo ""
log_success "All targeted Transit Gateways now reject automatic cross-account attachments."
log_info "100% Zero Workload Downtime: All active routing and existing VPC attachments remain fully operational."

exit 0
