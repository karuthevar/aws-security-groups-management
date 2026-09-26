#!/usr/bin/env bash
# ==============================================================================
# AWS Security Group Restoration Tool
# Script: restore_security_groups.sh
# Purpose: Recreates security groups from JSON backups generated during cleanup,
#          re-applying all metadata, tags, ingress rules, and egress rules.
# ==============================================================================

set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/lib/common.sh"

ROLE_NAME="${ROLE_NAME:-OrganizationAccountAccessRole}"
BACKUP_FILE=""
MANIFEST_FILE=""
TARGET_VPC_OVERRIDE=""
DRY_RUN=true
FORCE=false

show_help() {
    cat << EOF
AWS Security Group Restoration Tool
Restores security groups from backups created by cleanup_security_groups.sh.

USAGE:
    ./restore_security_groups.sh [OPTIONS]

OPTIONS:
    -b, --backup-file <FILE>    Path to a specific security group backup JSON file.
    -m, --manifest <FILE>       Path to a backup_manifest.json to restore multiple SGs.
        --target-vpc-id <VPC>   Override target VPC ID (useful if original VPC was deleted).
    -r, --role-name <ROLE>      IAM Role to assume in member accounts.
                                Default: OrganizationAccountAccessRole
        --execute               Execute real restoration (default is DRY-RUN).
    -y, --yes                   Skip interactive confirmation prompt.
    -h, --help                  Show this help message and exit.

EXAMPLES:
    # 1. Inspect and preview restoring a single backup (DRY RUN):
    ./restore_security_groups.sh --backup-file ./backups/20260926_120000/111122223333_Prod/us-east-1/sg-0123456789_app-sg.json

    # 2. Restore the security group into its original VPC and account:
    ./restore_security_groups.sh --backup-file ./backups/20260926_120000/111122223333_Prod/us-east-1/sg-0123456789_app-sg.json --execute

    # 3. Restore all security groups from a backup manifest:
    ./restore_security_groups.sh --manifest ./backups/20260926_120000/backup_manifest.json --execute

    # 4. Restore into a different VPC:
    ./restore_security_groups.sh --backup-file ./backups/.../sg-xxx.json --target-vpc-id vpc-0987654321fedcba0 --execute

EOF
}

# Parse Arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -b|--backup-file)
            BACKUP_FILE="$2"
            shift 2
            ;;
        -m|--manifest)
            MANIFEST_FILE="$2"
            shift 2
            ;;
        --target-vpc-id)
            TARGET_VPC_OVERRIDE="$2"
            shift 2
            ;;
        -r|--role-name)
            ROLE_NAME="$2"
            shift 2
            ;;
        --execute)
            DRY_RUN=false
            shift
            ;;
        -y|--yes)
            FORCE=true
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

cleanup() {
    clear_assumed_role
}
trap cleanup EXIT INT TERM

log_header "AWS Security Group Restoration Utility"

check_prerequisites

# Identify files to restore
FILES_TO_RESTORE=()

if [[ -n "${BACKUP_FILE}" ]]; then
    if command -v cygpath >/dev/null 2>&1; then
        BACKUP_FILE="$(cygpath -u "${BACKUP_FILE}")"
    fi
    if [[ ! -f "${BACKUP_FILE}" ]]; then
        log_error "Backup file not found: ${BACKUP_FILE}"
        exit 1
    fi
    FILES_TO_RESTORE+=("${BACKUP_FILE}")
elif [[ -n "${MANIFEST_FILE}" ]]; then
    if command -v cygpath >/dev/null 2>&1; then
        MANIFEST_FILE="$(cygpath -u "${MANIFEST_FILE}")"
    fi
    if [[ ! -f "${MANIFEST_FILE}" ]]; then
        log_error "Manifest file not found: ${MANIFEST_FILE}"
        exit 1
    fi
    while read -r bfile; do
        if command -v cygpath >/dev/null 2>&1; then
            bfile="$(cygpath -u "${bfile}")"
        fi
        if [[ -f "${bfile}" ]]; then
            FILES_TO_RESTORE+=("${bfile}")
        else
            log_warn "Referenced backup file missing: ${bfile}"
        fi
    done < <(jq -r '.[].BackupFile' "${MANIFEST_FILE}")
else
    log_error "You must specify either --backup-file <FILE> or --manifest <FILE>."
    show_help
    exit 1
fi

TOTAL_TO_RESTORE="${#FILES_TO_RESTORE[@]}"
if [[ "${TOTAL_TO_RESTORE}" -eq 0 ]]; then
    log_error "No valid backup files identified for restoration."
    exit 1
fi

log_info "Identified ${TOTAL_TO_RESTORE} security group backup(s) to process."

if [[ "${DRY_RUN}" == "true" ]]; then
    log_warn "MODE: DRY-RUN (Previewing restoration parameters only - NO resources created)"
    log_info "To execute actual restoration, re-run with: --execute"
else
    log_warn "MODE: EXECUTE (Will create new security groups and authorize rules)"
    if [[ "${FORCE}" != "true" ]]; then
        echo ""
        read -r -p "Type 'RESTORE' to proceed with restoring ${TOTAL_TO_RESTORE} security group(s): " confirmation
        if [[ "${confirmation}" != "RESTORE" ]]; then
            log_warn "Restoration aborted by user."
            exit 0
        fi
    fi
fi

RESTORED_COUNT=0
FAILED_COUNT=0

for bpath in "${FILES_TO_RESTORE[@]}"; do
    echo ""
    log_header "Restoring Backup: $(basename "${bpath}")"

    # Extract Metadata and SG payload
    ACC_ID=$(jq -r '.BackupMetadata.AccountId' "${bpath}")
    ACC_NAME=$(jq -r '.BackupMetadata.AccountName' "${bpath}")
    if [[ -z "${ACC_NAME}" || "${ACC_NAME}" == "null" ]]; then ACC_NAME="Account-${ACC_ID}"; fi
    REG=$(jq -r '.BackupMetadata.Region' "${bpath}")
    OLD_SG_ID=$(jq -r '.BackupMetadata.GroupId' "${bpath}")
    SG_NAME=$(jq -r '.BackupMetadata.GroupName' "${bpath}")
    ORIG_VPC_ID=$(jq -r '.BackupMetadata.VpcId' "${bpath}")
    SG_DESC=$(jq -r '.BackupMetadata.Description' "${bpath}")
    if [[ -z "${SG_DESC}" || "${SG_DESC}" == "null" ]]; then SG_DESC="Restored security group"; fi

    TARGET_VPC="${TARGET_VPC_OVERRIDE:-${ORIG_VPC_ID}}"

    printf "${COLOR_WHITE}%-24s : %s (%s)${COLOR_RESET}\n" "Target Account" "${ACC_NAME}" "${ACC_ID}"
    printf "${COLOR_WHITE}%-24s : %s${COLOR_RESET}\n" "Target Region" "${REG}"
    printf "${COLOR_WHITE}%-24s : %s${COLOR_RESET}\n" "Original Group ID" "${OLD_SG_ID}"
    printf "${COLOR_WHITE}%-24s : %s${COLOR_RESET}\n" "Security Group Name" "${SG_NAME}"
    printf "${COLOR_WHITE}%-24s : %s${COLOR_RESET}\n" "Target VPC ID" "${TARGET_VPC}"

    INGRESS_RULES_COUNT=$(jq '.SecurityGroup.IpPermissions | length' "${bpath}")
    EGRESS_RULES_COUNT=$(jq '.SecurityGroup.IpPermissionsEgress | length' "${bpath}")
    TAGS_COUNT=$(jq '.SecurityGroup.Tags | length' "${bpath}")

    printf "${COLOR_WHITE}%-24s : %s inbound, %s outbound, %s tags${COLOR_RESET}\n" "Rules & Tags" "${INGRESS_RULES_COUNT}" "${EGRESS_RULES_COUNT}" "${TAGS_COUNT}"

    if [[ "${DRY_RUN}" == "true" ]]; then
        log_info "DRY-RUN check passed for ${OLD_SG_ID}."
        continue
    fi

    # Authenticate to target account
    if [[ "${ACC_ID}" == "${CURRENT_ACCOUNT_ID}" ]]; then
        clear_assumed_role
    else
        if ! assume_account_role "${ACC_ID}" "${ROLE_NAME}" "SGRestore-${ACC_ID}"; then
            log_error "Could not assume role in target account ${ACC_ID}. Skipping restoration."
            ((FAILED_COUNT++))
            continue
        fi
    fi

    # Step 1: Verify target VPC exists
    if ! aws ec2 describe-vpcs --vpc-ids "${TARGET_VPC}" --region "${REG}" >/dev/null 2>&1; then
        log_error "Target VPC '${TARGET_VPC}' does not exist in ${REG} (Account: ${ACC_ID}). Cannot restore."
        ((FAILED_COUNT++))
        clear_assumed_role
        continue
    fi

    # Step 2: Create Security Group (or locate existing if Default SG)
    if [[ "${SG_NAME}" == "default" ]]; then
        log_step "Restoring rules onto existing Default Security Group in VPC '${TARGET_VPC}'..."
        NEW_SG_ID=$(aws ec2 describe-security-groups \
            --filters "Name=vpc-id,Values=${TARGET_VPC}" "Name=group-name,Values=default" \
            --region "${REG}" \
            --query 'SecurityGroups[0].GroupId' \
            --output text 2>&1)

        if [[ -z "${NEW_SG_ID}" ]] || [[ "${NEW_SG_ID}" == "None" ]] || [[ "${NEW_SG_ID}" == *"Error"* ]] || [[ "${NEW_SG_ID}" == *"Client"* ]]; then
            log_error "Could not locate default security group in VPC '${TARGET_VPC}'."
            ((FAILED_COUNT++))
            clear_assumed_role
            continue
        fi
        log_info "Targeting existing default SG: ${NEW_SG_ID}"
    else
        log_step "Creating security group '${SG_NAME}' in VPC '${TARGET_VPC}'..."
        NEW_SG_ID=$(aws ec2 create-security-group \
            --group-name "${SG_NAME}" \
            --description "${SG_DESC}" \
            --vpc-id "${TARGET_VPC}" \
            --region "${REG}" \
            --query 'GroupId' \
            --output text 2>&1)

        if [[ $? -ne 0 ]] || [[ -z "${NEW_SG_ID}" ]]; then
            # If group name already exists, append timestamp suffix
            if echo "${NEW_SG_ID}" | grep -q "already exists"; then
                FALLBACK_NAME="${SG_NAME}-restored-$(date +%s)"
                log_warn "Group name already exists. Retrying with '${FALLBACK_NAME}'..."
                NEW_SG_ID=$(aws ec2 create-security-group \
                    --group-name "${FALLBACK_NAME}" \
                    --description "${SG_DESC}" \
                    --vpc-id "${TARGET_VPC}" \
                    --region "${REG}" \
                    --query 'GroupId' \
                    --output text 2>&1)
            fi
        fi

        if [[ -z "${NEW_SG_ID}" ]] || [[ "${NEW_SG_ID}" == *"Error"* ]] || [[ "${NEW_SG_ID}" == *"Client"* ]]; then
            log_error "Failed to create security group: ${NEW_SG_ID}"
            ((FAILED_COUNT++))
            clear_assumed_role
            continue
        fi

        log_success "Created Security Group: ${NEW_SG_ID}"
    fi

    # Step 3: Apply Tags
    ORIG_TAGS=$(jq '.SecurityGroup.Tags // []' "${bpath}")
    TAGS_TO_APPLY=$(echo "${ORIG_TAGS}" | jq '. + [{"Key": "RestoredFromBackup", "Value": "true"}, {"Key": "OriginalGroupId", "Value": "'"${OLD_SG_ID}"'"}]')
    
    "${PYTHON_BIN:-python3}" -c "
import sys, json, subprocess
tags = json.loads(sys.argv[1])
sg_id = sys.argv[2]
region = sys.argv[3]
if tags:
    tag_specs = [{'Key': t['Key'], 'Value': t['Value']} for t in tags if not t['Key'].startswith('aws:')]
    if tag_specs:
        formatted = ['Key=' + t['Key'] + ',Value=' + t['Value'] for t in tag_specs]
        cmd = ['aws', 'ec2', 'create-tags', '--resources', sg_id, '--region', region, '--tags'] + formatted
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
" "${TAGS_TO_APPLY}" "${NEW_SG_ID}" "${REG}"

    # Step 4: Authorize Ingress Rules
    if [[ "${INGRESS_RULES_COUNT}" -gt 0 ]]; then
        log_step "Authorizing ${INGRESS_RULES_COUNT} inbound rule(s)..."
        INGRESS_JSON=$(jq -c '.SecurityGroup.IpPermissions' "${bpath}")
        INGRESS_RES=$(aws ec2 authorize-security-group-ingress \
            --group-id "${NEW_SG_ID}" \
            --ip-permissions "${INGRESS_JSON}" \
            --region "${REG}" 2>&1)
        if [[ $? -eq 0 ]]; then
            log_success "Inbound rules authorized successfully."
        else
            log_warn "Some inbound rules could not be authorized (may reference deleted SGs): ${INGRESS_RES}"
        fi
    fi

    # Step 5: Configure Outbound Rules
    if [[ "${EGRESS_RULES_COUNT}" -gt 0 ]]; then
        log_step "Configuring outbound rule(s)..."
        EGRESS_JSON=$(jq -c '.SecurityGroup.IpPermissionsEgress' "${bpath}")
        # Note: AWS default SG creation adds a default 0.0.0.0/0 egress rule.
        # Check if original was custom (not just default)
        aws ec2 authorize-security-group-egress \
            --group-id "${NEW_SG_ID}" \
            --ip-permissions "${EGRESS_JSON}" \
            --region "${REG}" >/dev/null 2>&1
    fi

    log_success "RESTORATION COMPLETED: Original ${OLD_SG_ID} -> Restored ${NEW_SG_ID}"
    ((RESTORED_COUNT++))

    clear_assumed_role

done

log_header "Restoration Summary"
printf "${COLOR_WHITE}%-28s : %s${COLOR_RESET}\n" "Total Evaluated" "${TOTAL_TO_RESTORE}"
if [[ "${DRY_RUN}" == "true" ]]; then
    printf "${COLOR_BLUE}%-28s : %s${COLOR_RESET}\n" "Dry-Run Validated" "${TOTAL_TO_RESTORE}"
else
    printf "${COLOR_GREEN}%-28s : %s${COLOR_RESET}\n" "Successfully Restored" "${RESTORED_COUNT}"
    printf "${COLOR_RED}%-28s : %s${COLOR_RESET}\n" "Failed / Skipped" "${FAILED_COUNT}"
fi

exit 0
