#!/usr/bin/env bash
# ==============================================================================
# AWS Organization Security Group Audit & Cleanup Utility
# Library: common.sh
# Purpose: Shared utility functions, logging, auth/assume-role, and prerequisites
# ==============================================================================

set -o pipefail

# --- Color Definitions ---
if [[ -t 1 ]] && [[ -z "${NO_COLOR:-}" ]]; then
    COLOR_RESET="\033[0m"
    COLOR_RED="\033[1;31m"
    COLOR_GREEN="\033[1;32m"
    COLOR_YELLOW="\033[1;33m"
    COLOR_BLUE="\033[1;34m"
    COLOR_CYAN="\033[1;36m"
    COLOR_GRAY="\033[0;90m"
    COLOR_WHITE="\033[1;37m"
    COLOR_MAGENTA="\033[1;35m"
else
    COLOR_RESET=""
    COLOR_RED=""
    COLOR_GREEN=""
    COLOR_YELLOW=""
    COLOR_BLUE=""
    COLOR_CYAN=""
    COLOR_GRAY=""
    COLOR_WHITE=""
    COLOR_MAGENTA=""
fi

# --- Logging Helpers ---
log_info() {
    printf "${COLOR_BLUE}[INFO]${COLOR_RESET} %b\n" "$*" >&2
}

log_step() {
    printf "${COLOR_CYAN}[STEP]${COLOR_RESET} %b\n" "$*" >&2
}

log_success() {
    printf "${COLOR_GREEN}[SUCCESS]${COLOR_RESET} %b\n" "$*" >&2
}

log_warn() {
    printf "${COLOR_YELLOW}[WARN]${COLOR_RESET} %b\n" "$*" >&2
}

log_error() {
    printf "${COLOR_RED}[ERROR]${COLOR_RESET} %b\n" "$*" >&2
}

log_header() {
    local text="$1"
    local border="================================================================================"
    printf "\n${COLOR_CYAN}%s\n %s\n%s${COLOR_RESET}\n" "$border" "$text" "$border" >&2
}

# --- Python Binary Detection ---
if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_BIN="python"
else
    PYTHON_BIN=""
fi

# --- Check Prerequisites ---
check_prerequisites() {
    local missing=0

    if ! command -v aws >/dev/null 2>&1; then
        log_error "AWS CLI ('aws') is not installed or not found in PATH."
        log_info "Please install AWS CLI v2: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        missing=1
    fi

    if ! command -v jq >/dev/null 2>&1; then
        # Check if python/python3 is available to suggest or act as fallback
        log_error "'jq' is not installed or not found in PATH."
        log_info "On Amazon Linux / RHEL / CentOS: sudo yum install -y jq"
        log_info "On Ubuntu / Debian:             sudo apt-get install -y jq"
        log_info "On macOS:                       brew install jq"
        log_info "On Windows (Git Bash/Chocolatey): choco install jq"
        missing=1
    fi

    if [[ "$missing" -eq 1 ]]; then
        log_error "Missing required dependencies. Please install them and re-run."
        exit 1
    fi

    if [[ "${SKIP_AWS_AUTH_CHECK:-}" == "1" ]]; then
        CURRENT_ACCOUNT_ID="${TEST_ACCOUNT_ID:-111122223333}"
        CURRENT_ARN="arn:aws:iam::${CURRENT_ACCOUNT_ID}:user/simulation-admin"
        log_info "Running in simulation/offline mode (Auth check skipped)."
        return 0
    fi

    # Verify AWS authentication
    log_info "Verifying AWS caller identity..."
    local caller_identity
    if ! caller_identity=$(aws sts get-caller-identity --output json 2>&1); then
        log_error "Failed to retrieve AWS caller identity. Are your AWS credentials configured?"
        log_error "Details: ${caller_identity}"
        exit 1
    fi

    CURRENT_ACCOUNT_ID=$(echo "${caller_identity}" | jq -r '.Account')
    CURRENT_ARN=$(echo "${caller_identity}" | jq -r '.Arn')
    log_success "Authenticated as: ${CURRENT_ARN} (Account: ${CURRENT_ACCOUNT_ID})"
}

# --- Preserved Original AWS Credentials ---
ORIG_AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
ORIG_AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
ORIG_AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-}"

# --- Assume IAM Role in Target Account ---
assume_account_role() {
    local target_account_id="$1"
    local role_name="$2"
    local session_name="${3:-SGAuditSession}"

    # If the target account is the current caller account, do not assume role unless required
    if [[ "${target_account_id}" == "${CURRENT_ACCOUNT_ID}" ]]; then
        clear_assumed_role
        return 0
    fi

    local target_role_arn="arn:aws:iam::${target_account_id}:role/${role_name}"
    local creds

    creds=$(aws sts assume-role \
        --role-arn "${target_role_arn}" \
        --role-session-name "${session_name}" \
        --duration-seconds 3600 \
        --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' \
        --output text 2>/dev/null)

    if [[ $? -ne 0 ]] || [[ -z "${creds}" ]]; then
        return 1
    fi

    local access_key
    local secret_key
    local session_token
    access_key=$(echo "${creds}" | awk '{print $1}')
    secret_key=$(echo "${creds}" | awk '{print $2}')
    session_token=$(echo "${creds}" | awk '{print $3}')

    export AWS_ACCESS_KEY_ID="${access_key}"
    export AWS_SECRET_ACCESS_KEY="${secret_key}"
    export AWS_SESSION_TOKEN="${session_token}"

    return 0
}

# --- Restore / Clear Assumed Role ---
clear_assumed_role() {
    if [[ -n "${ORIG_AWS_ACCESS_KEY_ID}" ]]; then
        export AWS_ACCESS_KEY_ID="${ORIG_AWS_ACCESS_KEY_ID}"
    else
        unset AWS_ACCESS_KEY_ID
    fi

    if [[ -n "${ORIG_AWS_SECRET_ACCESS_KEY}" ]]; then
        export AWS_SECRET_ACCESS_KEY="${ORIG_AWS_SECRET_ACCESS_KEY}"
    else
        unset AWS_SECRET_ACCESS_KEY
    fi

    if [[ -n "${ORIG_AWS_SESSION_TOKEN}" ]]; then
        export AWS_SESSION_TOKEN="${ORIG_AWS_SESSION_TOKEN}"
    else
        unset AWS_SESSION_TOKEN
    fi
}

# --- Discover Active Organization Accounts ---
get_organization_accounts() {
    local specific_accounts="$1" # Optional comma-separated list of account IDs

    if [[ -n "${specific_accounts}" ]]; then
        # Filter down to the explicitly provided accounts
        log_info "Using specified account filter: ${specific_accounts}"
        local accounts_json="[]"
        IFS=',' read -ra ADDR <<< "${specific_accounts}"
        for acc in "${ADDR[@]}"; do
            acc=$(echo "$acc" | tr -d '[:space:]')
            if [[ -n "$acc" ]]; then
                accounts_json=$(echo "${accounts_json}" | jq --arg id "$acc" '. + [{"Id": $id, "Name": ("Account-" + $id), "Email": "N/A"}]')
            fi
        done
        echo "${accounts_json}"
        return 0
    fi

    # Query AWS Organizations
    clear_assumed_role
    local org_accounts
    log_info "Querying AWS Organizations for active member accounts..."
    
    org_accounts=$(aws organizations list-accounts \
        --query 'Accounts[?Status==`ACTIVE`].[Id,Name,Email]' \
        --output json 2>/dev/null)

    if [[ $? -ne 0 ]] || [[ -z "${org_accounts}" ]] || [[ "${org_accounts}" == "null" ]]; then
        log_warn "Could not query AWS Organizations (or account is not an Organization Root/Delegated Admin)."
        log_warn "Falling back to scanning ONLY current account: ${CURRENT_ACCOUNT_ID}"
        echo "[{\"Id\": \"${CURRENT_ACCOUNT_ID}\", \"Name\": \"Management-Account\", \"Email\": \"N/A\"}]"
        return 0
    fi

    # Format into standard JSON objects: [{Id, Name, Email}]
    echo "${org_accounts}" | jq '[.[] | {Id: .[0], Name: .[1], Email: .[2]}]'
}

# --- Get Enabled Regions for an Account ---
get_account_regions() {
    local specific_regions="$1" # Optional comma-separated list of regions

    if [[ -n "${specific_regions}" ]]; then
        local regions_json="[]"
        IFS=',' read -ra ADDR <<< "${specific_regions}"
        for reg in "${ADDR[@]}"; do
            reg=$(echo "$reg" | tr -d '[:space:]')
            if [[ -n "$reg" ]]; then
                regions_json=$(echo "${regions_json}" | jq --arg r "$reg" '. + [$r]')
            fi
        done
        echo "${regions_json}"
        return 0
    fi

    local regions
    regions=$(aws ec2 describe-regions \
        --query 'Regions[].RegionName' \
        --output json 2>/dev/null)

    if [[ $? -ne 0 ]] || [[ -z "${regions}" ]] || [[ "${regions}" == "null" ]]; then
        # Default fallback to common regions if API fails
        echo '["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1"]'
        return 0
    fi

    echo "${regions}"
}
