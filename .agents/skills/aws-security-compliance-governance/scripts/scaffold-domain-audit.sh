#!/usr/bin/env bash
# ==============================================================================
# Scaffold Generator for AWS Security Domain Audit Scripts
# Generates production-ready, multi-account audit scripts adhering to enterprise standards.
# ==============================================================================

set -euo pipefail

DOMAIN_NAME="${1:-}"
if [[ -z "${DOMAIN_NAME}" ]]; then
    echo "Usage: $0 <domain_name>"
    echo "Example: $0 container"
    exit 1
fi

DOMAIN_LOWER=$(echo "${DOMAIN_NAME}" | tr '[:upper:]' '[:lower:]')
DOMAIN_UPPER=$(echo "${DOMAIN_NAME}" | tr '[:lower:]' '[:upper:]')
OUTPUT_SCRIPT="audit_${DOMAIN_LOWER}.sh"

cat << 'EOF' > "${OUTPUT_SCRIPT}"
#!/usr/bin/env bash
# ==============================================================================
# AWS Multi-Account Security Audit: DOMAIN_UPPER_PLACEHOLDER Domain
# Scans all active member accounts and regions across an AWS Organization.
# Evaluates compliance, classifies downtime impact, and generates JSON + HTML reports.
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

while [[ $# -gt 0 ]]; do
    case "$1" in
        -a|--accounts) SPECIFIC_ACCOUNTS="$2"; shift 2 ;;
        -g|--regions) SPECIFIC_REGIONS="$2"; shift 2 ;;
        -r|--role|--role-name) ROLE_NAME="$2"; shift 2 ;;
        -o|--output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --no-html) GENERATE_HTML=false; shift ;;
        -h|--help)
            echo "Usage: ./audit_DOMAIN_LOWER_PLACEHOLDER.sh [OPTIONS]"
            exit 0 ;;
        *) log_error "Unknown option: $1"; exit 1 ;;
    esac
done

cleanup() { clear_assumed_role; }
trap cleanup EXIT INT TERM

log_header "AWS DOMAIN_UPPER_PLACEHOLDER Security & Compliance Audit"
check_prerequisites

mkdir -p "${OUTPUT_DIR}"
REPORT_JSON="${OUTPUT_DIR}/DOMAIN_LOWER_PLACEHOLDER_compliance_report_${TIMESTAMP}.json"
REPORT_HTML="${OUTPUT_DIR}/DOMAIN_LOWER_PLACEHOLDER_compliance_report_${TIMESTAMP}.html"
RAW_TEMP_DIR="${OUTPUT_DIR}/.tmp_raw_${TIMESTAMP}"
mkdir -p "${RAW_TEMP_DIR}"

ACCOUNTS_JSON=$(get_organization_accounts "${SPECIFIC_ACCOUNTS}")
ACCOUNT_COUNT=$(echo "${ACCOUNTS_JSON}" | jq '. | length')
log_info "Identified ${ACCOUNT_COUNT} target account(s)."

ALL_FINDINGS="[]"
TOTAL_REGIONS_COUNT=0

for (( i=0; i<ACCOUNT_COUNT; i++ )); do
    ACCOUNT_ID=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Id")
    ACCOUNT_NAME=$(echo "${ACCOUNTS_JSON}" | jq -r ".[$i].Name")
    log_step "Processing Account: ${ACCOUNT_NAME} (${ACCOUNT_ID}) [$((i+1))/${ACCOUNT_COUNT}]..."

    if [[ "${ACCOUNT_ID}" != "${CURRENT_ACCOUNT_ID}" ]]; then
        ASSUMED=false
        for r in "${ROLE_NAME}" "${FALLBACK_ROLES[@]}"; do
            if assume_account_role "${ACCOUNT_ID}" "${r}" "DOMAIN_UPPER_PLACEHOLDERAuditSession"; then
                ASSUMED=true; break
            fi
        done
        if [[ "${ASSUMED}" != "true" ]]; then
            log_warn "Failed to assume role in account ${ACCOUNT_ID}. Skipping."
            continue
        fi
    fi

    REGIONS_JSON=$(get_account_regions "${SPECIFIC_REGIONS}")
    REGION_COUNT=$(echo "${REGIONS_JSON}" | jq '. | length')
    TOTAL_REGIONS_COUNT=$(( TOTAL_REGIONS_COUNT + REGION_COUNT ))

    for (( j=0; j<REGION_COUNT; j++ )); do
        REGION=$(echo "${REGIONS_JSON}" | jq -r ".[$j]")
        log_info "Scanning Region ${REGION} [${ACCOUNT_ID}]..."

        RAW_REG_FILE="${RAW_TEMP_DIR}/${ACCOUNT_ID}_${REGION}_raw.json"
        
        # INSERT DOMAIN SPECIFIC AWS CLI QUERIES HERE
        jq -n '{data: []}' > "${RAW_REG_FILE}"

        FINDINGS=$(${PYTHON_BIN:-python3} "${SCRIPT_DIR}/lib/compliance_engine.py" DOMAIN_LOWER_PLACEHOLDER "${RAW_REG_FILE}" "${ACCOUNT_ID}" "${ACCOUNT_NAME}" "${REGION}" 2>/dev/null || echo "[]")
        ALL_FINDINGS=$(echo "${ALL_FINDINGS}" "${FINDINGS}" | jq -s '.[0] + .[1]')
    done
done

rm -rf "${RAW_TEMP_DIR}"
echo "${ALL_FINDINGS}" | jq . > "${REPORT_JSON}"

if [[ "${GENERATE_HTML}" == "true" ]]; then
    ${PYTHON_BIN:-python3} "${SCRIPT_DIR}/lib/compliance_reporter.py" "${REPORT_JSON}" "${REPORT_HTML}" "" "${ACCOUNT_COUNT}" "${TOTAL_REGIONS_COUNT}"
fi

log_header "DOMAIN_UPPER_PLACEHOLDER Audit Complete"
log_success "JSON report preserved: ${REPORT_JSON}"
[[ "${GENERATE_HTML}" == "true" ]] && log_success "Interactive HTML dashboard: ${REPORT_HTML}"
EOF

sed -i "s/DOMAIN_LOWER_PLACEHOLDER/${DOMAIN_LOWER}/g" "${OUTPUT_SCRIPT}"
sed -i "s/DOMAIN_UPPER_PLACEHOLDER/${DOMAIN_UPPER}/g" "${OUTPUT_SCRIPT}"
chmod +x "${OUTPUT_SCRIPT}"

echo "[SUCCESS] Scaffolded new audit script: ${OUTPUT_SCRIPT}"
