#!/usr/bin/env bash
# ==============================================================================
# AWS Organization Security Group Audit & Cleanup Utility
# Library: html_generator.sh
# Purpose: Compiles audit findings and generates single-file interactive HTML dashboard
# ==============================================================================

HTML_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE_FILE="${HTML_LIB_DIR}/../templates/report_template.html"

generate_html_report() {
    local audit_json="$1"
    local output_html="$2"
    local account_count="${3:-1}"
    local region_count="${4:-1}"

    if [[ ! -f "${audit_json}" ]]; then
        log_error "Audit JSON file not found: ${audit_json}"
        return 1
    fi

    if [[ ! -f "${TEMPLATE_FILE}" ]]; then
        log_error "HTML report template not found: ${TEMPLATE_FILE}"
        return 1
    fi

    log_step "Generating interactive HTML security dashboard: ${output_html}..."

    # Detect python or fallback
    local python_bin=""
    if command -v python3 >/dev/null 2>&1; then
        python_bin="python3"
    elif command -v python >/dev/null 2>&1; then
        python_bin="python"
    fi

    if [[ -n "${python_bin}" ]]; then
        "${python_bin}" -c "
import sys
import json
import datetime

audit_json_path = sys.argv[1]
template_path = sys.argv[2]
output_html_path = sys.argv[3]
account_count = int(sys.argv[4])
region_count = int(sys.argv[5])

with open(audit_json_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

metadata = {
    'scanDate': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'accountCount': account_count,
    'regionCount': region_count,
    'totalSGs': len(data)
}

with open(template_path, 'r', encoding='utf-8') as f:
    template_content = f.read()

# Replace payloads
output_content = template_content.replace(
    '/* __DATA_PAYLOAD__ */ []',
    json.dumps(data)
)
if '/* __METADATA_PAYLOAD__ */ {}' in output_content:
    output_content = output_content.replace('/* __METADATA_PAYLOAD__ */ {}', json.dumps(metadata))
else:
    import re
    output_content = re.sub(
        r'const METADATA\s*=\s*/\* __METADATA_PAYLOAD__ \*/\s*\{[^}]*\};',
        f'const METADATA = {json.dumps(metadata)};',
        output_content
    )

with open(output_html_path, 'w', encoding='utf-8') as f:
    f.write(output_content)

print(f'HTML report successfully generated with {len(data)} security groups.')
" "${audit_json}" "${TEMPLATE_FILE}" "${output_html}" "${account_count}" "${region_count}"

        return $?
    fi

    # Fallback to sed/awk if python is unavailable
    log_info "Embedding JSON data into HTML template via awk..."
    awk -v data="$(cat "${audit_json}")" '{gsub(/\/\* __DATA_PAYLOAD__ \*\/ \[\]/, data); print}' "${TEMPLATE_FILE}" > "${output_html}"
    return 0
}
