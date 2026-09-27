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
    local account_count="${3:-}"
    local region_count="${4:-}"

    if [[ ! -f "${audit_json}" ]]; then
        log_error "Audit JSON file not found: ${audit_json}"
        return 1
    fi

    if [[ ! -f "${TEMPLATE_FILE}" ]]; then
        log_error "HTML report template not found: ${TEMPLATE_FILE}"
        return 1
    fi

    log_step "Generating interactive HTML security dashboard: ${output_html}..."
    mkdir -p "$(dirname "${output_html}")"

    # Detect python or fallback
    local python_bin=""
    if command -v python3 >/dev/null 2>&1; then
        python_bin="python3"
    elif command -v python >/dev/null 2>&1; then
        python_bin="python"
    fi

    if [[ -n "${python_bin}" ]]; then
        if "${python_bin}" -c "
import sys
import json
import datetime

audit_json_path = sys.argv[1]
template_path = sys.argv[2]
output_html_path = sys.argv[3]

with open(audit_json_path, 'r', encoding='utf-8') as f:
    data = json.load(f)

# Safely parse or compute counts
try:
    account_count = int(sys.argv[4]) if len(sys.argv) > 4 and sys.argv[4].strip() else None
except (ValueError, TypeError):
    account_count = None

if not account_count or account_count <= 0:
    unique_accounts = set(x.get('AccountId') for x in data if x.get('AccountId'))
    account_count = len(unique_accounts) if unique_accounts else 1

try:
    region_count = int(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[5].strip() else None
except (ValueError, TypeError):
    region_count = None

if not region_count or region_count <= 0:
    unique_regions = set(x.get('Region') for x in data if x.get('Region'))
    region_count = len(unique_regions) if unique_regions else 1

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
" "${audit_json}" "${TEMPLATE_FILE}" "${output_html}" "${account_count:-}" "${region_count:-}"; then
            if [[ -s "${output_html}" ]]; then
                log_success "Interactive HTML report generated successfully: ${output_html}"
                return 0
            else
                log_warn "Python execution finished but ${output_html} is empty. Trying fallback..."
            fi
        else
            log_warn "Python script failed to generate HTML. Falling back to alternative stream generator..."
        fi
    fi

    # Stream fallback if python is unavailable or failed (avoids awk buffer limit errors)
    log_info "Embedding JSON data into HTML template via stream fallback..."
    while IFS= read -r line; do
        if [[ "${line}" =~ /\*\ __DATA_PAYLOAD__\ \*/\ \[\] ]]; then
            cat "${audit_json}"
        else
            printf "%s\n" "${line}"
        fi
    done < "${TEMPLATE_FILE}" > "${output_html}"

    if [[ -s "${output_html}" ]]; then
        log_success "Interactive HTML report generated via fallback: ${output_html}"
        return 0
    else
        log_error "Failed to generate HTML report: ${output_html}"
        return 1
    fi
}
