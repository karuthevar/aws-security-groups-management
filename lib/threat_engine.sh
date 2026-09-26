#!/usr/bin/env bash
# ==============================================================================
# AWS Organization Security Group Audit & Cleanup Utility
# Library: threat_engine.sh
# Purpose: Orchestrates threat analysis, port risk evaluation, and attachments
# ==============================================================================

THREAT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

analyze_region_data() {
    local sgs_file="$1"
    local enis_file="$2"
    local account_id="$3"
    local account_name="$4"
    local region="$5"
    local output_file="$6"

    # Prefer python3 or python for rich object processing
    local python_bin=""
    if command -v python3 >/dev/null 2>&1; then
        python_bin="python3"
    elif command -v python >/dev/null 2>&1; then
        python_bin="python"
    fi

    if [[ -n "${python_bin}" ]]; then
        "${python_bin}" "${THREAT_LIB_DIR}/threat_analyzer.py" \
            "${sgs_file}" "${enis_file}" "${account_id}" "${account_name}" "${region}" > "${output_file}"
        return $?
    fi

    # Fallback to jq if python is somehow missing
    if command -v jq >/dev/null 2>&1; then
        # Pure JQ basic transformation
        jq --arg acc "$account_id" --arg acc_name "$account_name" --arg reg "$region" \
           --slurpfile enis "$enis_file" '
            ($enis[0].NetworkInterfaces // $enis[0] // []) as $all_enis |
            ($all_enis | map(.Groups[].GroupId) | unique) as $attached_ids |
            (.SecurityGroups // . // []) | map(
                . as $sg |
                ($sg.GroupName == "default") as $is_default |
                ($attached_ids | index($sg.GroupId) != null) as $is_attached |
                ([$sg.IpPermissions[]?.IpRanges[]? | select(.CidrIp == "0.0.0.0/0")] | length > 0) as $is_exposed |
                {
                    AccountId: $acc,
                    AccountName: $acc_name,
                    Region: $reg,
                    GroupId: $sg.GroupId,
                    GroupName: $sg.GroupName,
                    Description: $sg.Description,
                    VpcId: $sg.VpcId,
                    IsDefault: $is_default,
                    IsAttached: $is_attached,
                    AttachedResourcesCount: (if $is_attached then 1 else 0 end),
                    AttachedResources: [],
                    IsExposedToInternet: $is_exposed,
                    HasUnrestrictedEgress: true,
                    MaxSeverity: (if $is_exposed then "HIGH" else "LOW" end),
                    Threats: [],
                    ThreatCount: 0,
                    Recommendation: (
                        if $is_default then "DEFAULT_RESTRICT"
                        elif ($is_attached | not) then "CAN_DELETE"
                        elif $is_exposed then "RESTRICT_IMMEDIATELY"
                        else "SAFE_IN_USE" end
                    ),
                    ActionTitle: (
                        if $is_default then "Default SG - Restrict Traffic"
                        elif ($is_attached | not) then "Safe to Delete (Unattached)"
                        elif $is_exposed then "Restrict Ingress Immediately"
                        else "Safe & Monitored" end
                    ),
                    ActionDesc: "",
                    IngressRulesCount: ($sg.IpPermissions | length),
                    EgressRulesCount: ($sg.IpPermissionsEgress | length),
                    IpPermissions: $sg.IpPermissions,
                    IpPermissionsEgress: $sg.IpPermissionsEgress,
                    Tags: ($sg.Tags // [])
                }
            )
        ' "${sgs_file}" > "${output_file}"
        return $?
    fi

    log_error "Neither python3/python nor jq is available for threat analysis."
    return 1
}
