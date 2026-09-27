#!/usr/bin/env python3
"""
AWS Security Group Threat & Attachment Analyzer
Analyzes security group definitions and network interface attachments to assess
threat exposure, unattached cleanup candidates, and remediation recommendations.
"""

import sys
import json
from typing import Dict, List, Any

# Critical Admin Ports (Open to Internet = CRITICAL)
ADMIN_PORTS = {
    22: "SSH",
    3389: "RDP",
    23: "Telnet",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    5900: "VNC",
}

# Critical Database / Cache Ports (Open to Internet = CRITICAL)
DATABASE_PORTS = {
    3306: "MySQL/Aurora",
    5432: "PostgreSQL",
    1433: "MS-SQL",
    1521: "Oracle-DB",
    27017: "MongoDB",
    6379: "Redis",
    11211: "Memcached",
    9200: "Elasticsearch/OpenSearch-REST",
    9300: "Elasticsearch-Cluster",
    9042: "Cassandra",
}

# High Risk Infrastructure Ports (Open to Internet = HIGH)
HIGH_PORTS = {
    6443: "Kubernetes-API",
    2375: "Docker-Daemon-HTTP",
    2376: "Docker-Daemon-HTTPS",
    389: "LDAP",
    636: "LDAPS",
    445: "SMB",
    2049: "NFS",
    25: "SMTP",
    53: "DNS",
}

# Web Service Ports (Open to Internet = MEDIUM - review ALB/WAF)
WEB_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
}

def is_public_cidr(cidr: str) -> bool:
    """Checks if a CIDR represents public internet (0.0.0.0/0, ::/0, or /0)."""
    if not cidr:
        return False
    c = cidr.strip()
    return c == "0.0.0.0/0" or c == "::/0" or c.endswith("/0")

def analyze_rule(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyzes an ingress rule and identifies public exposures and threats.
    """
    findings = []
    protocol = rule.get("IpProtocol", "")
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    # Extract all public CIDRs in this rule
    public_cidrs = []
    for ip_range in rule.get("IpRanges", []):
        cidr = ip_range.get("CidrIp", "")
        if is_public_cidr(cidr):
            public_cidrs.append(cidr)

    for ipv6_range in rule.get("Ipv6Ranges", []):
        cidr = ipv6_range.get("CidrIpv6", "")
        if is_public_cidr(cidr):
            public_cidrs.append(cidr)

    if not public_cidrs:
        return findings

    cidr_str = ", ".join(sorted(set(public_cidrs)))

    # Case 1: All Traffic / All Ports (-1 or 0-65535)
    if protocol == "-1" or (from_port == 0 and to_port == 65535):
        findings.append({
            "severity": "CRITICAL",
            "threat_type": "ALL_TRAFFIC_EXPOSED",
            "message": f"ALL traffic (protocols & ports 0-65535) open to public internet ({cidr_str})",
            "port_info": "ALL TRAFFIC (-1)",
            "protocol": "ALL",
            "cidrs": public_cidrs
        })
        return findings

    # Port range handling
    fp = from_port if from_port is not None else 0
    tp = to_port if to_port is not None else 65535

    port_desc = f"{fp}" if fp == tp else f"{fp}-{tp}"

    # Check Administrative Ports
    for port, svc in ADMIN_PORTS.items():
        if fp <= port <= tp:
            findings.append({
                "severity": "CRITICAL",
                "threat_type": "ADMIN_PORT_EXPOSED",
                "message": f"Management port {port} ({svc}) open to public internet ({cidr_str})",
                "port_info": f"{svc} ({port})",
                "protocol": protocol,
                "cidrs": public_cidrs
            })

    # Check Database Ports
    for port, svc in DATABASE_PORTS.items():
        if fp <= port <= tp:
            findings.append({
                "severity": "CRITICAL",
                "threat_type": "DATABASE_PORT_EXPOSED",
                "message": f"Database port {port} ({svc}) open to public internet ({cidr_str})",
                "port_info": f"{svc} ({port})",
                "protocol": protocol,
                "cidrs": public_cidrs
            })

    # Check High Risk Ports
    for port, svc in HIGH_PORTS.items():
        if fp <= port <= tp:
            findings.append({
                "severity": "HIGH",
                "threat_type": "HIGH_RISK_PORT_EXPOSED",
                "message": f"Internal service port {port} ({svc}) open to public internet ({cidr_str})",
                "port_info": f"{svc} ({port})",
                "protocol": protocol,
                "cidrs": public_cidrs
            })

    # Check Web Ports
    for port, svc in WEB_PORTS.items():
        if fp <= port <= tp:
            findings.append({
                "severity": "MEDIUM",
                "threat_type": "WEB_PORT_EXPOSED",
                "message": f"Web port {port} ({svc}) open to public internet ({cidr_str}) - verify ALB/WAF protection",
                "port_info": f"{svc} ({port})",
                "protocol": protocol,
                "cidrs": public_cidrs
            })

    # If no specific port matched but a range or custom port is exposed
    if not findings:
        range_size = tp - fp + 1
        if range_size > 100:
            findings.append({
                "severity": "HIGH",
                "threat_type": "WIDE_PORT_RANGE",
                "message": f"Broad port range {port_desc} ({protocol.upper()}) open to public internet ({cidr_str})",
                "port_info": f"Range {port_desc}",
                "protocol": protocol,
                "cidrs": public_cidrs
            })
        else:
            findings.append({
                "severity": "MEDIUM",
                "threat_type": "CUSTOM_PORT_EXPOSED",
                "message": f"Custom port/range {port_desc} ({protocol.upper()}) open to public internet ({cidr_str})",
                "port_info": f"Port {port_desc}",
                "protocol": protocol,
                "cidrs": public_cidrs
            })

    return findings

def analyze_security_groups(
    sgs_data: List[Dict[str, Any]],
    enis_data: List[Dict[str, Any]],
    account_id: str,
    account_name: str,
    region: str
) -> List[Dict[str, Any]]:
    """
    Correlates security groups with network interfaces and performs threat analysis.
    """
    # Build map of SG ID -> Attached ENI summaries
    sg_attachment_map: Dict[str, List[Dict[str, Any]]] = {}
    for eni in enis_data:
        eni_id = eni.get("NetworkInterfaceId", "")
        eni_desc = eni.get("Description", "")
        eni_type = eni.get("InterfaceType", "interface")
        attachment = eni.get("Attachment", {})
        instance_id = attachment.get("InstanceId", "")
        resource_id = instance_id or attachment.get("AttachmentId", eni_id)

        resource_summary = {
            "NetworkInterfaceId": eni_id,
            "InterfaceType": eni_type,
            "Description": eni_desc,
            "InstanceId": instance_id,
            "ResourceId": resource_id
        }

        for group in eni.get("Groups", []):
            gid = group.get("GroupId")
            if gid:
                if gid not in sg_attachment_map:
                    sg_attachment_map[gid] = []
                sg_attachment_map[gid].append(resource_summary)

    analyzed_groups = []

    for sg in sgs_data:
        gid = sg.get("GroupId", "")
        gname = sg.get("GroupName", "")
        desc = sg.get("Description", "")
        vpc_id = sg.get("VpcId", "")
        is_default = (gname == "default")

        # Attachment status
        attached_enis = sg_attachment_map.get(gid, [])
        is_attached = len(attached_enis) > 0
        attached_count = len(attached_enis)

        # Ingress threat evaluation
        all_threats: List[Dict[str, Any]] = []
        is_exposed_to_internet = False

        ingress_rules = sg.get("IpPermissions", [])
        for rule in ingress_rules:
            findings = analyze_rule(rule)
            if findings:
                is_exposed_to_internet = True
                all_threats.extend(findings)

        # Check egress rules for overly permissive outbound
        egress_rules = sg.get("IpPermissionsEgress", [])
        has_unrestricted_egress = False
        for erule in egress_rules:
            if erule.get("IpProtocol") == "-1":
                for ip_range in erule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        has_unrestricted_egress = True
                        break

        # Calculate max severity
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "CLEAN": 0}
        current_max_rank = 0
        max_severity = "CLEAN"

        for threat in all_threats:
            sev = threat.get("severity", "LOW")
            rank = severity_rank.get(sev, 0)
            if rank > current_max_rank:
                current_max_rank = rank
                max_severity = sev

        # If no ingress threats found, but unrestricted egress is present
        if current_max_rank == 0:
            if is_exposed_to_internet:
                max_severity = "MEDIUM"
            else:
                max_severity = "LOW" if len(ingress_rules) > 0 else "CLEAN"

        # Determine actionable recommendation
        ingress_count = len(ingress_rules)
        if is_default:
            if ingress_count > 0:
                recommendation = "DEFAULT_RESTRICT"
                action_title = "Remove Ingress Rules (Default SG - Make Clean)"
                action_desc = f"AWS Default Security Group cannot be deleted via AWS API. Remove its {ingress_count} inbound rule(s) to isolate and make it completely clean."
            else:
                recommendation = "DEFAULT_CLEAN"
                action_title = "Default SG - Clean (0 Inbound Rules)"
                action_desc = "AWS Default Security Group has 0 inbound rules. Already restricted and clean."
        elif not is_attached:
            recommendation = "CAN_DELETE"
            action_title = "Safe to Delete (No Attached Resources)"
            action_desc = "No active resources (0 ENIs) are attached. Safe to back up and delete to eliminate clutter and attack surface."
        elif is_attached and max_severity in ("CRITICAL", "HIGH"):
            recommendation = "RESTRICT_IMMEDIATELY"
            action_title = "Restrict Ingress Immediately"
            action_desc = f"Actively attached to resources with {max_severity} internet exposure ({len(all_threats)} threats detected). Restrict ingress to authorized IP/VPC ranges."
        elif is_attached and max_severity == "MEDIUM":
            recommendation = "REVIEW_EXPOSURE"
            action_title = "Review Public Exposure"
            action_desc = "Actively attached to resources with public web or custom port ingress. Confirm if internet-facing ALB/WAF is intended, otherwise restrict."
        else:
            recommendation = "SAFE_IN_USE"
            action_title = "Safe & Monitored"
            action_desc = "Actively attached to resources. No public internet ingress detected (internal/private rules only)."

        analyzed_groups.append({
            "AccountId": account_id,
            "AccountName": account_name,
            "Region": region,
            "GroupId": gid,
            "GroupName": gname,
            "Description": desc,
            "VpcId": vpc_id,
            "IsDefault": is_default,
            "IsAttached": is_attached,
            "AttachedResourcesCount": attached_count,
            "AttachedResources": attached_enis[:15], # cap details for JSON brevity
            "IsExposedToInternet": is_exposed_to_internet,
            "HasUnrestrictedEgress": has_unrestricted_egress,
            "MaxSeverity": max_severity,
            "Threats": all_threats,
            "ThreatCount": len(all_threats),
            "Recommendation": recommendation,
            "ActionTitle": action_title,
            "ActionDesc": action_desc,
            "IngressRulesCount": len(ingress_rules),
            "EgressRulesCount": len(egress_rules),
            "IpPermissions": ingress_rules,
            "IpPermissionsEgress": egress_rules,
            "Tags": sg.get("Tags", [])
        })

    return analyzed_groups

def main():
    if len(sys.argv) < 6:
        sys.stderr.write("Usage: threat_analyzer.py <sgs_json_file> <enis_json_file> <account_id> <account_name> <region>\n")
        sys.exit(1)

    sgs_file = sys.argv[1]
    enis_file = sys.argv[2]
    account_id = sys.argv[3]
    account_name = sys.argv[4]
    region = sys.argv[5]

    try:
        with open(sgs_file, "r", encoding="utf-8") as f:
            sgs_raw = json.load(f)
            sgs_data = sgs_raw.get("SecurityGroups", sgs_raw) if isinstance(sgs_raw, dict) else sgs_raw
    except Exception as e:
        sys.stderr.write(f"Error reading SGs file {sgs_file}: {e}\n")
        sgs_data = []

    try:
        with open(enis_file, "r", encoding="utf-8") as f:
            enis_raw = json.load(f)
            enis_data = enis_raw.get("NetworkInterfaces", enis_raw) if isinstance(enis_raw, dict) else enis_raw
    except Exception as e:
        sys.stderr.write(f"Error reading ENIs file {enis_file}: {e}\n")
        enis_data = []

    results = analyze_security_groups(sgs_data, enis_data, account_id, account_name, region)
    print(json.dumps(results))

if __name__ == "__main__":
    main()
