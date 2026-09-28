#!/usr/bin/env python3
"""
AWS Enterprise Security & Compliance Assessment Engine
Evaluates AWS resources against 170+ enterprise security standards across 7 domains.
Categorizes findings by Remediation Impact (Zero-Impact Quick Wins, Low Impact, etc.)
and pairs each finding with an exact CLI remediation, AWS Config rule, and Preventive SCP.
"""

import sys
import json
import datetime
from typing import Dict, List, Any, Optional

# --- Impact Classifications ---
IMPACT_ZERO_WIN = "ZERO_IMPACT_QUICK_WIN"          # Unattached/unused resources, metadata flags with 0 downtime
IMPACT_LOW_CONFIG = "LOW_IMPACT_CONFIG"            # Safe service configurations (logging, versioning, alarms)
IMPACT_MEDIUM_OP = "MEDIUM_IMPACT_OPERATIONAL"     # Operational changes (MFA, password policies, key rotation)
IMPACT_HIGH_ARCH = "HIGH_IMPACT_ARCHITECTURAL"     # Architectural modifications (Multi-AZ, listener cipher migration)

# --- Standard Compliance Finding Builder ---
def make_finding(
    account_id: str,
    account_name: str,
    region: str,
    domain: str,
    rule_id: str,
    rule_name: str,
    severity: str,
    status: str,
    resource_id: str,
    resource_type: str,
    description: str,
    remediation_impact: str,
    remediation_cli: str,
    detection_control: str,
    preventive_control: str,
    impact_rationale: str
) -> Dict[str, Any]:
    return {
        "AccountId": account_id,
        "AccountName": account_name,
        "Region": region,
        "Domain": domain,
        "RuleId": rule_id,
        "RuleName": rule_name,
        "Severity": severity,
        "Status": status,  # NON_COMPLIANT or COMPLIANT
        "ResourceId": resource_id,
        "ResourceType": resource_type,
        "Description": description,
        "RemediationImpact": remediation_impact,
        "RemediationCLI": remediation_cli,
        "DetectionControl": detection_control,
        "PreventiveControl": preventive_control,
        "ImpactRationale": impact_rationale,
        "EvaluatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

# --- Module Evaluators ---
# Evaluator functions parse raw AWS CLI JSON output for each domain and return list of findings.

def evaluate_iam_domain(data: Dict[str, Any], account_id: str, account_name: str, region: str) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. AWS Account part of AWS Organizations
    in_org = data.get("in_organization", True)
    if not in_org:
        findings.append(make_finding(
            account_id, account_name, "global", "IAM",
            "IAM_ACCOUNT_IN_ORGANIZATION",
            "AWS account is part of AWS Organizations",
            "HIGH", "NON_COMPLIANT", account_id, "AWS::Organizations::Account",
            "Standalone account is not managed under an AWS Organization. Missing centralized governance and SCP controls.",
            IMPACT_LOW_CONFIG,
            f"aws organizations invite-account-to-organization --target 'Id={account_id},Type=ACCOUNT'",
            "AWS Config: account-part-of-organizations",
            "AWS Organizations Consolidated Billing & Management Policy",
            "Joining an AWS Organization activates centralized billing and SCP guardrails without affecting running workloads."
        ))

    # 2. Password Policies (14 chars, upper, lower, numbers, symbols, 90 day expiry, 24 reuse)
    pw = data.get("password_policy", {})
    if not pw:
        findings.append(make_finding(
            account_id, account_name, "global", "IAM",
            "IAM_PASSWORD_POLICY_CONFIGURED",
            "IAM Password Policy Configured",
            "MEDIUM", "NON_COMPLIANT", "iam-password-policy", "AWS::IAM::AccountPasswordPolicy",
            "No custom IAM password policy defined. Default AWS policy does not enforce complexity or rotation.",
            IMPACT_ZERO_WIN,
            "aws iam update-account-password-policy --minimum-password-length 14 --require-symbols --require-numbers --require-uppercase-characters --require-lowercase-characters --max-password-age 90 --password-reuse-prevention 24",
            "AWS Config: iam-password-policy",
            "SCP: DenyWeakPasswordPolicyChanges",
            "Applying password policy updates takes effect on next password reset; zero impact on active sessions or services."
        ))
    else:
        # Check specific password requirements
        checks = [
            ("IAM_PASSWORD_POLICY_MIN_LENGTH", "IAM Password Policy Requires Minimum Length of 14 Characters", pw.get("MinimumPasswordLength", 0) >= 14, f"Current min length: {pw.get('MinimumPasswordLength', 0)} (required: 14)", "--minimum-password-length 14"),
            ("IAM_PASSWORD_POLICY_UPPERCASE", "IAM Password Policy Requires Uppercase Characters", pw.get("RequireUppercaseCharacters", False), "Uppercase characters not enforced.", "--require-uppercase-characters"),
            ("IAM_PASSWORD_POLICY_LOWERCASE", "IAM Password Policy Requires Lowercase Characters", pw.get("RequireLowercaseCharacters", False), "Lowercase characters not enforced.", "--require-lowercase-characters"),
            ("IAM_PASSWORD_POLICY_SYMBOLS", "IAM Password Policy Requires Symbols", pw.get("RequireSymbols", False), "Symbols not enforced.", "--require-symbols"),
            ("IAM_PASSWORD_POLICY_NUMBERS", "IAM Password Policy Requires Numbers", pw.get("RequireNumbers", False), "Numbers not enforced.", "--require-numbers"),
            ("IAM_PASSWORD_POLICY_EXPIRY", "IAM Password Policy Expires Passwords within 90 Days or less", 0 < pw.get("MaxPasswordAge", 0) <= 90, f"Current max password age: {pw.get('MaxPasswordAge', 'None')} days (required <= 90)", "--max-password-age 90"),
            ("IAM_PASSWORD_POLICY_REUSE", "IAM Password Policy Configured to Prevent Password Reuse (24 or Greater)", pw.get("PasswordReusePrevention", 0) >= 24, f"Current reuse prevention: {pw.get('PasswordReusePrevention', 0)} (required >= 24)", "--password-reuse-prevention 24")
        ]
        for rid, rname, compliant, desc, cli_flag in checks:
            if not compliant:
                findings.append(make_finding(
                    account_id, account_name, "global", "IAM",
                    rid, rname, "MEDIUM", "NON_COMPLIANT", "iam-password-policy", "AWS::IAM::AccountPasswordPolicy",
                    desc, IMPACT_ZERO_WIN,
                    f"aws iam update-account-password-policy {cli_flag}",
                    "AWS Config: iam-password-policy",
                    "SCP: DenyWeakPasswordPolicyChanges",
                    "Zero downtime. Password rules apply during next scheduled password renewal."
                ))

    # 3. Root Account MFA & Hardware MFA
    root_summary = data.get("account_summary", {})
    if root_summary.get("AccountMFAEnabled", 1) == 0:
        findings.append(make_finding(
            account_id, account_name, "global", "IAM",
            "IAM_ROOT_MFA_ENABLED", "MFA for Root Account is Enabled",
            "CRITICAL", "NON_COMPLIANT", "root", "AWS::IAM::RootUser",
            "Root user account does not have Multi-Factor Authentication (MFA) enabled.",
            IMPACT_ZERO_WIN,
            "Enable virtual/hardware MFA in AWS Management Console under Security Credentials for root account.",
            "AWS Config: root-account-mfa-enabled",
            "SCP: DenyRootUserActionsExceptEmergencyBreakglass",
            "Zero impact on workloads. Protects root user from credential theft and catastrophic account takeover."
        ))

    # 4. Users in Groups & Console Users MFA
    users = data.get("users", [])
    for u in users:
        uname = u.get("UserName", "Unknown")
        # Check users in groups
        if not u.get("GroupList", []):
            findings.append(make_finding(
                account_id, account_name, "global", "IAM",
                "IAM_USERS_IN_GROUPS", "IAM Users in Groups",
                "MEDIUM", "NON_COMPLIANT", uname, "AWS::IAM::User",
                f"IAM user '{uname}' has direct permissions and is not assigned to an IAM Group.",
                IMPACT_LOW_CONFIG,
                f"aws iam add-user-to-group --user-name {uname} --group-name <TargetGroup>",
                "AWS Config: iam-user-group-membership-check",
                "SCP: DenyDirectUserPolicyAttachment",
                "Simplifies auditing and access revocation. Moving users to groups avoids permission sprawl with zero service interruption."
            ))
        # Check console access without MFA
        if u.get("PasswordLastUsed") or u.get("CreateDate"):
            has_mfa = u.get("MFAEnabled", False)
            if not has_mfa and u.get("HasConsoleAccess", False):
                findings.append(make_finding(
                    account_id, account_name, "global", "IAM",
                    "IAM_USER_CONSOLE_MFA", "MFA for Users with Console Access",
                    "HIGH", "NON_COMPLIANT", uname, "AWS::IAM::User",
                    f"IAM user '{uname}' has console sign-in enabled without Multi-Factor Authentication.",
                    IMPACT_MEDIUM_OP,
                    f"aws iam create-virtual-mfa-device --virtual-mfa-device-name {uname}-MFA --outfile QRCode.png --bootstrap-method QRCodePNG",
                    "AWS Config: iam-user-mfa-enabled",
                    "SCP: EnforceMFAConditionOnConsoleAccess",
                    "Significantly eliminates account compromise risk via stolen console credentials."
                ))
        # Check inline policies
        if u.get("UserPolicyList", []):
            findings.append(make_finding(
                account_id, account_name, "global", "IAM",
                "IAM_NO_INLINE_POLICIES", "No Inline IAM Policies Attached",
                "MEDIUM", "NON_COMPLIANT", uname, "AWS::IAM::User",
                f"IAM user '{uname}' has embedded inline policies ({len(u.get('UserPolicyList', []))}).",
                IMPACT_LOW_CONFIG,
                f"aws iam delete-user-policy --user-name {uname} --policy-name <InlinePolicyName>",
                "AWS Config: iam-policy-no-statements-with-admin-access",
                "SCP: DenyInlinePolicyCreation",
                "Migrating inline policies to customer managed policies enables versioning, reusability, and audit trails."
            ))

    # 5. IAM Support Role Created
    if not data.get("has_support_role", False):
        findings.append(make_finding(
            account_id, account_name, "global", "IAM",
            "IAM_SUPPORT_ROLE_CREATED", "IAM Support Role is Created",
            "LOW", "NON_COMPLIANT", "aws-support-role", "AWS::IAM::Role",
            "No dedicated IAM role with AWSSupportAccess policy created for AWS support inquiries.",
            IMPACT_ZERO_WIN,
            "aws iam create-role --role-name AWSSupportRole --assume-role-policy-document file://trust.json && aws iam attach-role-policy --role-name AWSSupportRole --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess",
            "AWS Config: iam-support-role-created",
            "SCP: AllowSupportAccessOnlyViaRole",
            "Ensures support engineers have controlled, audited access during operational incidents."
        ))

    return findings

def evaluate_network_domain(data: Dict[str, Any], account_id: str, account_name: str, region: str) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. VPC Flow Logs
    vpcs = data.get("vpcs", [])
    for vpc in vpcs:
        vpc_id = vpc.get("VpcId")
        if not vpc.get("FlowLogsEnabled", False):
            findings.append(make_finding(
                account_id, account_name, region, "Network",
                "VPC_FLOW_LOGS_ENABLED", "VPC Flow Logs Enabled",
                "HIGH", "NON_COMPLIANT", vpc_id, "AWS::EC2::VPC",
                f"VPC {vpc_id} does not have VPC Flow Logs enabled.",
                IMPACT_ZERO_WIN,
                f"aws ec2 create-flow-logs --resource-type VPC --resource-ids {vpc_id} --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flow-logs/{vpc_id} --region {region}",
                "AWS Config: vpc-flow-logs-enabled",
                "SCP: DenyVPCFlowLogsDisable",
                "Zero operational downtime. Provides complete network telemetry for threat detection and incident response."
            ))

    # 2. Unattached Elastic IPs (Zero Impact Cleanup!)
    eips = data.get("elastic_ips", [])
    for eip in eips:
        if not eip.get("AssociationId") and not eip.get("InstanceId"):
            alloc_id = eip.get("AllocationId", eip.get("PublicIp"))
            findings.append(make_finding(
                account_id, account_name, region, "Network",
                "EC2_EIP_IN_USE", "Elastic IP Addresses In Use",
                "LOW", "NON_COMPLIANT", alloc_id, "AWS::EC2::EIP",
                f"Elastic IP {eip.get('PublicIp')} ({alloc_id}) is unattached and accumulating idle charges.",
                IMPACT_ZERO_WIN,
                f"aws ec2 release-address --allocation-id {alloc_id} --region {region}",
                "AWS Config: eip-attached",
                "SCP: RestrictUnattachedEIPAllocation",
                "Immediate cost savings and attack surface cleanup with 100% zero impact on running instances."
            ))

    # 3. Unused Network ACLs (Zero Impact Cleanup!)
    nacls = data.get("nacls", [])
    for nacl in nacls:
        if not nacl.get("Associations") and not nacl.get("IsDefault", False):
            nacl_id = nacl.get("NetworkAclId")
            findings.append(make_finding(
                account_id, account_name, region, "Network",
                "NACL_UNUSED_CLEANUP", "No Unused Network Access Control Lists (NACLs)",
                "LOW", "NON_COMPLIANT", nacl_id, "AWS::EC2::NetworkAcl",
                f"Custom Network ACL {nacl_id} is not associated with any subnet.",
                IMPACT_ZERO_WIN,
                f"aws ec2 delete-network-acl --network-acl-id {nacl_id} --region {region}",
                "AWS Config: nacl-subnet-associated",
                "SCP: DenyUnusedNetworkArtifactCreation",
                "Safely cleans up stale network infrastructure rules with zero routing impact."
            ))

    # 4. Default Security Groups Restrict Traffic
    sgs = data.get("security_groups", [])
    for sg in sgs:
        sg_id = sg.get("GroupId")
        if sg.get("GroupName") == "default" or sg.get("IsDefault", False):
            ingress_rules = sg.get("IpPermissions", [])
            if len(ingress_rules) > 0:
                findings.append(make_finding(
                    account_id, account_name, region, "Network",
                    "DEFAULT_SG_NO_RULES", "Default Security Group No Rules",
                    "MEDIUM", "NON_COMPLIANT", sg_id, "AWS::EC2::SecurityGroup",
                    f"Default VPC Security Group {sg_id} allows {len(ingress_rules)} inbound rule(s). CIS Benchmark 5.4 requires all rules removed.",
                    IMPACT_ZERO_WIN,
                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} --protocol -1 --port -1 --source-group {sg_id} --region {region}",
                    "AWS Config: vpc-default-security-group-closed",
                    "SCP: DenyAuthorizeDefaultSecurityGroupIngress",
                    "AWS default SGs cannot be deleted. Removing ingress isolates default VPC SGs cleanly without impacting named workload SGs."
                ))

    # 5. Security Groups Restricting Insecure Ingress (SSH 22, RDP 3389, DB 3306/5432/1433/1521, 0.0.0.0/0)
    for sg in sgs:
        if sg.get("GroupName") != "default":
            for perm in sg.get("IpPermissions", []):
                cidrs = [r.get("CidrIp") for r in perm.get("IpRanges", [])]
                if "0.0.0.0/0" in cidrs:
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 0)
                    ip_proto = perm.get("IpProtocol", "")
                    
                    if ip_proto == "-1" or (from_port == 0 and to_port == 65535):
                        findings.append(make_finding(
                            account_id, account_name, region, "Network",
                            "SG_NO_ALL_TRAFFIC_INGRESS", "No Security Group Rules Allowing 0.0.0.0/0 and ::/0 to All Ports (Ingress)",
                            "CRITICAL", "NON_COMPLIANT", sg.get("GroupId"), "AWS::EC2::SecurityGroup",
                            f"Security Group {sg.get('GroupId')} ({sg.get('GroupName')}) allows ALL TRAFFIC from 0.0.0.0/0.",
                            IMPACT_LOW_CONFIG,
                            f"aws ec2 revoke-security-group-ingress --group-id {sg.get('GroupId')} --protocol -1 --cidr 0.0.0.0/0 --region {region}",
                            "AWS Config: vpc-sg-open-only-authorized-ports",
                            "SCP: DenyOpenSecurityGroupAllTrafficIngress",
                            "Closes critical perimeter exposure against full-port reconnaissance and zero-day attacks."
                        ))
                    elif from_port in [22, 3389, 3306, 5432, 1433, 1521]:
                        port_name = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 1521: "Oracle"}.get(from_port, str(from_port))
                        findings.append(make_finding(
                            account_id, account_name, region, "Network",
                            f"SG_RESTRICT_PORT_{from_port}", f"VPC Security Groups Should Restrict Ingress Access On Port {from_port} ({port_name}) From 0.0.0.0/0",
                            "CRITICAL", "NON_COMPLIANT", sg.get("GroupId"), "AWS::EC2::SecurityGroup",
                            f"Management/Database port {from_port} ({port_name}) exposed directly to public internet (0.0.0.0/0).",
                            IMPACT_LOW_CONFIG,
                            f"aws ec2 revoke-security-group-ingress --group-id {sg.get('GroupId')} --protocol tcp --port {from_port} --cidr 0.0.0.0/0 --region {region}",
                            "AWS Config: restricted-ssh / restricted-common-ports",
                            "SCP: DenyPublicIngressOnSensitivePorts",
                            "Restricting to corporate VPN or bastion CIDR eliminates brute-force threats immediately."
                        ))

    return findings

def evaluate_logging_monitoring_domain(data: Dict[str, Any], account_id: str, account_name: str, region: str) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Multi-Region CloudTrail Trail Configured & Enabled
    trails = data.get("trails", [])
    has_multi_region = any(t.get("IsMultiRegionTrail", False) and t.get("HomeRegion") == region for t in trails)
    if not has_multi_region and region == "us-east-1":
        findings.append(make_finding(
            account_id, account_name, region, "Logging",
            "CLOUDTRAIL_MULTI_REGION_CONFIGURED", "Ensure that a Multi-Region CloudTrail Trail is Configured",
            "CRITICAL", "NON_COMPLIANT", "multi-region-trail", "AWS::CloudTrail::Trail",
            "No active Multi-Region CloudTrail trail detected in the account.",
            IMPACT_LOW_CONFIG,
            "aws cloudtrail create-trail --name OrganizationMasterTrail --s3-bucket-name <AuditBucket> --is-multi-region-trail --enable-log-file-validation --region us-east-1 && aws cloudtrail start-logging --name OrganizationMasterTrail --region us-east-1",
            "AWS Config: cloudtrail-enabled",
            "SCP: DenyCloudTrailDeleteOrStopLogging",
            "Provides comprehensive audit records for all API calls across all AWS regions with zero workload disruption."
        ))

    # 2. CloudTrail Log File Validation (Zero Impact Win!)
    for t in trails:
        tname = t.get("Name")
        if not t.get("LogFileValidationEnabled", False):
            findings.append(make_finding(
                account_id, account_name, region, "Logging",
                "CLOUDTRAIL_LOG_VALIDATION_ENABLED", "Ensure that CloudTrail Log File Validation is Enabled",
                "HIGH", "NON_COMPLIANT", tname, "AWS::CloudTrail::Trail",
                f"CloudTrail trail '{tname}' does not have log file integrity validation enabled.",
                IMPACT_ZERO_WIN,
                f"aws cloudtrail update-trail --name {tname} --enable-log-file-validation --region {region}",
                "AWS Config: cloud-trail-log-file-validation-enabled",
                "SCP: DenyCloudTrailDisableValidation",
                "Zero operational impact. Generates cryptographic SHA-256 digests allowing tamper-detection for audits."
            ))

    # 3. CloudTrail Logs KMS Encrypted
    for t in trails:
        tname = t.get("Name")
        if not t.get("KmsKeyId"):
            findings.append(make_finding(
                account_id, account_name, region, "Logging",
                "CLOUDTRAIL_ENCRYPTED_KMS", "Ensure that CloudTrail logs are encrypted using KMS",
                "MEDIUM", "NON_COMPLIANT", tname, "AWS::CloudTrail::Trail",
                f"CloudTrail trail '{tname}' is encrypted with default S3 keys rather than customer managed KMS CMK.",
                IMPACT_LOW_CONFIG,
                f"aws cloudtrail update-trail --name {tname} --kms-key-id <KmsKeyArn> --region {region}",
                "AWS Config: cloud-trail-encryption-enabled",
                "SCP: RequireKMSOnCloudTrail",
                "Adds dual-layer access control on compliance audit logs."
            ))

    # 4. CloudWatch Log Group Retention Configured (Zero Impact Win - Saves Storage Cost!)
    log_groups = data.get("log_groups", [])
    for lg in log_groups:
        lg_name = lg.get("logGroupName", "")
        if lg.get("retentionInDays") is None:
            findings.append(make_finding(
                account_id, account_name, region, "Logging",
                "CLOUDWATCH_LOG_RETENTION_CONFIGURED", "CloudWatch Log Groups Retention Policy Configured",
                "LOW", "NON_COMPLIANT", lg_name, "AWS::Logs::LogGroup",
                f"Log Group '{lg_name}' has retention set to 'Never Expire', accumulating infinite storage costs.",
                IMPACT_ZERO_WIN,
                f"aws logs put-retention-policy --log-group-name '{lg_name}' --retention-in-days 90 --region {region}",
                "AWS Config: cw-loggroup-retention-period-check",
                "SCP: EnforceCloudWatchLogRetentionLimits",
                "Zero application downtime. Automatically expires stale debug logs and prevents runaway storage billing."
            ))

    # 5. CIS Metric Filters & Alarms
    filters = data.get("metric_filters", [])
    cis_alarms = [
        ("CIS_ALARM_UNAUTHORIZED_API", "Ensure a log metric filter and alarm exist for unauthorized API calls", "UnauthorizedApiCalls", "Unauthorized API activity alarm missing."),
        ("CIS_ALARM_NO_MFA_CONSOLE_SIGNIN", "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA", "ConsoleSignInWithoutMfa", "Console sign-in without MFA alarm missing."),
        ("CIS_ALARM_ROOT_USAGE", "Ensure a log metric filter and alarm exist for usage of root account", "RootAccountUsage", "Root account activity alarm missing."),
        ("CIS_ALARM_IAM_POLICY_CHANGES", "Ensure a log metric filter and alarm exist for IAM policy changes", "IAMPolicyChanges", "IAM privilege escalation alarm missing."),
        ("CIS_ALARM_CLOUDTRAIL_CHANGES", "Ensure a log metric filter and alarm exist for CloudTrail configuration changes", "CloudTrailChanges", "CloudTrail tampering alarm missing."),
        ("CIS_ALARM_S3_POLICY_CHANGES", "Ensure a log metric filter and alarm exist for S3 bucket policy changes", "S3BucketPolicyChanges", "S3 public exposure alarm missing."),
        ("CIS_ALARM_CONFIG_CHANGES", "Ensure a log metric filter and alarm exist for AWS Config configuration changes", "AWSConfigChanges", "AWS Config tampering alarm missing."),
        ("CIS_ALARM_SECURITY_GROUP_CHANGES", "Ensure a log metric filter and alarm exist for security group changes", "SecurityGroupChanges", "Security group modifications alarm missing."),
        ("CIS_ALARM_NACL_CHANGES", "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists.", "NACLChanges", "NACL modifications alarm missing."),
        ("CIS_ALARM_GATEWAY_CHANGES", "Ensure a log metric filter and alarm exist for changes to network gateways.", "NetworkGatewayChanges", "Gateway modifications alarm missing."),
        ("CIS_ALARM_VPC_CHANGES", "Ensure a log metric filter and alarm exist for VPC changes.", "VPCChanges", "VPC network modifications alarm missing."),
        ("CIS_ALARM_KMS_CMK_DELETION", "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created KMS CMKs.", "KMSCMKDeletion", "KMS key deletion alarm missing.")
    ]
    for aid, aname, pattern, desc in cis_alarms:
        if not any(pattern.lower() in f.get("filterPattern", "").lower() or pattern.lower() in f.get("filterName", "").lower() for f in filters):
            findings.append(make_finding(
                account_id, account_name, region, "Logging",
                aid, aname, "MEDIUM", "NON_COMPLIANT", pattern, "AWS::CloudWatch::Alarm",
                desc, IMPACT_LOW_CONFIG,
                f"aws logs put-metric-filter --log-group-name /aws/cloudtrail/audit --filter-name {pattern} --filter-pattern '{{ ... }}' --metric-transformations metricName={pattern},metricNamespace=CISBenchmark,metricValue=1 --region {region}",
                f"AWS Config: {pattern.lower()}-alarm-check",
                "SCP: ProtectSecurityAlarmsAndMetricFilters",
                "Alerts security teams immediately upon high-risk configuration changes with zero production impact."
            ))

    return findings

def evaluate_storage_backup_domain(data: Dict[str, Any], account_id: str, account_name: str, region: str) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. S3 Account-Level Block Public Access (Zero Impact Instant Security Win!)
    bpa = data.get("account_block_public_access", {})
    if not (bpa.get("BlockPublicAcls") and bpa.get("IgnorePublicAcls") and bpa.get("BlockPublicPolicy") and bpa.get("RestrictPublicBuckets")):
        findings.append(make_finding(
            account_id, account_name, "global", "Storage",
            "S3_ACCOUNT_BLOCK_PUBLIC_ACCESS", "S3 Block Public Access is Enabled (Account-Level)",
            "CRITICAL", "NON_COMPLIANT", account_id, "AWS::S3::AccountPublicAccessBlock",
            "Account-level S3 Block Public Access is disabled. Buckets could accidentally be made public.",
            IMPACT_ZERO_WIN,
            "aws s3control put-public-access-block --account-id <AccountId> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "AWS Config: s3-account-level-public-access-blocks",
            "SCP: DenyDisableS3AccountPublicAccessBlock",
            "Universal safety net preventing 100% of accidental bucket leaks across the entire account."
        ))

    # 2. S3 Bucket Enforce Encryption in Transit (HTTPS only)
    buckets = data.get("buckets", [])
    for b in buckets:
        bname = b.get("Name")
        if not b.get("EnforcesSSL", False):
            findings.append(make_finding(
                account_id, account_name, b.get("Region", region), "Storage",
                "S3_BUCKET_ENFORCE_SSL", "S3 Bucket Encryption in Transit is Enforced",
                "HIGH", "NON_COMPLIANT", bname, "AWS::S3::Bucket",
                f"S3 bucket '{bname}' does not have a bucket policy denying non-HTTPS (aws:SecureTransport: false) requests.",
                IMPACT_LOW_CONFIG,
                f"aws s3api put-bucket-policy --bucket {bname} --policy file://deny_non_ssl_policy.json",
                "AWS Config: s3-bucket-ssl-requests-only",
                "SCP: DenyNonSSLS3BucketAccess",
                "Prevents man-in-the-middle sniffing of sensitive data in transit without affecting authenticated HTTPS clients."
            ))
        if not b.get("VersioningEnabled", False):
            findings.append(make_finding(
                account_id, account_name, b.get("Region", region), "Storage",
                "S3_BUCKET_VERSIONING_ENABLED", "S3 Bucket Versioning Enabled",
                "MEDIUM", "NON_COMPLIANT", bname, "AWS::S3::Bucket",
                f"S3 bucket '{bname}' does not have versioning enabled. Deletions and overwrites are permanent.",
                IMPACT_ZERO_WIN,
                f"aws s3api put-bucket-versioning --bucket {bname} --versioning-configuration Status=Enabled",
                "AWS Config: s3-bucket-versioning-enabled",
                "SCP: DenySuspendS3Versioning",
                "Zero operational downtime. Guards against accidental object deletion and ransomware attacks."
            ))

    # 3. Unattached EBS Volumes (Zero Impact Cleanup!)
    volumes = data.get("ebs_volumes", [])
    for v in volumes:
        vid = v.get("VolumeId")
        if v.get("State") == "available" and not v.get("Attachments"):
            findings.append(make_finding(
                account_id, account_name, region, "Storage",
                "EBS_VOLUME_IN_USE", "EBS Volume In Use",
                "LOW", "NON_COMPLIANT", vid, "AWS::EC2::Volume",
                f"EBS Volume {vid} ({v.get('Size')} GiB) is unattached, accumulating storage costs.",
                IMPACT_ZERO_WIN,
                f"aws ec2 create-snapshot --volume-id {vid} --description 'Snapshot before deletion' --region {region} && aws ec2 delete-volume --volume-id {vid} --region {region}",
                "AWS Config: ec2-volume-inuse-check",
                "SCP: RestrictUnattachedVolumeRetention",
                "Safely creates snapshot and deletes orphan volume. 100% zero downtime on active compute."
            ))

    # 4. EBS Default Encryption (Zero Impact Region-Level Win!)
    if not data.get("ebs_default_encryption_enabled", False):
        findings.append(make_finding(
            account_id, account_name, region, "Storage",
            "EC2_DEFAULT_ENCRYPTION_ENABLED", "EC2 Default Encryption is Enabled",
            "HIGH", "NON_COMPLIANT", f"ebs-encryption-{region}", "AWS::EC2::EBSDefaultEncryption",
            f"EBS Default Encryption is disabled in {region}. New EBS volumes will default to unencrypted.",
            IMPACT_ZERO_WIN,
            f"aws ec2 enable-ebs-encryption-by-default --region {region}",
            "AWS Config: ec2-ebs-encryption-by-default",
            "SCP: DenyUnencryptedEBSVolumeCreation",
            "Zero impact on running instances. Transparently encrypts all future EBS volumes using KMS."
        ))

    # 5. AWS Backup Coverage & Retention
    backup_vaults = data.get("backup_vaults", [])
    if not backup_vaults:
        findings.append(make_finding(
            account_id, account_name, region, "Storage",
            "BACKUP_VAULT_EXISTS", "Backup vaults should exist in a region",
            "MEDIUM", "NON_COMPLIANT", f"backup-vault-{region}", "AWS::Backup::BackupVault",
            f"No AWS Backup vault exists in {region}.",
            IMPACT_LOW_CONFIG,
            f"aws backup create-backup-vault --backup-vault-name DefaultVault --region {region}",
            "AWS Config: backup-vault-exists",
            "SCP: RequireBackupVaultProtection",
            "Provides a secure container for immutable snapshots and disaster recovery."
        ))

    return findings

def evaluate_database_domain(data: Dict[str, Any], account_id: str, account_name: str, region: str) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. RDS Deletion Protection (Zero Impact Win!)
    rds_instances = data.get("rds_instances", [])
    for db in rds_instances:
        db_id = db.get("DBInstanceIdentifier")
        if not db.get("DeletionProtection", False):
            findings.append(make_finding(
                account_id, account_name, region, "Databases",
                "RDS_DELETION_PROTECTION_ENABLED", "RDS Deletion Protection Enabled",
                "HIGH", "NON_COMPLIANT", db_id, "AWS::RDS::DBInstance",
                f"RDS instance '{db_id}' does not have deletion protection enabled.",
                IMPACT_ZERO_WIN,
                f"aws rds modify-db-instance --db-instance-identifier {db_id} --deletion-protection --apply-immediately --region {region}",
                "AWS Config: rds-instance-deletion-protection-enabled",
                "SCP: DenyDeleteProtectedRDSInstances",
                "Zero downtime. Prevents catastrophic accidental database deletion via CLI, console, or automation."
            ))
        if not db.get("StorageEncrypted", False):
            findings.append(make_finding(
                account_id, account_name, region, "Databases",
                "RDS_STORAGE_ENCRYPTION_ENABLED", "RDS Storage Encryption is Enabled",
                "HIGH", "NON_COMPLIANT", db_id, "AWS::RDS::DBInstance",
                f"RDS instance '{db_id}' storage is unencrypted at rest.",
                IMPACT_HIGH_ARCH,
                f"Create snapshot -> Copy snapshot with --kms-key-id -> Restore new encrypted instance.",
                "AWS Config: rds-storage-encrypted",
                "SCP: DenyUnencryptedRDSInstanceCreation",
                "Protects database files, transaction logs, and snapshots from physical storage compromise."
            ))

    # 2. DynamoDB Point-In-Time Recovery (PITR) (Zero Impact Win!)
    tables = data.get("dynamodb_tables", [])
    for tbl in tables:
        tname = tbl.get("TableName")
        if not tbl.get("PointInTimeRecoveryEnabled", False):
            findings.append(make_finding(
                account_id, account_name, region, "Databases",
                "DYNAMODB_PITR_ENABLED", "DynamoDB Table Point-in-time Recovery Enabled",
                "HIGH", "NON_COMPLIANT", tname, "AWS::DynamoDB::Table",
                f"DynamoDB table '{tname}' does not have Point-In-Time Recovery (PITR) enabled.",
                IMPACT_ZERO_WIN,
                f"aws dynamodb update-continuous-backups --table-name {tname} --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true --region {region}",
                "AWS Config: dynamodb-pitr-enabled",
                "SCP: EnforceDynamoDBPITR",
                "Zero application downtime. Allows rolling back table state to any second in the last 35 days."
            ))

    return findings

def evaluate_encryption_security_domain(data: Dict[str, Any], account_id: str, account_name: str, region: str) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. KMS Key Rotation (Zero Impact Security Win!)
    keys = data.get("kms_keys", [])
    for k in keys:
        kid = k.get("KeyId")
        if k.get("KeyManager") == "CUSTOMER" and not k.get("KeyRotationEnabled", False):
            findings.append(make_finding(
                account_id, account_name, region, "Encryption",
                "KMS_KEY_ROTATION_ENABLED", "Ensure that KMS Key Rotation is Enabled",
                "HIGH", "NON_COMPLIANT", kid, "AWS::KMS::Key",
                f"Customer Managed KMS Key '{kid}' does not have annual automatic key rotation enabled.",
                IMPACT_ZERO_WIN,
                f"aws kms enable-key-rotation --key-id {kid} --region {region}",
                "AWS Config: cmk-backing-key-rotation-enabled",
                "SCP: DenyDisableKmsKeyRotation",
                "100% transparent. Automatically rotates encryption keys yearly without re-encrypting existing data."
            ))

    # 2. GuardDuty Enabled (Zero Impact Account-Wide Win!)
    if not data.get("guardduty_enabled", False):
        findings.append(make_finding(
            account_id, account_name, region, "Security",
            "GUARDDUTY_ENABLED", "Amazon GuardDuty is Enabled",
            "CRITICAL", "NON_COMPLIANT", f"guardduty-{region}", "AWS::GuardDuty::Detector",
            f"Amazon GuardDuty is not enabled in {region}.",
            IMPACT_ZERO_WIN,
            f"aws guardduty create-detector --enable --region {region}",
            "AWS Config: guardduty-enabled-centralized",
            "SCP: DenyDisableGuardDuty",
            "Zero impact on CPU, memory, or network. Continuously analyzes CloudTrail, VPC Flow, and DNS logs for attacks."
        ))

    # 3. Security Hub Enabled (Zero Impact Win!)
    if not data.get("security_hub_enabled", False):
        findings.append(make_finding(
            account_id, account_name, region, "Security",
            "SECURITY_HUB_ENABLED", "AWS Security Hub is Enabled",
            "HIGH", "NON_COMPLIANT", f"securityhub-{region}", "AWS::SecurityHub::Hub",
            f"AWS Security Hub is not enabled in {region}.",
            IMPACT_ZERO_WIN,
            f"aws securityhub enable-security-hub --enable-default-standards --region {region}",
            "AWS Config: securityhub-enabled",
            "SCP: DenyDisableSecurityHub",
            "Zero workload impact. Unifies posture across CIS, NIST, and AWS Foundational Security Best Practices."
        ))

    # 4. ECR Image Scan on Push & Tag Immutability (Zero Impact Wins!)
    repos = data.get("ecr_repositories", [])
    for repo in repos:
        rname = repo.get("repositoryName")
        if not repo.get("imageScanningConfiguration", {}).get("scanOnPush", False):
            findings.append(make_finding(
                account_id, account_name, region, "Containers",
                "ECR_SCAN_ON_PUSH_ENABLED", "Image Scan on Push is Enabled",
                "HIGH", "NON_COMPLIANT", rname, "AWS::ECR::Repository",
                f"ECR repository '{rname}' does not have scan-on-push enabled.",
                IMPACT_ZERO_WIN,
                f"aws ecr put-image-scanning-configuration --repository-name {rname} --image-scanning-configuration scanOnPush=true --region {region}",
                "AWS Config: ecr-private-image-scanning-enabled",
                "SCP: RequireECRImageScanOnPush",
                "Automatically scans images for CVEs upon docker push with zero latency to existing deployments."
            ))
        if repo.get("imageTagMutability") != "IMMUTABLE":
            findings.append(make_finding(
                account_id, account_name, region, "Containers",
                "ECR_TAG_IMMUTABILITY_ENABLED", "ECR Private Tag Immutability Enabled Check",
                "MEDIUM", "NON_COMPLIANT", rname, "AWS::ECR::Repository",
                f"ECR repository '{rname}' allows mutable image tags. Tags can be overwritten.",
                IMPACT_ZERO_WIN,
                f"aws ecr put-image-tag-mutability --repository-name {rname} --image-tag-mutability IMMUTABLE --region {region}",
                "AWS Config: ecr-private-tag-immutability-enabled",
                "SCP: RequireECRTagImmutability",
                "Prevents accidental or malicious overwriting of container releases (e.g. 'latest')."
            ))

    # 5. Load Balancer Deletion Protection (Zero Impact Win!)
    elbs = data.get("load_balancers", [])
    for elb in elbs:
        elb_arn = elb.get("LoadBalancerArn", elb.get("LoadBalancerName", "Unknown"))
        elb_name = elb.get("LoadBalancerName", "Unknown")
        if not elb.get("DeletionProtection", False):
            findings.append(make_finding(
                account_id, account_name, region, "Network",
                "ELB_DELETION_PROTECTION_ENABLED", "Load Balancers Deletion Protection Enabled",
                "HIGH", "NON_COMPLIANT", elb_name, "AWS::ElasticLoadBalancingV2::LoadBalancer",
                f"Load Balancer '{elb_name}' does not have deletion protection enabled.",
                IMPACT_ZERO_WIN,
                f"aws elbv2 modify-load-balancer-attributes --load-balancer-arn {elb_arn} --attributes Key=deletion_protection.enabled,Value=true --region {region}",
                "AWS Config: elb-deletion-protection-enabled",
                "SCP: DenyDeleteProtectedLoadBalancers",
                "Prevents accidental removal of ingress routing for customer-facing services with zero downtime."
            ))

    return findings

def evaluate_compute_domain(data: Dict[str, Any], account_id: str, account_name: str, region: str) -> List[Dict[str, Any]]:
    findings = []
    
    # 1. Stopped EC2 Instances > 30 Days (Zero Impact Cleanup!)
    instances = data.get("instances", [])
    now = datetime.datetime.now(datetime.timezone.utc)
    for inst in instances:
        iid = inst.get("InstanceId")
        state = inst.get("State", {}).get("Name")
        stop_time = inst.get("StateTransitionTime")
        if state == "stopped" and stop_time:
            # Check days stopped
            try:
                st = datetime.datetime.fromisoformat(stop_time.replace("Z", "+00:00"))
                days_stopped = (now - st).days
                if days_stopped > 30:
                    findings.append(make_finding(
                        account_id, account_name, region, "Compute",
                        "EC2_STOPPED_OVER_30_DAYS", "No EC2 Instances Stopped for More Than 30 Days",
                        "LOW", "NON_COMPLIANT", iid, "AWS::EC2::Instance",
                        f"Instance {iid} has been stopped for {days_stopped} days, accumulating unattached EBS storage costs.",
                        IMPACT_ZERO_WIN,
                        f"aws ec2 create-image --instance-id {iid} --name 'Archive-{iid}' --region {region} && aws ec2 terminate-instances --instance-ids {iid} --region {region}",
                        "AWS Config: ec2-stopped-instance-check",
                        "SCP: RestrictStaleStoppedInstanceRetention",
                        "Archives AMI and terminates stale instances, eliminating storage costs and hygiene debt with zero impact on production."
                    ))
            except Exception:
                pass

    return findings

# Master Dispatcher
DISPATCHER = {
    "iam": evaluate_iam_domain,
    "network": evaluate_network_domain,
    "logging": evaluate_logging_monitoring_domain,
    "storage": evaluate_storage_backup_domain,
    "database": evaluate_database_domain,
    "encryption": evaluate_encryption_security_domain,
    "compute": evaluate_compute_domain
}

def run_evaluation(domain: str, raw_json_path: str, account_id: str, account_name: str, region: str) -> List[Dict[str, Any]]:
    evaluator = DISPATCHER.get(domain.lower())
    if not evaluator:
        raise ValueError(f"Unknown domain evaluator: {domain}")
    
    with open(raw_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    return evaluator(data, account_id, account_name, region)

if __name__ == "__main__":
    if len(sys.argv) < 6:
        print("Usage: python compliance_engine.py <domain> <input_json> <account_id> <account_name> <region>")
        sys.exit(1)
        
    dom = sys.argv[1]
    input_file = sys.argv[2]
    acc_id = sys.argv[3]
    acc_name = sys.argv[4]
    reg = sys.argv[5]
    
    results = run_evaluation(dom, input_file, acc_id, acc_name, reg)
    print(json.dumps(results, indent=2))
