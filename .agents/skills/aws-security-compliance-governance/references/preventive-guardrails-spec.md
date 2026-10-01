# Preventive Guardrails & Continuous Compliance Specification

## 1. The Triple-Layer Defense Model

Every security control evaluated in the enterprise must be backed by a three-tiered architecture:

```text
Layer 1: Organization SCPs (Preventative Boundary)
   │  └── Blocks non-compliant API actions across all member accounts at the IAM evaluation root.
   ▼
Layer 2: AWS Config Rules / Conformance Packs (Detective & Continuous Drift)
   │  └── Continuously records resource configuration changes, evaluates compliance, and flags drift.
   ▼
Layer 3: Scripted Remediation Engine (Corrective & Safe Recovery)
      └── Scans, provides dry-run previews, generates full state backups, and fixes non-compliant assets.
```

---

## 2. AWS Config Conformance Pack Standards

All continuous audit rules must be codified into a single deployable AWS CloudFormation Conformance Pack template (`conformance_pack_security_baseline.yaml`).

### Deployment Across Entire AWS Organization:
```bash
aws configservice put-organization-conformance-pack \
    --organization-conformance-pack-name OrgSecurityBaseline \
    --template-body file://conformance_pack_security_baseline.yaml
```

### Key Core Rule Definitions:
* **Transit Gateway**: `TRANSIT_GATEWAY_AUTO_APPROVAL_CHECK`
* **VPC Flow Logs**: `VPC_FLOW_LOGS_ENABLED`
* **Default Security Group**: `VPC_DEFAULT_SECURITY_GROUP_CLOSED`
* **SSH & Database Ports**: `INCOMING_SSH_DISABLED`, `RESTRICTED_INCOMING_TRAFFIC`
* **Elastic IPs**: `EIP_ATTACHED`
* **CloudTrail & Logging**: `CLOUD_TRAIL_ENABLED`, `CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED`, `CLOUD_TRAIL_ENCRYPTION_ENABLED`
* **S3 Storage**: `S3_ACCOUNT_LEVEL_PUBLIC_ACCESS_BLOCKS`, `S3_BUCKET_SSL_REQUESTS_ONLY`
* **Databases**: `RDS_DELETION_PROTECTION_ENABLED`, `DYNAMODB_PITR_ENABLED`
* **IAM**: `IAM_PASSWORD_POLICY`, `ROOT_ACCOUNT_MFA_ENABLED`

---

## 3. Service Control Policy (SCP) Guardrail Standards

SCPs prevent configuration drift before it happens by denying unauthorized modifications, even by account root users in member accounts.

### Mandatory SCP Rules:
1. **Deny Modification of Transit Gateway Auto-Accept**:
   ```json
   {
     "Sid": "DenyUnapprovedTransitGatewayModification",
     "Effect": "Deny",
     "Action": [
       "ec2:ModifyTransitGateway",
       "ec2:CreateTransitGateway"
     ],
     "Resource": "*",
     "Condition": {
       "ArnNotLike": {
         "aws:PrincipalArn": [
           "arn:aws:iam::*:role/OrganizationAccountAccessRole",
           "arn:aws:iam::*:role/AWSControlTowerExecution",
           "arn:aws:iam::*:role/*NetworkAdmin*"
         ]
       }
     }
   }
   ```

2. **Deny Disabling CloudTrail & Deleting Logs**:
   ```json
   {
     "Sid": "DenyCloudTrailDisabling",
     "Effect": "Deny",
     "Action": [
       "cloudtrail:StopLogging",
       "cloudtrail:DeleteTrail",
       "cloudtrail:UpdateTrail"
     ],
     "Resource": "*",
     "Condition": {
       "ArnNotLike": {
         "aws:PrincipalArn": [
           "arn:aws:iam::*:role/OrganizationAccountAccessRole",
           "arn:aws:iam::*:role/AWSControlTowerExecution"
         ]
       }
     }
   }
   ```

3. **Deny Disabling S3 Account Block Public Access**:
   ```json
   {
     "Sid": "DenyDisableS3BlockPublicAccess",
     "Effect": "Deny",
     "Action": [
       "s3:DeleteAccountPublicAccessBlock",
       "s3:PutAccountPublicAccessBlock"
     ],
     "Resource": "*",
     "Condition": {
       "ArnNotLike": {
         "aws:PrincipalArn": [
           "arn:aws:iam::*:role/OrganizationAccountAccessRole",
           "arn:aws:iam::*:role/AWSControlTowerExecution"
         ]
       }
     }
   }
   ```

---

## 4. Log Metric Filters & CloudWatch Alarms

For critical network modifications (such as changes to Network Access Control Lists, Security Groups, or Internet Gateways), configure automated detection:

1. **NACL Changes Filter Pattern**:
   ```text
   { ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }
   ```
2. **Security Group Changes Filter Pattern**:
   ```text
   { ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }
   ```
3. **Alarm Action**: Alarm must trigger SNS topic connected to the SecOps alerting pipeline.
