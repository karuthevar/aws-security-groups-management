# Operational Impact & Complexity Classification Matrix

## 1. Core Principle: Zero Timelines
**STRICT RULE**: Under no circumstances should audit reports, remediation roadmaps, leadership dashboards, or executive presentations include calendar dates, deadlines, day/week estimates, or arbitrary completion timeframes.

Leadership requires decisions based purely on **Operational Impact**, **Downtime Risk**, **Implementation Complexity**, and **Risk Concentration**.

---

## 2. Operational Impact & Downtime Risk Tiers

Every finding and rule evaluated across the AWS estate must be mapped to one of three standardized impact tiers:

### Tier 1: `ZERO_IMPACT_QUICK_WIN`
* **Definition**: Remediations that carry **100% Zero Workload Downtime** and **Zero Traffic Disruption**.
* **Operational Effect**: The modification acts solely as a future guardrail or cleans up orphaned resources without altering active routing, existing network connections, compute runtimes, or database sessions.
* **Approval Requirement**: Pre-approved standard change / autonomous remediation.
* **Canonical Examples**:
  * **Transit Gateway Auto Cross-Account Attachment**: Changing `AutoAcceptSharedAttachments=enable` to `disable`. Existing attachments and active routing remain completely untouched; only prevents future unauthorized VPC attachments.
  * **S3 Account-Level Block Public Access**: Enables account-level public blocks. Internal cross-account and IAM-authenticated S3 traffic is 100% unaffected.
  * **CloudTrail Log File Validation**: Enables cryptographic hashing on log digests. Zero impact on logging ingestion.
  * **CloudWatch Alarm Actions**: Attaches SNS notification topics to existing metric filters. Zero workload disruption.
  * **Unattached Security Group Deletion**: Deletes security groups with zero network interfaces (`active ENIs == 0`).
  * **Unallocated Elastic IP Release**: Releases unattached EIPs incurring hourly charges.
  * **EBS Volume Encryption by Default**: Mandates encryption for *future* EBS volumes. Existing active volumes continue unaffected.

### Tier 2: `LOW_IMPACT_REVIEW`
* **Definition**: Configuration changes that do not cause outages but require lightweight verification of organizational policy or administrative workflows before toggling.
* **Operational Effect**: Internal AWS management plane adjustments that do not impact end-user application traffic.
* **Approval Requirement**: Fast-track peer review / lightweight change ticket.
* **Canonical Examples**:
  * **IAM Password Policy**: Increasing length and complexity requirements. Only affects future password rotations for console IAM users.
  * **Default Security Group Ingress Restriction**: Revoking inbound rules on default VPC security groups. (Best practice: no workloads should ever be assigned to default SGs).
  * **RDS Deletion Protection**: Enabling termination protection flag on databases. Prevents accidental deletion without modifying database engine or connections.
  * **DynamoDB Point-in-Time Recovery (PITR)**: Enabling continuous backups. Zero read/write latency impact.
  * **Root Account MFA Enforcement**: Enforcing virtual or hardware MFA on the root user.

### Tier 3: `HIGH_RISK_PLANNED_WINDOW`
* **Definition**: High-friction changes that alter active network ingress/egress rules, TLS configurations, or storage access policies where active production traffic flows.
* **Operational Effect**: Risk of dropped connections or authentication failures if dependent legacy services are not accounted for.
* **Approval Requirement**: Scheduled maintenance window, architecture review, and staged rollback plan.
* **Canonical Examples**:
  * **In-Use Security Group Rule Revocation**: Restricting port 22 (SSH) or 3389 (RDP) on security groups currently attached to live EC2 instances or ENIs.
  * **VPC Network Access Control List (NACL) Ingress Denials**: Applying broad subnet-level subnet boundary blocks.
  * **KMS CMK Key Rotation / Policy Changes**: Modifying customer managed key policies on live encryption keys.
  * **S3 Bucket Policy Enforce TLS (`aws:SecureTransport`)**: Rejecting plaintext HTTP calls where legacy SDK clients may still exist.

---

## 3. Implementation Complexity Dimensions

| Level | Technical Effort | Automation Capability | Dependency Scope |
| :--- | :--- | :--- | :--- |
| **Low** | Single AWS CLI command or API call (e.g. `aws ec2 modify-transit-gateway`) | 100% automated via script or AWS Config remediation | Self-contained resource |
| **Medium** | Multi-step configuration (e.g. creating CloudWatch log group + metric filter + alarm + SNS topic) | Scripted template execution | Resource + CloudWatch + IAM role |
| **High** | Requires client-side coordination, VPC peering adjustment, or client migration | Phased canary deployment | Distributed applications & clients |

---

## 4. Account Risk Concentration & ROI Prioritization

When presenting multi-account findings to leadership, prioritize accounts using the **Maximum Improvement Index (ROI)**:

$$\text{Remediation ROI} = \frac{\text{Critical Findings} \times 3 + \text{High Findings} \times 2 + \text{Zero-Impact Quick Wins} \times 1.5}{\text{Operational Complexity Score}}$$

### Prioritization Rules:
1. **Target Highest Finding Concentration First**: If 80% of open security findings are concentrated in 2 out of 10 member accounts, prioritize those 2 accounts first to capture 80% security posture uplift.
2. **Execute Zero-Impact Quick Wins in Bulk**: Group all Tier 1 remediations across all accounts into a single automated run. This dramatically boosts compliance percentage instantly with zero operational pushback.
3. **Stage High-Risk Items Independently**: High-risk items must never block low-risk or zero-impact remediations.
