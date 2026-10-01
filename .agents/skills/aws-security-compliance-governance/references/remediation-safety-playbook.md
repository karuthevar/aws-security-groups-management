# Safe Remediation & Rollback Architecture Playbook

## 1. Zero-Surprise Remediation Standard

Any remediation script developed under this governance framework must adhere to the **Zero-Surprise Principle**:

1. **Default Mode Must Be Non-Destructive**: Executing a script with no arguments (e.g. `./cleanup_security_groups.sh` or `./disable_tgw_auto_accept.sh`) must run in `--dry-run` mode.
2. **Explicit Intent Required**: The `--execute` flag is strictly required to modify any AWS infrastructure.
3. **Interactive Confirmation**: When running in `--execute` mode interactively, the user must explicitly type `CONFIRM` before any AWS modification API call is triggered.
4. **Automation Flag**: Automated CI/CD pipelines can bypass the interactive confirmation prompt using `-y` or `--yes`.

---

## 2. Complete State Backup Before Mutation

Before revoking a security group rule, deleting an unattached security group, or modifying a resource:
1. **Full API State Snapshot**: Capture the complete JSON description of the resource, including inbound rules, outbound rules, associations, tags, and VPC metadata.
2. **Account & Region Isolation**: Store individual backup files in an account/region directory hierarchy:
   ```text
   backups/<TIMESTAMP>/<ACCOUNT_ID>_<ACCOUNT_NAME>/<REGION>/<RESOURCE_ID>_<NAME>.json
   ```
3. **Master Manifest**: Generate a `backup_manifest.json` file in the backup directory listing all modified resources, original states, and actions taken.

---

## 3. Automated Restoration & Rollback

Every remediation tool that performs destructive actions (such as deletion or rule stripping) must have a companion restoration script (e.g. `restore_security_groups.sh`).

### Restoration Workflow:
1. Reads `backup_manifest.json` or individual resource JSON snapshots.
2. Assumes the appropriate cross-account role in the target account.
3. Recreates the deleted resources in the original VPC with identical names and tags.
4. Re-authorizes all original inbound and outbound rules with exact CIDRs, security group references, and port ranges.
5. Emits a restoration summary log with exit code 0.

---

## 4. Git & Data Sanitization Rules

**CRITICAL SECURITY RULE**: Infrastructure backups and audit reports contain internal network topologies, account IDs, VPC IDs, CIDR ranges, and active security vulnerabilities. They must **never** be committed to Git.

### Mandatory `.gitignore` Directives:
```gitignore
# Reports and Output data (NEVER commit to git)
reports/
reports/**
audit_results/
audit_results/**
*.html
*.json
!test/mock_*.json
!controls/**/*.json
!templates/*.html
test/test_*

# Backups (contain actual infrastructure SG JSON snapshots - NEVER commit to git)
backups/
backups/**
*.bak
```
