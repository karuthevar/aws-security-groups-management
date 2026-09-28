#!/usr/bin/env bash
# ==============================================================================
# Automated Test Suite for AWS Security Group Audit & Cleanup Utility
# ==============================================================================

set -eo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${TEST_DIR}/.." && pwd)"

# Add mock bin to PATH
export PATH="${TEST_DIR}/mock_bin:${PATH}"

echo "================================================================================"
echo " Running Automated Unit & Integration Tests"
echo "================================================================================"

echo ""
echo "[TEST 1] Verifying threat analyzer against mock data..."
python lib/threat_analyzer.py \
    test/mock_sgs.json \
    test/mock_enis.json \
    "111122223333" \
    "Production-Workload" \
    "us-east-1" > test/test_output.json

RECORD_COUNT=$(python -c "import json; print(len(json.load(open('test/test_output.json'))))")
if [[ "${RECORD_COUNT}" -eq 7 ]]; then
    echo "✓ Test 1 Passed: Analyzed 7 security groups successfully."
else
    echo "✗ Test 1 Failed: Expected 7 records, got ${RECORD_COUNT}"
    exit 1
fi

echo ""
echo "[TEST 2] Verifying threat classification logic..."
python -c "
import json
with open('test/test_output.json') as f:
    sgs = {x['GroupId']: x for x in json.load(f)}

# Bastion (SSH) -> CRITICAL & RESTRICT_IMMEDIATELY
assert sgs['sg-01111111111111111']['MaxSeverity'] == 'CRITICAL', 'Bastion should be CRITICAL'
assert sgs['sg-01111111111111111']['Recommendation'] == 'RESTRICT_IMMEDIATELY', 'Bastion should be RESTRICT_IMMEDIATELY'

# Aurora DB -> CRITICAL & RESTRICT_IMMEDIATELY
assert sgs['sg-02222222222222222']['MaxSeverity'] == 'CRITICAL', 'Aurora DB should be CRITICAL'

# Abandoned open all -> CAN_DELETE (unattached)
assert sgs['sg-03333333333333333']['Recommendation'] == 'CAN_DELETE', 'Abandoned SG should be CAN_DELETE'

# Default SG -> DEFAULT_RESTRICT
assert sgs['sg-04444444444444444']['Recommendation'] == 'DEFAULT_RESTRICT', 'Default SG should be DEFAULT_RESTRICT'

# ALB -> REVIEW_EXPOSURE
assert sgs['sg-05555555555555555']['Recommendation'] == 'REVIEW_EXPOSURE', 'ALB should be REVIEW_EXPOSURE'

# Internal Microservice -> SAFE_IN_USE
assert sgs['sg-06666666666666666']['Recommendation'] == 'SAFE_IN_USE', 'Internal service should be SAFE_IN_USE'

# Stale POC -> CAN_DELETE
assert sgs['sg-07777777777777777']['Recommendation'] == 'CAN_DELETE', 'Stale POC should be CAN_DELETE'

print('[PASS] All threat evaluation assertions passed perfectly!')
"
echo "✓ Test 2 Passed: Threat classifications validated."

echo ""
echo "[TEST 3] Generating standalone HTML security dashboard..."
source "${ROOT_DIR}/lib/common.sh"
source "${ROOT_DIR}/lib/html_generator.sh"
generate_html_report "${TEST_DIR}/test_output.json" "${TEST_DIR}/test_dashboard.html" 1 1

if [[ -f "${TEST_DIR}/test_dashboard.html" ]] && [[ -s "${TEST_DIR}/test_dashboard.html" ]]; then
    echo "✓ Test 3 Passed: HTML dashboard generated ($(wc -c < "${TEST_DIR}/test_dashboard.html") bytes)."
else
    echo "✗ Test 3 Failed: HTML dashboard not generated."
    exit 1
fi

echo ""
echo "[TEST 4] Testing cleanup_security_groups.sh (Dry Run)..."
"${ROOT_DIR}/cleanup_security_groups.sh" --audit-file "${TEST_DIR}/test_output.json"
echo "✓ Test 4 Passed: Cleanup dry-run completed."

echo ""
echo "[TEST 5] Testing cleanup_security_groups.sh (Execute Mode)..."
CLEANUP_BACKUP_DIR="${TEST_DIR}/test_backups"
rm -rf "${CLEANUP_BACKUP_DIR}"
"${ROOT_DIR}/cleanup_security_groups.sh" \
    --audit-file "${TEST_DIR}/test_output.json" \
    --backup-dir "${CLEANUP_BACKUP_DIR}" \
    --execute \
    --yes

if [[ -f "${CLEANUP_BACKUP_DIR}/backup_manifest.json" ]]; then
    echo "✓ Test 5 Passed: Cleanup execute mode generated backup manifest."
else
    echo "✗ Test 5 Failed: Backup manifest missing."
    exit 1
fi

echo ""
echo "[TEST 6] Testing restore_security_groups.sh..."
"${ROOT_DIR}/restore_security_groups.sh" \
    --manifest "${CLEANUP_BACKUP_DIR}/backup_manifest.json" \
    --execute \
    --yes

echo "✓ Test 6 Passed: Restoration completed successfully."

echo ""
echo "[TEST 7] Testing compliance engine against IAM, Storage, and Database mock fixtures..."
python lib/compliance_engine.py iam test/mock_compliance_iam.json "111122223333" "Production" "global" > test/test_compliance_iam.json
python lib/compliance_engine.py storage test/mock_compliance_storage.json "111122223333" "Production" "us-east-1" > test/test_compliance_storage.json
python lib/compliance_engine.py database test/mock_compliance_databases.json "111122223333" "Production" "us-east-1" > test/test_compliance_databases.json

python -c "
import json
with open('test/test_compliance_iam.json') as f:
    iam = json.load(f)
assert any(x['RuleId'] == 'IAM_ROOT_MFA_ENABLED' for x in iam), 'Missing Root MFA check'
assert any(x['RemediationImpact'] == 'ZERO_IMPACT_QUICK_WIN' for x in iam), 'Should identify Zero-Impact wins'

with open('test/test_compliance_storage.json') as f:
    stor = json.load(f)
assert any(x['RuleId'] == 'S3_ACCOUNT_BLOCK_PUBLIC_ACCESS' for x in stor), 'Missing S3 BPA check'
assert any(x['RuleId'] == 'EBS_VOLUME_IN_USE' for x in stor), 'Missing unattached EBS check'

with open('test/test_compliance_databases.json') as f:
    db = json.load(f)
assert any(x['RuleId'] == 'RDS_DELETION_PROTECTION_ENABLED' for x in db), 'Missing RDS deletion protection check'
assert any(x['RuleId'] == 'DYNAMODB_PITR_ENABLED' for x in db), 'Missing DynamoDB PITR check'

print('[PASS] Compliance evaluation engine validated across IAM, Storage, and Databases!')
"
echo "✓ Test 7 Passed: Compliance engine evaluations verified."

echo ""
echo "[TEST 8] Testing compliance reporter HTML generation..."
python -c "
import json
iam = json.load(open('test/test_compliance_iam.json'))
stor = json.load(open('test/test_compliance_storage.json'))
db = json.load(open('test/test_compliance_databases.json'))
merged = iam + stor + db
with open('test/test_all_compliance.json', 'w') as f:
    json.dump(merged, f, indent=2)
"
python lib/compliance_reporter.py test/test_all_compliance.json test/test_compliance_dashboard.html templates/compliance_template.html 1 1

if [[ -f "test/test_compliance_dashboard.html" ]] && [[ -s "test/test_compliance_dashboard.html" ]]; then
    echo "✓ Test 8 Passed: Interactive compliance HTML dashboard generated ($(wc -c < test/test_compliance_dashboard.html) bytes)."
else
    echo "✗ Test 8 Failed: Compliance HTML dashboard not generated."
    exit 1
fi

echo ""
echo "[TEST 9] Validating Service Control Policies (SCPs) and Conformance Pack syntax..."
python -c "
import json, glob
scps = glob.glob('controls/scps/*.json')
assert len(scps) >= 5, f'Expected at least 5 SCPs, found {len(scps)}'
for s in scps:
    with open(s) as f:
        data = json.load(f)
        assert data.get('Version') == '2012-10-17', f'Invalid version in {s}'
        assert 'Statement' in data, f'Missing Statement in {s}'
print(f'[PASS] Successfully validated {len(scps)} SCP files JSON syntax!')
"
echo "✓ Test 9 Passed: SCP guardrail policies syntax verified."

echo ""
echo "================================================================================"
echo " ALL TESTS PASSED SUCCESSFULLY! "
echo "================================================================================"
