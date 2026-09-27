#!/usr/bin/env bash
# ==============================================================================
# Script: setup_git_hooks.sh
# Purpose: Configures local Git repository to enforce security hooks in .githooks/
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}" || exit 1

chmod +x .githooks/* 2>/dev/null || true
git config core.hooksPath .githooks

echo "[SUCCESS] Git hooks successfully configured to use .githooks/"
echo "Enforced guards:"
echo "  - pre-commit: Prevents accidental staging/committing of reports, backups, and credentials"
echo "  - pre-push:   Prevents accidental pushing of reports, backups, and credentials"
