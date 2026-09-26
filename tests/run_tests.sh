#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# YOLO Mode Test Runner
# ==============================================================================

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "======================================================================"
echo " 1. Running 77-case Adversarial Security & Baseline Verification..."
echo "======================================================================"
python3 "${REPO_DIR}/skills/yolo-mode/scripts/adversarial_test.py" --fast-filter

echo -e "\n======================================================================"
echo " 2. Running Security Monitor Integration Verification..."
echo "======================================================================"
python3 "${REPO_DIR}/skills/security-monitor/scripts/test_security_monitor_integration.py"

echo -e "\n🎉 ALL TEST SUITES PASSED CLEANLY (100% VERIFIED)!"
