#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== 1. Adversarial Fast-Filter Verification (51 vectors) ==="
python3 "${REPO_DIR}/skills/yolo-mode/scripts/adversarial_test.py"

echo -e "\n=== 2. Security Monitor & Tamper Verification ==="
python3 "${REPO_DIR}/skills/security-monitor/scripts/test_security_monitor_integration.py"

echo -e "\n🎉 ALL TESTS PASSED (100% VERIFIED)"
