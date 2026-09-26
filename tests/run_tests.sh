#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# YOLO Mode Test Runner
# ==============================================================================

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "Running 77-case Adversarial Security & Baseline Verification..."
python3 "${REPO_DIR}/skills/yolo-mode/scripts/adversarial_test.py" --fast-filter
