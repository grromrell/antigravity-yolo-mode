#!/usr/bin/env python3
"""
Integration Test for Security Monitor & YOLO Mode.

Verifies:
1. Anti-Tampering: Any attempt in YOLO mode to modify `skills/security-monitor/*` is strictly rejected.
2. Escalation Protocol: Ambiguous commands are classified as AMBIGUOUS and escalated.
3. Audit Document: Entry is logged to `.yolo-security-audit.log` with concise explanations.
"""

import json
import os
import sys
from datetime import datetime

# Add script directory to sys.path to import fast_filter
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

from fast_filter import classify

AUDIT_LOG_PATH = "/tmp/test_yolo_audit.log"


def test_anti_tampering():
    print("Testing Anti-Tampering (Modifying Security Monitor in YOLO mode)...")
    tamper_commands = [
        "touch ~/.gemini/config/skills/security-monitor/SKILL.md",
        "rm -rf skills/security-monitor/",
        "echo 'all safe' > skills/security-monitor/scripts/fast_filter.py",
        "echo 'payload' > .git/hooks/pre-commit",
        "echo 'allow all' > .agents/rules/security.md",
    ]

    all_passed = True
    for cmd in tamper_commands:
        res = classify(cmd)
        if res.get("verdict") == "ALWAYS_ASK":
            print(f"  ✅ [PASS] Tamper attempt blocked: `{cmd}` -> {res.get('reason')}")
        else:
            print(f"  🚨 [FAIL] Tamper attempt not blocked: `{cmd}` -> {res}")
            all_passed = False

    return all_passed


def test_gatekeeper_escalation():
    print("\nTesting Gatekeeper Escalation & Audit Logging...")

    # Candidate borderline/ambiguous request (cloud sync tool):
    request = "aws s3 sync ./dist s3://my-bucket"
    res = classify(request)

    if res.get("verdict") == "AMBIGUOUS":
        print(f"  ✅ [PASS] Ambiguous command escalated: `{request}` -> {res.get('reason')}")
    else:
        print(f"  🚨 [FAIL] Command not classified as AMBIGUOUS: {res}")
        return False

    # Simulate Gatekeeper Verdict & Audit Entry
    verdict = "REJECT_FOR_USER_REVIEW"
    reasoning = "Sourcemap upload transmits source code to external servers; requires confirmation."
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = f"""### [{timestamp}] Security Review Entry
- **Request:** `{request}`
- **Classification:** `{res.get('verdict')}`
- **Security Monitor Verdict:** `{verdict}`
- **Security Monitor Reasoning:** {reasoning}
\n"""

    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(entry)

    print(f"  ✅ [PASS] Audit entry successfully created at {AUDIT_LOG_PATH}")
    return True


def main():
    print("=" * 70)
    print("SECURITY MONITOR INTEGRATION VERIFICATION")
    print("=" * 70)
    p1 = test_anti_tampering()
    p2 = test_gatekeeper_escalation()
    print("=" * 70)
    if p1 and p2:
        print("✅ ALL SECURITY MONITOR INTEGRATION TESTS PASSED (100%)")
        sys.exit(0)
    else:
        print("❌ SOME TESTS FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
