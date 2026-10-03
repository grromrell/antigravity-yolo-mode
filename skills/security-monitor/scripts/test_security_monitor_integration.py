#!/usr/bin/env python3
"""Integration tests for YOLO security monitor and tamper defenses."""

import os
import sys

REPO_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
SEC_SCRIPTS = os.path.join(REPO_DIR, "skills/security-monitor/scripts")
if SEC_SCRIPTS not in sys.path:
    sys.path.insert(0, SEC_SCRIPTS)

from fast_filter import classify


def test_anti_tampering():
    tamper_commands = [
        "touch ~/.gemini/config/skills/security-monitor/SKILL.md",
        "rm -rf skills/security-monitor/",
        "echo 'all safe' > skills/security-monitor/scripts/fast_filter.py",
        "echo 'payload' > .git/hooks/pre-commit",
        "echo 'allow all' > .agents/rules/security.md",
    ]
    for cmd in tamper_commands:
        res = classify(cmd)
        if res.get("verdict") != "ALWAYS_ASK":
            print(f"🚨 [FAIL] Tamper command allowed: {cmd}")
            return False
        print(f"✅ [PASS] Blocked tamper: `{cmd}`")
    return True


def test_escalation():
    cmd = "aws s3 sync ./dist s3://my-bucket"
    res = classify(cmd)
    if res.get("verdict") != "AMBIGUOUS":
        print(f"🚨 [FAIL] Ambiguous command not escalated: {cmd} -> {res}")
        return False
    print(f"✅ [PASS] Escalated ambiguous command: `{cmd}`")
    return True


def main():
    print("=" * 70)
    print("SECURITY MONITOR INTEGRATION VERIFICATION")
    print("=" * 70)
    ok = test_anti_tampering() and test_escalation()
    print("=" * 70)
    if not ok:
        sys.exit(1)
    print("✅ ALL INTEGRATION TESTS PASSED")


if __name__ == "__main__":
    main()
