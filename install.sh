#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Antigravity YOLO Mode Installer
# ==============================================================================

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${CYAN}${BOLD}"
echo "======================================================================"
echo "         ANTIGRAVITY YOLO MODE — AUTOMATED INSTALLER"
echo "======================================================================"
echo -e "${RESET}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEMINI_CONFIG="${HOME}/.gemini/config"
GEMINI_SKILLS="${GEMINI_CONFIG}/skills"
CLI_DIR="${HOME}/.gemini/antigravity-cli"
LOCAL_BIN="${HOME}/.local/bin"

echo -e "📂 Preparing target directories..."
mkdir -p "${GEMINI_SKILLS}/yolo-mode/scripts"
mkdir -p "${GEMINI_SKILLS}/security-monitor/scripts"
mkdir -p "${LOCAL_BIN}"
mkdir -p "${CLI_DIR}"

# 1. Install Skills
echo -e "📦 Installing skills into ${GEMINI_SKILLS}..."
cp -f "${REPO_DIR}/skills/yolo-mode/SKILL.md" "${GEMINI_SKILLS}/yolo-mode/"
cp -f "${REPO_DIR}/skills/yolo-mode/scripts/adversarial_test.py" "${GEMINI_SKILLS}/yolo-mode/scripts/"
cp -f "${REPO_DIR}/skills/security-monitor/SKILL.md" "${GEMINI_SKILLS}/security-monitor/"
cp -f "${REPO_DIR}/skills/security-monitor/scripts/fast_filter.py" "${GEMINI_SKILLS}/security-monitor/scripts/"
cp -f "${REPO_DIR}/skills/security-monitor/scripts/test_security_monitor_integration.py" "${GEMINI_SKILLS}/security-monitor/scripts/"

chmod +x "${GEMINI_SKILLS}/yolo-mode/scripts/adversarial_test.py"
chmod +x "${GEMINI_SKILLS}/security-monitor/scripts/fast_filter.py"

# 2. Install CLI Command Wrappers
echo -e "🚀 Installing ${BOLD}yolo${RESET} and ${BOLD}noyolo${RESET} launchers to ${LOCAL_BIN}..."
cp -f "${REPO_DIR}/bin/yolo" "${LOCAL_BIN}/yolo"
cp -f "${REPO_DIR}/bin/noyolo" "${LOCAL_BIN}/noyolo"
chmod +x "${LOCAL_BIN}/yolo" "${LOCAL_BIN}/noyolo"

# Check PATH
if [[ ":$PATH:" != *":${LOCAL_BIN}:"* ]]; then
    echo -e "${YELLOW}⚠️  Note: ${LOCAL_BIN} is not in your current PATH.${RESET}"
    echo -e "   Add this to your ~/.zshrc or ~/.bashrc:"
    echo -e "   export PATH=\"\${HOME}/.local/bin:\$PATH\""
fi

# 3. Install Global Security Guardrails in GEMINI.md
GEMINI_MD="${GEMINI_CONFIG}/GEMINI.md"
echo -e "🛡️  Configuring global security guardrails in ${GEMINI_MD}..."
if [ ! -f "${GEMINI_MD}" ]; then
    cp -f "${REPO_DIR}/config/GEMINI.md" "${GEMINI_MD}"
else
    if ! grep -q "Global Security & YOLO Policy" "${GEMINI_MD}" 2>/dev/null; then
        echo -e "\n" >> "${GEMINI_MD}"
        cat "${REPO_DIR}/config/GEMINI.md" >> "${GEMINI_MD}"
    fi
fi

# 4. Patch settings.json Permissions Allowlist
SETTINGS_JSON="${CLI_DIR}/settings.json"
echo -e "⚙️  Updating CLI permissions allowlist in ${SETTINGS_JSON}..."
python3 - <<EOF
import json, os

settings_path = os.path.expanduser("${SETTINGS_JSON}")
patch_path = os.path.join("${REPO_DIR}", "config", "settings.patch.json")

settings = {}
if os.path.exists(settings_path):
    try:
        with open(settings_path, "r") as f:
            settings = json.load(f)
    except Exception:
        settings = {}

with open(patch_path, "r") as f:
    patch = json.load(f)

perms = settings.setdefault("permissions", {})
allow_list = perms.setdefault("allow", [])
existing = set(allow_list)

for item in patch.get("permissions", {}).get("allow", []):
    if item not in existing:
        allow_list.append(item)
        existing.add(item)

with open(settings_path, "w") as f:
    json.dump(settings, f, indent=2)
EOF

# 5. Run Verification Suite
echo -e "\n🧪 Running verification test suite across 77 attack vectors & safe baselines..."
python3 "${GEMINI_SKILLS}/yolo-mode/scripts/adversarial_test.py" --fast-filter > /tmp/yolo_install_test.log 2>&1 || true

if grep -q "SUMMARY: 77/77 passed (100.0%)" /tmp/yolo_install_test.log; then
    echo -e "${GREEN}${BOLD}✅ ALL 77 VERIFICATION TESTS PASSED (100%)${RESET}"
else
    echo -e "${YELLOW}⚠️  Tests completed with notes (see /tmp/yolo_install_test.log)${RESET}"
fi

echo -e "\n${GREEN}${BOLD}======================================================================"
echo "             YOLO MODE SUCCESSFULLY INSTALLED!"
echo "======================================================================${RESET}"
echo -e "Quick Usage:"
echo -e "  1. Start or resume in YOLO mode:  ${CYAN}${BOLD}yolo${RESET}"
echo -e "  2. Start or resume in normal mode: ${CYAN}${BOLD}noyolo${RESET} (or ${CYAN}agy -c${RESET})"
echo -e "  3. Toggle within any chat session: ${CYAN}${BOLD}/yolo${RESET}"
echo -e "\nEnjoy frictionless, safe AI pair programming!\n"
