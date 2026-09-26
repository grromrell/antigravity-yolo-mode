#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# Antigravity YOLO Mode Uninstaller
# ==============================================================================

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
CYAN="\033[36m"
RED="\033[31m"
RESET="\033[0m"

echo -e "${YELLOW}${BOLD}"
echo "======================================================================"
echo "         ANTIGRAVITY YOLO MODE — UNINSTALLER"
echo "======================================================================"
echo -e "${RESET}"

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEMINI_CONFIG="${HOME}/.gemini/config"
GEMINI_SKILLS="${GEMINI_CONFIG}/skills"
CLI_DIR="${HOME}/.gemini/antigravity-cli"
LOCAL_BIN="${HOME}/.local/bin"

# 1. Remove Launchers
echo -e "🗑️  Removing CLI wrappers from ${LOCAL_BIN}..."
rm -f "${LOCAL_BIN}/yolo" "${LOCAL_BIN}/noyolo"

# 2. Remove Skills
echo -e "🗑️  Removing skills from ${GEMINI_SKILLS}..."
rm -rf "${GEMINI_SKILLS}/yolo-mode"
rm -rf "${GEMINI_SKILLS}/security-monitor"

# 3. Clean GEMINI.md
GEMINI_MD="${GEMINI_CONFIG}/GEMINI.md"
if [ -f "${GEMINI_MD}" ]; then
    echo -e "🧹 Cleaning YOLO policy from ${GEMINI_MD}..."
    python3 - <<EOF
import os

gemini_md_path = os.path.expanduser("${GEMINI_MD}")
if os.path.exists(gemini_md_path):
    with open(gemini_md_path, "r") as f:
        content = f.read()

    marker = "# Global Security & YOLO Policy"
    if marker in content:
        parts = content.split(marker)
        # keep everything before the marker
        cleaned = parts[0].rstrip() + "\n"
        with open(gemini_md_path, "w") as f:
            f.write(cleaned)
        print("   Removed YOLO section from GEMINI.md")
EOF
fi

# 4. Optional: Remove permissions allowlist additions from settings.json
SETTINGS_JSON="${CLI_DIR}/settings.json"
if [ -f "${SETTINGS_JSON}" ] && [ -f "${REPO_DIR}/config/settings.patch.json" ]; then
    echo -e "⚙️  Reverting YOLO entries in ${SETTINGS_JSON}..."
    python3 - <<EOF
import json, os

settings_path = os.path.expanduser("${SETTINGS_JSON}")
patch_path = os.path.join("${REPO_DIR}", "config", "settings.patch.json")

if os.path.exists(settings_path) and os.path.exists(patch_path):
    try:
        with open(settings_path, "r") as f:
            settings = json.load(f)
        with open(patch_path, "r") as f:
            patch = json.load(f)

        patch_items = set(patch.get("permissions", {}).get("allow", []))
        allow_list = settings.get("permissions", {}).get("allow", [])

        # Filter out items present in patch
        new_allow = [item for item in allow_list if item not in patch_items]
        settings["permissions"]["allow"] = new_allow

        with open(settings_path, "w") as f:
            json.dump(settings, f, indent=2)
        print("   Reverted permissions allowlist in settings.json")
    except Exception as e:
        print(f"   Note: Could not patch settings.json: {e}")
EOF
fi

echo -e "\n${GREEN}${BOLD}======================================================================"
echo "             YOLO MODE SUCCESSFULLY UNINSTALLED"
echo "======================================================================${RESET}"
echo -e "All launchers, skills, and configuration overrides have been removed.\n"
