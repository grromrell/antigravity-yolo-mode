#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEMINI_CONFIG="${HOME}/.gemini/config"
GEMINI_SKILLS="${GEMINI_CONFIG}/skills"
CLI_DIR="${HOME}/.gemini/antigravity-cli"
LOCAL_BIN="${HOME}/.local/bin"

echo "Uninstalling Antigravity YOLO Mode..."

# 1. Remove Launcher
rm -f "${LOCAL_BIN}/yolo"

# 2. Remove Skills
[ -d "${GEMINI_SKILLS}/security-monitor" ] && chmod -R u+w "${GEMINI_SKILLS}/security-monitor" 2>/dev/null || true
rm -rf "${GEMINI_SKILLS}/yolo-mode" "${GEMINI_SKILLS}/security-monitor"

# 3. Clean GEMINI.md
GEMINI_MD="${GEMINI_CONFIG}/GEMINI.md"
if [ -f "${GEMINI_MD}" ]; then
    python3 - <<EOF
import os
path = os.path.expanduser("${GEMINI_MD}")
if os.path.exists(path):
    content = open(path).read()
    marker = "# Global Security & YOLO Policy"
    if marker in content:
        open(path, "w").write(content.split(marker)[0].rstrip() + "\n")
EOF
fi

# 4. Revert settings.json
SETTINGS_JSON="${CLI_DIR}/settings.json"
PATCH_PATH="${REPO_DIR}/config/settings.patch.json"
if [ -f "${SETTINGS_JSON}" ] && [ -f "${PATCH_PATH}" ]; then
    python3 - <<EOF
import json, os
spath = os.path.expanduser("${SETTINGS_JSON}")
ppath = "${PATCH_PATH}"
if os.path.exists(spath) and os.path.exists(ppath):
    try:
        settings = json.load(open(spath))
        patch = json.load(open(ppath))
        remove = set(patch.get("permissions", {}).get("allow", []))
        current = settings.get("permissions", {}).get("allow", [])
        settings["permissions"]["allow"] = [x for x in current if x not in remove]
        json.dump(settings, open(spath, "w"), indent=2)
    except Exception:
        pass
EOF
fi

echo "Uninstalled successfully."
