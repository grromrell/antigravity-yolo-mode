#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GEMINI_CONFIG="${HOME}/.gemini/config"
GEMINI_SKILLS="${GEMINI_CONFIG}/skills"
CLI_DIR="${HOME}/.gemini/antigravity-cli"
LOCAL_BIN="${HOME}/.local/bin"

echo "Installing Antigravity YOLO Mode..."

# 1. Directories & Skills
mkdir -p "${GEMINI_SKILLS}" "${LOCAL_BIN}" "${CLI_DIR}"

# Temporarily permit write to security-monitor if updating existing installation
[ -d "${GEMINI_SKILLS}/security-monitor" ] && chmod -R u+w "${GEMINI_SKILLS}/security-monitor" 2>/dev/null || true

cp -R "${REPO_DIR}/skills/." "${GEMINI_SKILLS}/"
chmod +x "${GEMINI_SKILLS}/yolo-mode/scripts/adversarial_test.py" \
         "${GEMINI_SKILLS}/security-monitor/scripts/fast_filter.py"

# Enforce read-only immutability on security-monitor
chmod -R 555 "${GEMINI_SKILLS}/security-monitor"

# 2. Launcher
cp -f "${REPO_DIR}/bin/yolo" "${LOCAL_BIN}/yolo"
chmod +x "${LOCAL_BIN}/yolo"

if [[ ":$PATH:" != *":${LOCAL_BIN}:"* ]]; then
    echo "Notice: ${LOCAL_BIN} not in PATH. Add to ~/.zshrc: export PATH=\"\${HOME}/.local/bin:\$PATH\""
fi

# 3. Security Policy in GEMINI.md
GEMINI_MD="${GEMINI_CONFIG}/GEMINI.md"
if [ ! -f "${GEMINI_MD}" ]; then
    cp -f "${REPO_DIR}/config/GEMINI.md" "${GEMINI_MD}"
elif ! grep -q "Global Security & YOLO Policy" "${GEMINI_MD}" 2>/dev/null; then
    printf "\n" >> "${GEMINI_MD}"
    cat "${REPO_DIR}/config/GEMINI.md" >> "${GEMINI_MD}"
fi

# 4. Patch settings.json permissions
python3 - <<EOF
import json, os
settings_path = os.path.expanduser("${CLI_DIR}/settings.json")
patch_path = os.path.join("${REPO_DIR}", "config", "settings.patch.json")
settings = json.load(open(settings_path)) if os.path.exists(settings_path) else {}
patch = json.load(open(patch_path))
allow = settings.setdefault("permissions", {}).setdefault("allow", [])
allow.extend([x for x in patch.get("permissions", {}).get("allow", []) if x not in allow])
json.dump(settings, open(settings_path, "w"), indent=2)
EOF

# 5. Verify
echo "Verifying security invariants..."
python3 "${REPO_DIR}/skills/yolo-mode/scripts/adversarial_test.py" > /dev/null
python3 "${REPO_DIR}/skills/security-monitor/scripts/test_security_monitor_integration.py" > /dev/null

echo "Installed successfully."
echo "Usage: 'yolo' (resume), 'yolo -n' (fresh), 'agy' (normal)"
