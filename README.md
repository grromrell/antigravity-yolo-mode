# Antigravity YOLO Mode

Fast execution mode for Google Antigravity CLI (`agy`). Auto-approves safe local development commands while blocking outbound network mutation, out-of-repo file modifications, package installs, and privilege escalation. Primarily used for Python, will likely need modification for other languages.

## Install

```bash
git clone https://github.com/your-username/antigravity-yolo-mode.git
cd antigravity-yolo-mode
./install.sh
```

## Usage

```bash
# Resume session in YOLO mode (default)
yolo

# Start fresh session in YOLO mode
yolo -n

# Pass standard agy arguments
yolo -m pro
```

Within a YOLO session:
- `/yolo` turns YOLO mode off (returns to normal confirmation prompts).
*(YOLO mode must be started via the `yolo` terminal command to bypass native CLI permissions.)*

## Safety Rules

| Category | Policy | Examples |
| :--- | :--- | :--- |
| **Local Dev** | Auto-Accept | `pytest`, `npm test`, `git status/add/commit`, local file edits, inspection tools |
| **Network Writes** | Halt for Approval | `git push`, `curl -d/-X POST`, `nc`, `npm publish`, `docker push` |
| **Filesystem Escapes** | Halt for Approval | `rm ../`, `rmdir ~`, writes to `/etc`, `/var`, `/usr` |
| **Dependencies & Root** | Halt for Approval | `npm install`, `pip install`, `brew install`, `sudo`, `su` |
| **Tampering** | Immutable | Edits to `.git/hooks/*`, `security-monitor/*`, agent security rules |

## Verification

```bash
bash tests/run_tests.sh
```

Runs 51 adversarial test cases against deterministic classifier `skills/security-monitor/scripts/fast_filter.py`.

## Uninstall

```bash
./uninstall.sh
```
