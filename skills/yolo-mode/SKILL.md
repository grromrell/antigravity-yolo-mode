---
name: yolo-mode
description: Fast execution mode. Auto-accepts safe local dev operations; halts on network writes, external file modifications, or privilege escalations.
---

# YOLO Mode

Auto-accept safe local operations. Halt on dangerous operations. Escalate ambiguous commands to Security Monitor.

## State Control
YOLO mode requires launching with `yolo` from the terminal (`--dangerously-skip-permissions`).
- `/yolo` deactivates YOLO mode for the current session.
- If invoked while OFF outside of a `yolo` CLI launch, inform the user: `⚠️ YOLO mode requires native CLI flags. Launch with 'yolo' from your terminal.`
- Internal state commands: `/yolo on` and `/yolo off` (used by launchers).

### State Responses
- **ON**: `🟡 YOLO MODE: ON — auto-accepting safe operations. Failing fast on dangerous ones.`
- **OFF**: `⚪ YOLO MODE: OFF — normal approval flow.`
- **Log**: Output `✅ auto-accepted: <action>` before executing allowed commands.

## Execution Pipeline

### Tier 1: Fast Filter
Run classifier before shell actions:
`python3 ~/.gemini/config/skills/security-monitor/scripts/fast_filter.py "<command>"`

1. **AUTO-ACCEPT**:
   - Local Python/Node/Rust/Go runtimes, test suites, linters, build commands.
   - Local git operations (`status`, `log`, `diff`, `add`, `commit -m "..."`, `checkout`, `branch`).
   - In-repo file reads, writes, and text processing (`ls`, `grep`, `cat`, `find`, `sed`, `awk`, `jq`).
   - Read-only HTTP GET requests without payloads.

2. **HALT FOR APPROVAL** (Prompt: `⚠️ Needs approval: <command> — <reason>`):
   - Outbound writes: `git push`, remote config, HTTP mutations (`POST`/`PUT`/`DELETE`, `-d`, `--json`), raw sockets (`nc`), deploy targets (`npm publish`, `docker push`).
   - Out-of-tree file modifications: operations on `../`, `~`, `/etc`, `/var`, `/usr`.
   - Privilege & packages: `sudo`, `su`, `npm install`, `pip install`, `brew install`.
   - Shell hijacking: `| bash`, `eval`, `base64 -d | sh`, environment hijacking (`LD_PRELOAD`, `BASH_ENV`).
   - Untrusted archive extractions: `tar -xzf`, `unzip`.

### Tier 2: Security Monitor Escalation
When command is ambiguous:
1. Invoke subagent `security-monitor` (Model: `flash_lite`) with `COMMAND: <cmd> | YOLO_CONCERN: <reason>`.
2. Parse response: `{"verdict": "AUTO_APPROVE" | "REJECT_FOR_USER_REVIEW", "reason": "<reason>"}`.
3. Log result: `echo "[$(date +'%Y-%m-%d %H:%M:%S')] CMD: <cmd> | VERDICT: <verdict> - <reason>" >> .yolo-security-audit.log`.
4. Halt if rejected; execute if approved.

## Hard Boundaries (Immutable)
Never create, edit, or delete:
- `skills/security-monitor/*`
- `.git/hooks/*`, `.git/config`, `core.hooksPath`
- `package.json` install hooks
- Security rules (`.agents/rules/*`, `GEMINI.md`, `AGENTS.md`)
