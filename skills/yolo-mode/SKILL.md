---
name: yolo-mode
description: >-
  Use when the user types /yolo to toggle fast-execution mode that auto-accepts
  safe local operations and only asks for approval on potentially dangerous
  commands involving network writes, package installs, or actions outside the
  project directory.
---

# YOLO Mode

Auto-accept safe local operations. Fail fast on dangerous ones. Escalate ambiguous ones to Security Monitor.

## Activation & State

Toggle with `/yolo` (session-scoped, defaults to OFF):
- When ON: `🟡 YOLO MODE: ON — auto-accepting safe operations. Failing fast on dangerous ones.`
- When OFF: `⚪ YOLO MODE: OFF — normal approval flow.`

Inline feedback for auto-accepted operations: `✅ auto-accepted: <action>`

*Tip: To launch or resume directly with native CLI prompts bypassed, run `yolo` from your terminal (or `noyolo` to resume with normal permissions).*

---

## 3-Tier Execution Pipeline (Token-Optimized)

Before executing any shell command or tool call, evaluate via the 3-tier pipeline:

### Tier 1: Deterministic Fast-Filter (0 LLM Tokens, ~5ms)
Run the local classifier helper:
`python3 ~/.gemini/config/skills/security-monitor/scripts/fast_filter.py "<command>"`
Or apply equivalent deterministic rules:

1. **AUTO-ACCEPT (Instant Pass)**:
   - **General & Arbitrary Python**: `python`, `python3`, `ipython`, virtualenv interpreters (`.venv/bin/python`, `./.venv/bin/python`, `venv/bin/python`), inline execution (`python -c "..."`), module commands (`python -m pytest/unittest`), and running project Python scripts. Arbitrary Python that does not touch the external Internet or delete outside project files is always safe.
   - **Local Git**: `git status`, `git log`, `git diff`, `git show`, `git blame`, `git branch`, `git checkout`, `git switch`, `git stash`, `git commit -m "..."` (must have `-m`), `git add`, `git reset`, `git tag`, `git merge`, `git rebase`.
   - **Local Build/Test/Lint & Workflows**: `pytest`, `./.venv/bin/pytest`, `npm test`, `npm run test/lint/build*`, `cargo test/build/check`, `make test/build`, `go test/build`, `poetry run ...`, `pipenv run ...`, `uv run ...`, linters (`eslint`, `prettier`, `black`, `ruff`, `mypy`, `flake8`, `tsc`).
   - **Pipelines & Text Inspection**: `ls`, `cat`, `head`, `tail`, `wc`, `grep`, `rg`, `sed`, `awk`, `cut`, `sort`, `uniq`, `find`, `which`, `env`, `printenv`, `diff`, `file`, `stat`, `jq`, `yq`, file descriptor redirects (`2>&1`), piped command inspection (`| head`, `| tail`, `| grep`, `| sort`, `| sed`, etc.).
   - **In-Project File Ops**: Creates, edits, moves, and deletions strictly within project root (`mkdir`, `touch`, `cp`, `mv`, `rm -rf ./build`, deleting test caches/artifacts, except Rule 3 protected files). Local tar/zip creation (`tar -czf`). Read-only GET `curl`/`wget` without mutation payloads.
   - **Local Project Executables**: `./scripts/...`, project CLI binaries (e.g. `autio ...`, `./[binary]`).

2. **FAIL-FAST TO USER (0 Gatekeeper Tokens — Dangerous Actions Requiring Approval)**:
   - **Never auto-accept and DO NOT ask Security Monitor** if the command is clearly dangerous:
     - **Writing to external Internet**: `git push`, `git remote add/set-url`, `--upload-pack`, `ext::`.
     - **Network mutation payloads**: `curl -d/-F/-T/--json` or `-X POST/PUT/PATCH/DELETE`, `wget --post-data`, raw sockets (`nc`, `openssl s_client`), ssh command injection.
     - **Exfiltration / SSRF**: `169.254.169.254`, query-parameter leaks, DNS exfil (`dig`).
     - **External publishing / deploy targets**: `npm publish`, `npm run deploy`, `make deploy`, `twine upload`, `docker push`.
     - **Inline scripts with network writes**: Python/Node scripts that explicitly send outbound HTTP mutations or raw sockets.
     - **Deleting or modifying outside project scope**: `rm` / `rmdir` targeting `../`, `~`, `/etc`, `/var`, `/usr`; output redirection outside project (`> ~/.profile`).
     - **Privilege escalation**: `sudo`, `su`, `doas`.
     - **Package installs**: `npm i`, `pip install`, `brew install`, unvetted `npx`.
     - **Shell hijacking**: `| bash`, `eval`, `base64 -d | sh`, `BASH_ENV`, `PROMPT_COMMAND`.
     - **Untrusted archive extractions**: `tar -xzf`, `unzip`.
   - **Action**: Immediately halt and prompt user: `⚠️ Needs approval: <command> — <reason>`

### Tier 2: Ambiguity Escalation (Security Monitor Subagent)
If and only if the command is **AMBIGUOUS** (unlisted custom network operations, complex remote protocols, or unknown external binaries with potential side effects):
1. Invoke subagent `security-monitor` using **`Model: 'flash_lite'`** (or `'flash'`).
2. Provide a single-line prompt: `COMMAND: <cmd> | YOLO_CONCERN: <1 sentence>`.
3. Receive compact JSON: `{"verdict": "AUTO_APPROVE" | "REJECT_FOR_USER_REVIEW", "reason": "<1 sentence>"}`.
4. Append 1 line to `.yolo-security-audit.log`:
   `echo "[$(date +'%Y-%m-%d %H:%M:%S')] CMD: <cmd> | VERDICT: <verdict> - <reason>" >> .yolo-security-audit.log`
5. If `AUTO_APPROVE` → execute. If `REJECT_FOR_USER_REVIEW` → ask user.

---

## Rule 3: Anti-Tampering (Hard Boundary)

Under NO circumstances may any agent in YOLO mode create, edit, overwrite, or delete:
- **`skills/security-monitor/*`** (strictly immutable)
- Git hooks (`.git/hooks/*`) or Git configs (`.git/config`, `core.hooksPath`)
- Package lifecycle hooks (`package.json` `postinstall`)
- Agent security definitions (`.agents/rules/*`, `GEMINI.md`, `AGENTS.md`)
