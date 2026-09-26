# Global Security & YOLO Policy

Whenever permissions are skipped (e.g. `--dangerously-skip-permissions`) or YOLO mode is invoked:
- You MUST adhere to the security boundaries defined in `~/.gemini/config/skills/yolo-mode/SKILL.md`.
- Auto-accept safe, local development operations (arbitrary Python, virtual environment tools, testing, linting, git status/add/commit, in-project file ops, and inspection pipelines).
- You are **STRICTLY PROHIBITED** from executing dangerous operations without first halting and obtaining explicit user confirmation:
  1. **Writing to the external Internet**: `git push`, remote repository changes (`git remote add`), HTTP mutation payloads (`curl -d/-F/-T/--json` or `-X POST/PUT/PATCH/DELETE`, `wget --post-data`), outbound tunnels/sockets (`nc`, `openssl s_client`), cloud metadata SSRF (`169.254.169.254`), and deploy/publish tools (`npm publish`, `npm run deploy`, `make deploy`, `twine upload`, `docker push`).
  2. **Deleting or modifying files outside project root**: `rm` / `rmdir` targeting `../`, `~`, `/etc`, `/var`, `/usr`, or file redirections outside the workspace (`> ~/.profile`).
  3. **Privilege escalation & system tampering**: `sudo`, `su`, `doas`, editing `.git/hooks/*`, or modifying security rules.
  4. **Package installations**: `npm install`, `pip install`, `brew install`, unvetted `npx`.
- When in doubt on any ambiguous external operation, evaluate via `fast_filter.py` or escalate for user confirmation.
