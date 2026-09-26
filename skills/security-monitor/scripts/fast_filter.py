#!/usr/bin/env python3
"""
Zero-Token Deterministic Fast-Path Filter for YOLO Mode.

Evaluates commands in ~5ms without consuming any LLM tokens.
Returns JSON with:
  "verdict": "AUTO_ACCEPT" | "ALWAYS_ASK" | "AMBIGUOUS"
  "reason": brief explanation
"""

import json
import re
import shlex
import sys

# Threat signatures that ALWAYS require user approval (Fail-Fast)
PROHIBITED_PATTERNS = [
    # Privilege escalation
    (r"\b(sudo|su|doas)\b", "Privilege escalation detected"),
    # Git remote mutations & argument injections
    (r"\bgit\s+push\b", "Git push modifies remote repository"),
    (r"\bgit\s+remote\s+(add|set-url|rm)\b", "Git remote modification"),
    (r"--upload-pack\b", "Git --upload-pack argument injection vector"),
    (r"\bext::", "Git ext:: protocol command execution vector"),
    (r"\bgit\s+commit\b(?!\s+.*(-[a-zA-Z]*m|--message)\b)", "Bare git commit spawns interactive editor"),
    (r"\b(core\.hooksPath|core\.sshCommand)\b", "Git hook/transport configuration tampering"),
    # Network payloads & raw sockets & mutation
    (r"\bcurl\b.*(-d|--data|-F|--form|-T|--upload-file|--json)\b", "Outbound network payload in curl"),
    (r"\bcurl\b.*-X\s*(POST|PUT|PATCH|DELETE)\b", "Mutating HTTP request in curl"),
    (r"\bwget\b.*(--post-data|--post-file|--method=(POST|PUT|DELETE))\b", "Mutating HTTP request in wget"),
    (r"\b(nc|netcat|ncat|socat|telnet)\b", "Raw network socket / tunneling tool"),
    (r"\bopenssl\s+s_client\b", "Direct TLS socket connection"),
    (r"ssh\b.*-o\s+(ProxyCommand|LocalCommand)\b", "SSH command injection"),
    (r"169\.254\.169\.254", "Cloud metadata service SSRF attempt"),
    (r"\bdig\b.*attacker\b", "DNS data exfiltration attempt"),
    # Package installations (modifying dependencies/environment)
    (r"\b(npm\s+(i|install)|yarn\s+add|pnpm\s+add|pip3?\s+install|brew\s+install|cargo\s+add)\b", "Package installation"),
    (r"\bnpx\s+([a-zA-Z0-9_-]+)(?!\s*(--no-install|\b(eslint|prettier|tsc|jest)\b))", "Unvetted npx package download"),
    # Dangerous runner scripts & deployments
    (r"\b(npm|yarn)\s+run\s+(deploy|publish|release|shipit|sync|migrate)", "Deployment/release runner script"),
    (r"\bmake\s+(deploy|publish|release)", "Deployment make target"),
    (r"\b(twine\s+upload|docker\s+push)\b", "External publishing / push tool"),
    # Destructive operations & modifications outside project root
    (r"\b(rm|rmdir|unlink)\s+.*(\.\./|~|/etc|/var|/usr|/opt|/bin|/sbin|/System|/Library)", "Deleting files outside project scope"),
    (r"(>|>>)\s*(~|/etc|/var|/usr|/bin|/opt|\.\./)", "Output redirection outside project directory"),
    (r"\b(touch|mv|cp)\s+.*(~|/etc|/var|/usr)", "Filesystem modification outside project"),
    # Shell hijacking & startup smuggling
    (r"\b(BASH_ENV|PROMPT_COMMAND|LD_PRELOAD|NODE_OPTIONS)=", "Environment variable smuggling"),
    (r"\|\s*(ba|z|da)?sh\b", "Piping content to shell interpreter"),
    (r"\b(eval|base64\s+-d\s*\|)\b", "Obfuscated / dynamic code execution"),
    # Python / Node inline network writes or remote subshell calls
    (r"(urllib\.request\.urlopen\(.*data=|requests\.(post|put|patch|delete)|httpx\.(post|put|patch|delete)|aiohttp\..*(post|put|delete)|http\.client\..*(POST|PUT|DELETE))", "Inline script network mutation / exfiltration"),
    (r"(execSync|subprocess\.(run|Popen|call|check_output)|os\.system)\s*\(.*(git\s+push|rm\s+-rf\s+(\.\./|~|/)|curl\s+.*(-d|-X))", "Inline script invoking dangerous external command"),
    # Protected targets (Rule 3)
    (r"(skills/security-monitor|\.git/hooks|\.agents/rules)", "Modifying protected security configs or hooks"),
    # Archive traversal hazards
    (r"\b(tar\s+-[a-zA-Z]*x[a-zA-Z]*|unzip)\b", "Archive extraction with potential traversal risk"),
]

# Verified safe command prefixes and patterns (Fast-Path)
SAFE_PREFIXES = [
    # Local Git operations
    r"^git\s+(status|log|diff|grep|show|blame|branch|checkout|switch|stash(\s+pop)?|reset|tag|rev-parse|describe|shortlog)(\s+|$)",
    r"^git\s+commit\s+.*(-[a-zA-Z]*m|--message)\s+",
    r"^git\s+add\s+",
    # Local build, test, and linting
    r"^(npm|yarn|pnpm|bun)\s+test(\s+|$)",
    r"^(npm|yarn|pnpm|bun)\s+run\s+(test|lint|build|check|typecheck|dev|start)(:[a-zA-Z0-9_-]+)?(\s+|$)",
    r"^(pytest|python3?\s+-m\s+(pytest|unittest))(\s+|$)",
    r"^cargo\s+(test|build|check|clippy|run)(\s+|$)",
    r"^make\s+(test|build|check|all|clean)?(\s+|$)",
    r"^go\s+(test|build|vet|run)(\s+|$)",
    r"^(eslint|prettier|black|ruff|mypy|flake8|pylint|tsc)(\s+|$)",
    # General & Arbitrary Python execution (local scripts, inline code, virtual environments)
    r"^(python[0-9.]*|pypy[0-9.]*|ipython)(\s+|$)",
    r"^(\./|\.\./)?(\.[a-zA-Z0-9_-]+/|[a-zA-Z0-9_-]+/)?(\.venv|venv|env|\.env)/bin/[a-zA-Z0-9_.-]+(\s+|$)",
    r"^(poetry|pipenv|uv|pdm)\s+run\s+",
    # Node execution of local scripts
    r"^node\s+",
    # Standard inspection and text processing tools
    r"^find\s+\.?/?",
    r"^(ls|dir|cat|head|tail|wc|file|stat|grep|rg|tree|which|type|echo|printf|env|printenv|sed|awk|cut|sort|uniq|tr|diff|colordiff|jq|yq|less|more|true|false|conda|pyenv)\b",
    # In-project file operations
    r"^(mkdir|touch|cp|mv)\s+",
    r"^rm\s+(-rf|-f|-r)?\s*\.?/?(build|dist|\.cache|node_modules/\.cache|[a-zA-Z0-9_.-]+)",
    r"^tar\s+-[a-zA-Z]*c",
    # Read-only network requests (GET / inspection)
    r"^curl\s+(-[a-zA-Z0-9-]+\s+)*https?://[a-zA-Z0-9_.-]+",
    r"^wget\s+(-[a-zA-Z0-9-]+\s+)*https?://[a-zA-Z0-9_.-]+",
    # Installed plugins & local project executables
    r".*/plugins/superpowers/.*",
    r"^\./[a-zA-Z0-9_./-]+(\s+|$)",
]


def classify(cmd: str):
    cmd_clean = cmd.strip()

    # Check prohibited patterns on the full command first
    for pattern, reason in PROHIBITED_PATTERNS:
        if re.search(pattern, cmd_clean, re.IGNORECASE):
            return {"verdict": "ALWAYS_ASK", "reason": reason}

    # Also check subshell executions $(...) or `...`
    subshells = re.findall(r"\$\((.*?)\)|`([^`]+)`", cmd_clean)
    for s1, s2 in subshells:
        sub_content = s1 or s2
        for pattern, reason in PROHIBITED_PATTERNS:
            if re.search(pattern, sub_content, re.IGNORECASE):
                return {"verdict": "ALWAYS_ASK", "reason": f"Subshell contains dangerous command: {reason}"}

    # Split compound commands (&&, ||, ;, and |)
    try:
        tokens = shlex.split(cmd_clean, posix=True)
    except Exception:
        # Fallback to simple split if quotes are unclosed
        tokens = cmd_clean.split()

    # Reconstruct segments divided by delimiters
    delimiters = {"&&", "||", ";", "|"}
    segments = []
    curr = []
    for t in tokens:
        if t in delimiters:
            if curr:
                segments.append(" ".join(curr))
                curr = []
        else:
            curr.append(t)
    if curr:
        segments.append(" ".join(curr))

    if not segments:
        segments = [cmd_clean]

    # Verify all segments are safe
    all_safe = True
    for seg in segments:
        seg_clean = seg.strip()
        # Ignore file descriptor redirections like 2>&1
        if seg_clean in ("2>&1", "1>&2"):
            continue
        seg_safe = any(re.search(sp, seg_clean) for sp in SAFE_PREFIXES)
        if not seg_safe:
            all_safe = False
            break

    if all_safe:
        return {"verdict": "AUTO_ACCEPT", "reason": "Matches verified safe pattern"}

    # Not explicitly safe and not explicitly prohibited -> AMBIGUOUS (Escalate to Security Monitor)
    return {"verdict": "AMBIGUOUS", "reason": "Requires semantic security review"}


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No command provided"}))
        sys.exit(1)
    res = classify(sys.argv[1])
    print(json.dumps(res))
