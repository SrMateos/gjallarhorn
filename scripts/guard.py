#!/usr/bin/env python3
"""laya-guard: PreToolUse hook for Claude Code.

Three layers, in order:
  1. Hard rules (deterministic): secrets, data deletion, destructive commands.
  2. Fast allowlist: routine commands that are not worth sending to the model.
  3. Laya (local classifier served by laya-serve) for everything in the grey zone.

Output:
  - nothing  -> neutral: Claude Code continues with its normal permission flow
  - "ask"    -> the agent stops and asks the user
  - "deny"   -> the action is blocked and Claude receives the reason

Stdlib only, so it starts fast on every tool call.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------- configuration
PORT = int(os.environ.get("LAYA_GUARD_PORT", "8765"))
STATE_DIR = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache")) / "laya-guard"
ON_DANGER = os.environ.get("LAYA_GUARD_ON_DANGER", "ask")   # when Laya flags danger: ask | deny
ON_ERROR = os.environ.get("LAYA_GUARD_ON_ERROR", "ask")     # when Laya is down: ask (fail-closed) | pass (fail-open)
THRESHOLD = float(os.environ.get("LAYA_GUARD_THRESHOLD", "0.55"))  # min P(routine) to let an action pass
WAIT_S = float(os.environ.get("LAYA_GUARD_WAIT", "20"))     # how long to wait for the server to start
# Total time for asking Laya (waiting for the server + request + retries). It must stay below the
# hook timeout in hooks/hooks.json (30 s): Claude Code lets a timed-out hook's tool call through.
BUDGET_S = float(os.environ.get("LAYA_GUARD_BUDGET", "25"))
MAX_CHARS = 20_000                                          # roughly < 8k tokens for laya-multilingual
# The English checkpoint (ModernBERT-large) is the most accurate on English text, but it only has
# 512 tokens of context, ~320 of which are left for the state. Actions up to this size go to the
# English checkpoint; longer ones go to laya-multilingual with 8k. Measured on the described action.
EN_MAX_CHARS = int(os.environ.get("LAYA_GUARD_EN_MAX_CHARS", "1000"))
# Python rules:
#   on     -> rules decide first, Laya only sees the grey zone (default)
#   shadow -> rules still decide, but Laya scores EVERY action and it gets logged (for comparison)
#   off    -> no rules and no allowlist: Laya decides everything on its own. Experiments only.
RULES = os.environ.get("LAYA_GUARD_RULES", "on")
# Checkpoint: auto (English if it fits, otherwise multilingual 8k) | english | multilingual
MODEL = os.environ.get("LAYA_GUARD_MODEL", "auto")
PLUGIN_ROOT = Path(os.environ.get("CLAUDE_PLUGIN_ROOT", Path(__file__).resolve().parent.parent))

# ---------------------------------------------------------------- secrets
SECRET_NAMES = {
    ".envrc", ".netrc", ".pgpass", ".pypirc", ".npmrc", ".git-credentials",
    ".htpasswd", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
}
SECRET_EXT = (".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore", ".jks", ".age", ".gpg")
SECRET_DIRS = {".ssh", ".aws", ".gnupg", ".password-store"}
ENV_OK = re.compile(r"\.env\.(example|sample|template|dist)$")   # templates are fine to touch

# Credential-looking tokens inside content that is about to be written
SECRET_CONTENT = re.compile(
    r"(sk-(ant|proj|live)-[A-Za-z0-9_-]{10,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,}|"
    r"github_pat_[A-Za-z0-9_]{30,}|xox[bpa]-[A-Za-z0-9-]{10,}|hf_[A-Za-z0-9]{30,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(password|passwd|secret|api_?key|token)\s*[=:]\s*['\"][^'\"\s]{8,}['\"])",
    re.IGNORECASE,
)


def is_secret_path(p: str) -> bool:
    p = p.strip().strip("'\"")
    if not p:
        return False
    name = os.path.basename(p.rstrip("/"))
    if name in SECRET_NAMES or name.lower().endswith(SECRET_EXT):
        return True
    if re.fullmatch(r"\.env(\..+)?", name) and not ENV_OK.search(name):
        return True
    if re.fullmatch(r"(credentials|secrets?)(\.\w+)?", name, re.IGNORECASE):
        return True
    return any(part in SECRET_DIRS for part in Path(p).parts) or ".kube/config" in p


# ---------------------------------------------------------------- data
DATA_DIRS = {"data", "datasets", "dataset", "raw", "processed", "outputs", "trajectories", "trajs"}
DATA_EXT = (".parquet", ".jsonl", ".csv", ".tsv", ".h5", ".hdf5", ".npy", ".npz", ".arrow",
            ".feather", ".pt", ".pth", ".ckpt", ".safetensors", ".db", ".sqlite", ".tar", ".zst", ".gz")


def is_data_path(p: str) -> bool:
    p = p.strip().strip("'\"")
    parts = [x for x in Path(p).parts if x not in (".", "/")]
    return any(x in DATA_DIRS for x in parts) or p.lower().endswith(DATA_EXT)


def is_root_or_home(p: str) -> bool:
    p = p.strip().strip("'\"").rstrip("/") or "/"
    return p in {"/", "~", "$HOME", "${HOME}", "*", "/*", "~/*", "$HOME/*", ".", "..", "./*"} or \
        p in {str(Path.home()), "/home", "/etc", "/usr", "/var", "/opt", "/boot"}


# ---------------------------------------------------------------- Bash
OPERATORS = {";", "&&", "||", "|", "&", "(", ")", "|&"}


def tokenize(cmd: str) -> list[str]:
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        return cmd.split()


def path_candidates(tokens: list[str]) -> list[str]:
    out = []
    for t in tokens:
        out.append(t)
        for sep in ("=", ":"):          # --env-file=.env, host:~/.ssh/id_rsa
            if sep in t:
                out.extend(t.split(sep))
        if t.startswith((">", "<")):
            out.append(t.lstrip("<>&"))
    return out


def rm_targets(tokens: list[str]):
    """Return [(flags, targets)] for every rm in the command."""
    res, i = [], 0
    while i < len(tokens):
        if os.path.basename(tokens[i]) == "rm":
            flags, targets = "", []
            i += 1
            while i < len(tokens) and tokens[i] not in OPERATORS:
                t = tokens[i]
                if t.startswith("-") and t != "--":
                    flags += t
                elif t != "--":
                    targets.append(t)
                i += 1
            res.append((flags, targets))
        i += 1
    return res


HARD_DENY = [
    (re.compile(r"\b(mkfs(\.\w+)?|shred|wipefs)\b"), "unrecoverable wipe of a disk or files"),
    (re.compile(r"\bdd\b.*\bof=/dev/"), "dd writing directly to a device"),
    (re.compile(r"--no-preserve-root"), "rm on the filesystem root"),
    (re.compile(r":\(\)\s*\{\s*:\|:&\s*\};:"), "fork bomb"),
]
ASK = [
    (re.compile(r"\bfind\b.*(-delete\b|-exec\s+rm\b)"), "find that deletes files"),
    (re.compile(r"\bgit\s+push\b.*(--force\b|\s-f\b|--mirror\b)"), "forced git push (rewrites remote history)"),
    (re.compile(r"\bgit\s+(reset\s+--hard|clean\s+-\w*f|filter-(branch|repo)|checkout\s+--\s+\.)"),
     "git command that discards changes or rewrites history"),
    (re.compile(r"\b(curl|wget)\b[^|]*\|\s*(sudo\s+)?(ba|z|fi)?sh\b"), "downloads and runs a remote script"),
    (re.compile(r"\bsudo\b"), "command with sudo"),
    (re.compile(r"\bchmod\b.*(-R|777)|\bchown\b.*-R"), "bulk permission change"),
    (re.compile(r"^\s*(env|printenv|export\s+-p|set)\s*$|/proc/\S*/environ"),
     "dumps environment variables (may contain secrets)"),
    (re.compile(r"\bcurl\b.*(\s-T\s|--upload-file|\s-F\s|--form|(-d|--data(-binary|-raw)?)\s+@)"),
     "uploads a local file to an external server"),
    (re.compile(r"\b(scp|rsync)\b.*\S+@\S+:|\brsync\b.*--delete"), "copies/syncs with a remote host"),
    (re.compile(r"\btruncate\b|>\s*/dev/sd"), "truncates files or writes to a disk"),
]

SAFE_FIRST = {"ls", "pwd", "cat", "head", "tail", "wc", "echo", "grep", "rg", "tree", "which",
              "file", "stat", "du", "df", "diff", "less", "sort", "uniq", "jq", "fd", "ruff", "mypy"}
SAFE_PREFIX = ("git status", "git diff", "git log", "git show", "git branch", "git add", "git commit",
               "git fetch", "git stash list", "uv run pytest", "uv run python -m pytest", "uv sync",
               "uv add", "uv lock", "uv pip list", "uv tree", "pytest", "python -m pytest", "npm test",
               "npm run lint", "make test")
SHELL_META = re.compile(r"[;&|<>`$()\n]")


def check_bash(cmd: str):
    """-> (decision | None, reason, touches_secret)"""
    tokens = tokenize(cmd)
    for c in path_candidates(tokens):
        if is_secret_path(c):
            return "deny", f"The command touches a secrets file ({c}). Ask the user to do it.", True
    for rx, why in HARD_DENY:
        if rx.search(cmd):
            return "deny", f"Blocked: {why}.", False
    for flags, targets in rm_targets(tokens):
        for t in targets:
            if is_root_or_home(t):
                return "deny", f"Blocked: rm on {t}.", False
            if is_data_path(t):
                return "deny", f"Blocked: rm on data ({t}). Data must not be deleted by the agent.", False
        if "r" in flags or "f" in flags:
            return "ask", f"rm {flags} {' '.join(targets)}", False
    for rx, why in ASK:
        if rx.search(cmd):
            return "ask", why, False
    stripped = cmd.strip()
    if not SHELL_META.search(stripped):
        if (tokens and tokens[0] in SAFE_FIRST) or stripped.startswith(SAFE_PREFIX):
            return "pass", "allowlist", False
    return None, "", False   # grey zone -> Laya


# ---------------------------------------------------------------- other tools
def project_dir(data) -> Path:
    return Path(os.environ.get("CLAUDE_PROJECT_DIR") or data.get("cwd") or os.getcwd()).resolve()


def inside(path: str, root: Path) -> bool:
    try:
        Path(path).expanduser().resolve().relative_to(root)
        return True
    except ValueError:
        return False


def check_rules(data: dict):
    """-> (decision | None, reason, touches_secret)"""
    tool, ti = data.get("tool_name", ""), data.get("tool_input", {}) or {}
    if tool == "Bash":
        return check_bash(ti.get("command", ""))
    if tool in ("Read", "Grep"):
        for key in ("file_path", "path", "glob"):
            if ti.get(key) and is_secret_path(ti[key]):
                return "deny", f"Reading a secrets file ({ti[key]}) is not allowed.", True
        return "pass", "normal read", False
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        path = ti.get("file_path") or ti.get("notebook_path") or ""
        if is_secret_path(path):
            return "deny", f"Writing to a secrets file ({path}) is not allowed.", True
        if SECRET_CONTENT.search(json.dumps(ti, ensure_ascii=False)):
            return "ask", "The content seems to include a plaintext credential.", True
        if tool == "Write" and is_data_path(path) and Path(path).exists():
            return "ask", f"Overwrites an existing data file ({path}).", False
        if inside(path, project_dir(data)):
            return "pass", "edit inside the project", False
        return None, "", False   # outside the project -> Laya
    return None, "", False       # MCP and everything else -> Laya


# ---------------------------------------------------------------- Laya
# English checkpoint: fields named in backticks (the convention of Laya's presets) and concrete
# examples in the criteria. On examples.jsonl this took AUC from 0.80 to 0.93 over QUESTION_MULTI.
QUESTION_EN = {
    "risk": {
        "type": "choice",
        "instructions": "Should a careful developer review `action` before an AI coding agent runs it in `working_directory`?",
        "criteria": {
            "A": "yes: deletes data, reads or leaks secrets or .env files, uploads data, force-pushes, runs remote "
                 "scripts, or changes production, databases, cloud or system files",
            "B": "no: everyday development inside the project such as git status, reading or editing code, "
                 "running tests, builds or local scripts",
        },
    }
}
# Multilingual checkpoint: does worse with the prompt above (AUC 0.61), so it keeps the original one (0.79).
QUESTION_MULTI = {
    "risk": {
        "type": "choice",
        "instructions": (
            "Is this AI coding agent action dangerous? Dangerous: deletes or overwrites hard-to-recover data, "
            "exposes secrets or .env files, sends data to external hosts, changes system settings or permissions, "
            "rewrites git history, or modifies remote or production resources."
        ),
        # choice with neutral keys instead of noul (see 'Honest Limits' in the model card)
        "criteria": {
            "A": "dangerous: destructive, irreversible, touches secrets, exfiltrates data or affects production",
            "B": "routine: normal development such as reading code, editing project files, running tests or scripts locally",
        },
    }
}


def describe(tool: str, ti: dict) -> str:
    """The tool call in plain English: the English checkpoint reads this better than raw JSON."""
    if tool == "Bash":
        return f"Run shell command: {ti.get('command', '')}"
    if tool == "Read":
        return f"Read file {ti.get('file_path', '')}"
    if tool == "Grep":
        return f"Search for {ti.get('pattern', '')!r} in {ti.get('path') or ti.get('glob') or '.'}"
    if tool == "Edit":
        return f"Edit file {ti.get('file_path', '')}: replace {ti.get('old_string', '')!r} with {ti.get('new_string', '')!r}"
    if tool == "Write":
        return f"Write file {ti.get('file_path', '')} with content: {ti.get('content', '')}"
    return f"Call tool {tool} with {json.dumps(ti, ensure_ascii=False)}"


def server_up() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", PORT), timeout=0.3):
            return True
    except OSError:
        return False


def ensure_server(timeout: float = WAIT_S) -> bool:
    """Start laya-serve if needed and wait up to `timeout` seconds for its port to open."""
    if server_up():
        return True
    pidfile = STATE_DIR / "laya.pid"
    starting = False
    if pidfile.exists():
        try:
            os.kill(int(pidfile.read_text().strip()), 0)
            starting = True
        except (OSError, ValueError):
            pass
    if not starting:   # SessionStart did not launch it: launch it ourselves
        subprocess.Popen([str(PLUGIN_ROOT / "scripts" / "start_laya.sh")],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if server_up():
            return True
        time.sleep(0.5)
    return False


def p_danger(ans: dict) -> float | None:
    """P(A). Not `confidence`: for choice questions that one is entropy-based, not a probability."""
    probs = ans.get("probabilities")
    if isinstance(probs, dict) and isinstance(probs.get("A"), (int, float)):
        return float(probs["A"])
    conf = ans.get("answer_confidence")
    if isinstance(conf, (int, float)) and ans.get("choice") in ("A", "B"):
        return float(conf) if ans["choice"] == "A" else 1.0 - float(conf)
    return None


def ask_laya(data: dict, model_pref: str | None = None, deadline: float | None = None) -> dict:
    """Ask Laya about one tool call. `deadline` (time.monotonic()) bounds the request and its retries."""
    deadline = deadline or time.monotonic() + BUDGET_S
    tool, ti = data.get("tool_name"), data.get("tool_input", {}) or {}
    wd = str(project_dir(data))
    described = describe(tool, ti)
    pref = model_pref or MODEL
    if pref == "english" or (pref == "auto" and len(described) <= EN_MAX_CHARS):
        model = "english"
        state = {"agent": "AI coding agent (Claude Code)", "action": described, "working_directory": wd}
        body = {"state": state, "questions": QUESTION_EN, "model": "english"}
    else:   # does not fit in 512 tokens: use the 8k checkpoint
        model = "multilingual"
        action = str(ti.get("command") if tool == "Bash" else json.dumps(ti, ensure_ascii=False))
        state = {"tool": tool, "action": action[:MAX_CHARS], "working_directory": wd}
        body = {"state": state, "questions": QUESTION_MULTI, "model": "multilingual", "max_len": 8192}
    key = (STATE_DIR / "api_key").read_text().strip()
    req = urllib.request.Request(
        f"http://127.0.0.1:{PORT}/v1/systemone", data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"})
    for attempt in range(3):   # 503 = server busy (another session or the warm-up): retry briefly
        remaining = deadline - time.monotonic()
        if remaining < 1:
            raise TimeoutError(f"no time left within the {BUDGET_S:.0f} s budget")
        try:
            with urllib.request.urlopen(req, timeout=remaining) as r:
                resp = json.load(r)
            break
        except urllib.error.HTTPError as e:
            if e.code != 503 or attempt == 2 or deadline - time.monotonic() < 2:
                raise
            time.sleep(1)
    ans = resp["answers"]["risk"]
    return {"choice": ans.get("choice"), "p_danger": p_danger(ans), "model": model, "raw": ans}


# ---------------------------------------------------------------- decision
def laya_verdict(data: dict, model_pref: str | None = None):
    """-> (decision, reason, source, extra) according to Laya. Takes at most BUDGET_S seconds."""
    deadline = time.monotonic() + BUDGET_S
    try:
        if not ensure_server(min(WAIT_S, BUDGET_S)):
            raise RuntimeError("laya-serve is not responding (first run still downloading the model?)")
        v = ask_laya(data, model_pref, deadline)
    except Exception as e:  # noqa: BLE001
        return ON_ERROR, f"Laya unavailable ({e})", "error", None
    p = v["p_danger"]
    p_s = f"P(danger) {p:.2f}" if p is not None else "P(danger) ?"
    if v["choice"] == "A":
        return ON_DANGER, f"Laya flags this action as dangerous ({p_s}, {v['model']})", "laya", v
    if p is None or 1 - p < THRESHOLD:
        return "ask", f"Laya is not sure this is routine ({p_s}, {v['model']})", "laya", v
    return "pass", f"Laya: routine ({p_s}, {v['model']})", "laya", v


def decide(data: dict, use_laya: bool = True, rules: str | None = None, model_pref: str | None = None):
    """-> (decision: 'pass'|'ask'|'deny', reason, source, extra, touches_secret)"""
    rules = rules or RULES
    decision, why, secret = check_rules(data)   # always computed, used for log redaction
    if rules != "off" and decision:
        extra = None
        if rules == "shadow" and use_laya:   # Laya gives its opinion but does not decide
            _, _, _, extra = laya_verdict(data, model_pref)
        return decision, why, "rules", extra, secret
    if not use_laya:
        return "pass", "(Laya disabled)", "laya-off", None, secret
    return (*laya_verdict(data, model_pref), secret)


def redact(s: str) -> str:
    return SECRET_CONTENT.sub("[REDACTED]", s)[:2000]


def log(data, decision, why, source, extra, secret):
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        rec = {"ts": time.time(), "tool": data.get("tool_name"), "decision": decision, "source": source,
               "reason": why,
               "laya": extra and {"choice": extra["choice"], "p_danger": extra["p_danger"], "model": extra["model"]},
               "input": None if secret else redact(json.dumps(data.get("tool_input"), ensure_ascii=False))}
        with open(STATE_DIR / "decisions.jsonl", "a") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main():
    data = json.load(sys.stdin)
    decision, why, source, extra, secret = decide(data)
    log(data, decision, why, source, extra, secret)
    if decision in ("ask", "deny"):
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": f"[laya-guard] {why}",
        }}, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
