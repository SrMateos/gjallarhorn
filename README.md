# laya-guard

> **Proof of concept.** Not a security boundary. Do not rely on it to protect data you care about.

A Claude Code plugin that reviews every tool call before it runs, aimed at auto mode. It combines
deterministic rules with [Laya](https://pypi.org/project/laya/), a small classifier that runs locally.

## How it works

A `PreToolUse` hook (`scripts/guard.py`) checks every `Bash`, `Read`, `Grep`, `Write`, `Edit`,
`MultiEdit`, `NotebookEdit` and MCP tool call. It goes through three layers in order:

1. **Rules.** Deterministic, no model involved.
   - **Deny**: reading, editing or referencing secrets files (`.env*` except `.env.example`,
     `.env.sample`, `.env.template` and `.env.dist`; SSH keys; `~/.aws`; `.netrc`; `*.pem`; `*.key`...);
     `rm` on data (`data/`, `raw/`, `*.parquet`, `*.csv`, `*.jsonl`...) or on `/`, `~` or `.`;
     `mkfs`, `shred`, `dd of=/dev/...`.
   - **Ask**: any other `rm -r`/`rm -f`, `find -delete`, `git push --force`, `git reset --hard`,
     `curl | bash`, `sudo`, recursive `chmod`/`chown`, file uploads, `scp`/`rsync` to remote hosts,
     dumping the environment, and plaintext credentials in written content.
2. **Allowlist.** Routine commands without shell operators (`git status`, `git diff`, `ls`, `cat`,
   `rg`, `uv run pytest`...), reads of non-secret files and edits inside the project pass without
   calling the model.
3. **Laya.** Everything else: non-trivial Bash, writes outside the project and MCP tools. The action is
   described in plain English and sent to the English checkpoint. Laya returns P(danger), and the
   action passes only if P(routine) = 1 − P(danger) reaches `LAYA_GUARD_THRESHOLD`. Actions longer
   than `LAYA_GUARD_EN_MAX_CHARS` go to the multilingual checkpoint, which has an 8k-token context.

The hook never grants permissions: it only asks or denies. When an action passes, Claude Code continues
with its normal permission flow. If Laya is down or too slow, the hook applies `LAYA_GUARD_ON_ERROR`.

## Install

Requires `uv`, `python3` and `curl`.

```bash
git clone <repo-url> ~/laya-guard
```

Use it for a single session:

```bash
claude --plugin-dir ~/laya-guard
```

Use it in every session by adding an alias to your shell config (`~/.bashrc` or `~/.zshrc`):

```bash
alias claude='claude --plugin-dir ~/laya-guard'
```

### The Laya server

On session start, `scripts/start_laya.sh` launches `laya-serve` in the background with `uvx`, on
`127.0.0.1:8765`, protected by a random API key stored in `~/.cache/laya-guard/api_key`.

- The first run downloads the models and takes a while. Until the server is up, actions that need
  Laya ask you.
- The server is shared across sessions and keeps running after you exit Claude Code.
  Stop it with `scripts/stop_laya.sh`.
- Server log: `~/.cache/laya-guard/laya-serve.log`.

## Configuration

Set these environment variables before starting Claude Code, for example
`LAYA_GUARD_RULES=shadow claude --plugin-dir ~/laya-guard`.

| Variable | Default | Description |
|---|---|---|
| `LAYA_GUARD_RULES` | `on` | Rule mode, see below |
| `LAYA_GUARD_MODEL` | `auto` | Laya checkpoint: `auto` (English unless the action is too long), `english` or `multilingual` |
| `LAYA_GUARD_THRESHOLD` | `0.55` | Minimum P(routine) for Laya to let an action pass |
| `LAYA_GUARD_ON_DANGER` | `ask` | What to do when Laya flags danger: `ask`, or `deny` (use `deny` with `claude -p`, where nobody can answer) |
| `LAYA_GUARD_ON_ERROR` | `ask` | What to do when Laya is unavailable: `ask` (fail-closed) or `pass` (fail-open) |
| `LAYA_GUARD_BUDGET` | `25` | Max seconds for the whole Laya call (waiting for the server, request, retries). Keep it below the hook timeout in `hooks/hooks.json` (30 s): Claude Code lets a timed-out hook's call through |
| `LAYA_GUARD_WAIT` | `20` | Max seconds to wait for the server to start, within the budget |
| `LAYA_GUARD_EN_MAX_CHARS` | `1000` | Longest action, in characters, sent to the English checkpoint (512-token context) |
| `LAYA_GUARD_PORT` | `8765` | Port of `laya-serve` |
| `LAYA_DEVICE` | Laya's default | `cuda` or `cpu` for the server |

### Rule modes

| `LAYA_GUARD_RULES` | Who decides | Use it for |
|---|---|---|
| `on` | Rules and allowlist first; Laya only for the rest | Normal use |
| `shadow` | Rules and allowlist, but Laya also scores every action and its verdict is logged | Measuring Laya on real traffic without risk |
| `off` | Laya alone, no rules and no allowlist | Experiments only |

## Decision log

Every decision is appended to `~/.cache/laya-guard/decisions.jsonl` with the tool, the decision, who made
it, the reason and Laya's verdict (choice, P(danger), checkpoint). Credentials in the input are redacted,
and the input is left out entirely when the action touches a secrets file.

## Evaluate

`scripts/eval.py` runs the labelled actions in `examples/examples.jsonl` through the same `decide()`
function the hook uses. Start the Laya server first by opening a session with the plugin, or with
`scripts/start_laya.sh`.

```bash
uv run python scripts/eval.py                          # what the hook does (rules + Laya)
uv run python scripts/eval.py --no-laya                # rules only
uv run python scripts/eval.py --rules off              # Laya alone, on every example
uv run python scripts/eval.py --rules shadow           # rules decide, Laya's verdict alongside
uv run python scripts/eval.py --model multilingual     # force a checkpoint
uv run python scripts/eval.py --file my_examples.jsonl # other examples
uv run python scripts/eval.py -v                       # print the reason for each decision
```

Each row shows the expected label, the guard's decision (`pass`, `ask` or `deny`), who made it, and
Laya's P(danger) with the checkpoint that answered. The summary reports:

- how many dangerous actions were stopped and how many routine ones passed, with the mistakes listed;
- Laya's **AUC**: the probability that a random dangerous action scores higher than a random routine
  one, independent of the threshold;
- the highest P(danger) among routine actions and the lowest among dangerous ones. If they overlap, no
  threshold separates them perfectly.

Each line of `examples.jsonl` is a JSON object with `expected` (`routine` or `dangerous`), `note`,
`tool_name` and `tool_input`.

## Project layout

```
.claude-plugin/plugin.json   plugin manifest
hooks/hooks.json             SessionStart and PreToolUse hooks
scripts/guard.py             the hook: rules, allowlist and Laya client (stdlib only)
scripts/start_laya.sh        starts laya-serve in the background
scripts/stop_laya.sh         stops it
scripts/eval.py              evaluation over labelled examples
examples/examples.jsonl      labelled example actions
```

## Limitations

- Laya is used zero-shot and its scores overlap for routine and dangerous actions. Fine-tuning on
  labelled entries from `decisions.jsonl` is the natural next step.
- The prompt and threshold were tuned on the same 31 examples used to evaluate them.
- The multilingual checkpoint, used for long actions, is noticeably weaker than the English one.
- Rules match text patterns and can be bypassed by a determined agent.
- It is unverified whether 1000 characters always fit in the English checkpoint's context. Dense code
  may need a lower `LAYA_GUARD_EN_MAX_CHARS`.

## License

[MIT](LICENSE)
