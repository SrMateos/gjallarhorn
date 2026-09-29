# Gjallarhorn

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
`tool_name`, `tool_input` and, optionally, `cwd` (the project directory, `/tmp/demo-project` by default).

## Learning from your answers

Laya is weak zero-shot: its own documentation calls it "a fast base to specialise, not a zero-shot
decision engine". The plugin records how you answer each time it asks, so you can build a labelled
dataset from real use and fine-tune Laya on it.

### How your answer is recorded

Claude Code does not pass your answer to hooks, so the plugin infers it from whether the call ran:

```
SessionStart  ->  sessions.jsonl    this session has the hooks below
PreToolUse    ->  decisions.jsonl   the guard's decision ("ask", "pass", "deny") and the call's ID
   ... Claude Code asks you: approve or reject ...
PostToolUse   ->  ran.jsonl         the call's ID, only if it actually ran
```

For every call the guard asked about:

| In `ran.jsonl`? | Your answer | Label |
|---|---|---|
| Yes | approved | `routine` |
| No | rejected (or you interrupted the session) | `dangerous` |

All files live in `~/.cache/laya-guard/`. Credentials in `decisions.jsonl` are redacted, and the input is
left out entirely when the action touches a secrets file, so those actions never become labels.

### Export the labels

```bash
python3 ~/laya-guard/scripts/export_labels.py
```

It writes `~/.cache/laya-guard/labelled.jsonl`, one line per answered question, in the same format as
`examples/examples.jsonl`:

```json
{"expected": "routine", "note": "approved: git status && git log", "tool_name": "Bash",
 "tool_input": {"command": "git status && git log"}, "cwd": "/home/you/project",
 "asked_by": "laya", "p_danger": 0.49}
```

`expected` is your answer, `asked_by` says whether the rules or Laya asked, and `p_danger` is Laya's
score at the time. Questions from the last 2 minutes are skipped in case you have not answered yet
(`--min-age` changes it). The file contains your real commands: do not commit it.

Check Laya against your answers:

```bash
uv run python scripts/eval.py --file ~/.cache/laya-guard/labelled.jsonl --rules off
```

### Fine-tune Laya

From least to most effort:

1. **Tune the threshold.** Run the eval above and pick the `LAYA_GUARD_THRESHOLD` that best separates
   your approvals from your rejections. Works with a few dozen labels.
2. **Train a small head on the frozen model.** [stuntd](https://github.com/bladedevoff/stuntd), linked
   from Laya's documentation, trains a decision head on your labelled rows and needs far less data and
   compute than a full fine-tune.
3. **Full fine-tune.** Laya's
   [fine-tuning notebook](https://github.com/NandhaKishorM/laya/blob/main/notebooks/laya_finetune_typed_decisions_2xT4_kaggle.ipynb)
   runs the whole loop on Kaggle's free 2x T4 GPUs: build the dataset, train, fit calibration
   temperatures and evaluate. For reference, 4 epochs over ~30k questions take about 4 to 5 hours.

This plugin does not yet convert `labelled.jsonl` to the notebook's dataset format or load a custom
checkpoint in `laya-serve`; see the [Laya model card](https://huggingface.co/convaiinnovations/laya)
for both. Before training:

- **Collect enough data.** A few test sessions are not enough; you need hundreds of labels from real use.
- **Balance the classes.** In normal use you approve most questions. The hand-written
  `examples/examples.jsonl` can add dangerous cases.
- **Review the labels.** You may approve out of fatigue, or reject a harmless command because of what
  Claude was about to do next.
- **Evaluate on held-out data.** Never measure on the examples you trained on; for instance, train on
  `labelled.jsonl` and evaluate on `examples/examples.jsonl`.

## Project layout

```
.claude-plugin/plugin.json   plugin manifest
hooks/hooks.json             SessionStart, PreToolUse and PostToolUse hooks
scripts/guard.py             the hook: rules, allowlist and Laya client (stdlib only)
scripts/export_labels.py     turns your answers to the guard's questions into labelled examples
scripts/start_laya.sh        starts laya-serve in the background
scripts/stop_laya.sh         stops it
scripts/eval.py              evaluation over labelled examples
examples/examples.jsonl      labelled example actions
```

## Limitations

- Laya is used zero-shot and its scores overlap for routine and dangerous actions, especially on long
  compound commands. See [Learning from your answers](#learning-from-your-answers).
- The prompt and threshold were tuned on the same 31 examples used to evaluate them.
- The multilingual checkpoint, used for long actions, is noticeably weaker than the English one.
- Rules match text patterns and can be bypassed by a determined agent.
- It is unverified whether 1000 characters always fit in the English checkpoint's context. Dense code
  may need a lower `LAYA_GUARD_EN_MAX_CHARS`.

## License

[MIT](LICENSE)
