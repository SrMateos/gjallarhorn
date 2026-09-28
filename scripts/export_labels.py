#!/usr/bin/env python3
"""Turn the user's answers to laya-guard's questions into labelled examples.

Every "ask" in decisions.jsonl is matched by tool_use_id against ran.jsonl (written by the PostToolUse
hook):
  - the call ran        -> the user approved it -> "routine"
  - the call never ran  -> the user rejected it (or interrupted the session) -> "dangerous"

The output has the examples.jsonl format, so it can go straight into eval.py:

  python3 scripts/export_labels.py                    # writes ~/.cache/laya-guard/labelled.jsonl
  python3 scripts/eval.py --file ~/.cache/laya-guard/labelled.jsonl --rules off

User answers are noisy labels (approval fatigue, rejecting an approach rather than a danger): review
them before fine-tuning. The file holds your real commands, so do not commit it.
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import guard  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--out", default=str(guard.STATE_DIR / "labelled.jsonl"))
ap.add_argument("--min-age", type=float, default=120,
                help="skip asks younger than this many seconds: the user may not have answered yet")
a = ap.parse_args()


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return out


ran_log = read_jsonl(guard.STATE_DIR / "ran.jsonl")
ran = {r["tool_use_id"] for r in ran_log if r.get("tool_use_id")}
ran_ids = set(ran)
decisions = read_jsonl(guard.STATE_DIR / "decisions.jsonl")
# Sessions where the PostToolUse hook was active. In the others (started before the hook existed)
# nothing is recorded, so every ask would look rejected. SessionStart marks them in sessions.jsonl;
# sessions from before that marker count if at least one of their calls shows up in ran.jsonl.
hooked = {r.get("session_id") for r in read_jsonl(guard.STATE_DIR / "sessions.jsonl")}
hooked |= {r.get("session_id") for r in decisions if r.get("tool_use_id") in ran_ids}
now = time.time()
seen, examples = set(), []
skipped = {"no tool_use_id": 0, "session without the PostToolUse hook": 0, "secret (input not logged)": 0,
           "input truncated": 0, "too recent": 0}
for r in decisions:
    if r.get("decision") != "ask":
        continue
    tid = r.get("tool_use_id")
    if not tid:
        skipped["no tool_use_id"] += 1   # logged before this feature existed
        continue
    if tid in seen:
        continue
    if r.get("session_id") not in hooked:
        skipped["session without the PostToolUse hook"] += 1
        continue
    if r.get("input") is None:
        skipped["secret (input not logged)"] += 1
        continue
    if now - r["ts"] < a.min_age and tid not in ran:
        skipped["too recent"] += 1
        continue
    try:
        tool_input = json.loads(r["input"])
    except json.JSONDecodeError:
        skipped["input truncated"] += 1
        continue
    seen.add(tid)
    approved = tid in ran
    action = tool_input.get("command") if r["tool"] == "Bash" else guard.describe(r["tool"], tool_input)
    examples.append({
        "expected": "routine" if approved else "dangerous",
        "note": f"{'approved' if approved else 'rejected'}: {' '.join(str(action).split())[:80]}",
        "tool_name": r["tool"], "tool_input": tool_input, "cwd": r.get("cwd"),
        "asked_by": r["source"], "p_danger": (r.get("laya") or {}).get("p_danger"),
    })

out = Path(a.out).expanduser()
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text("".join(json.dumps(e, ensure_ascii=False) + "\n" for e in examples))
approved = sum(e["expected"] == "routine" for e in examples)
print(f"{len(examples)} labelled examples -> {out}  (approved {approved}, rejected {len(examples) - approved})")
for why, n in skipped.items():
    if n:
        print(f"  skipped {n}: {why}")
