#!/usr/bin/env python3
"""Run examples/examples.jsonl through the guard and report accuracy.

  python3 scripts/eval.py                         # rules + Laya on the grey zone (what the hook does)
  python3 scripts/eval.py --rules off             # Laya ONLY, on every example
  python3 scripts/eval.py --rules shadow          # rules decide, Laya's verdict shown alongside
  python3 scripts/eval.py --no-laya               # rules only
  python3 scripts/eval.py --model multilingual    # force a checkpoint (english | multilingual | auto)
  python3 scripts/eval.py --file my_examples.jsonl
  python3 scripts/eval.py -v                      # also print the reason of every decision
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
DEFAULT_CWD = "/tmp/demo-project"   # the project the hand-written examples pretend to run in
import guard  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("--rules", choices=["on", "off", "shadow"], default="on")
ap.add_argument("--model", choices=["auto", "english", "multilingual"], default=None)
ap.add_argument("--no-laya", action="store_true")
ap.add_argument("--file", default=str(ROOT / "examples" / "examples.jsonl"))
ap.add_argument("-v", "--verbose", action="store_true", help="print the reason of every decision")
a = ap.parse_args()

TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def paint(s: str, code: str) -> str:
    return f"\033[{code}m{s}\033[0m" if TTY else s


GREEN, RED, YELLOW, DIM, BOLD = "32", "31", "33", "2", "1"


def label(decision: str) -> str:
    return "routine" if decision == "pass" else "dangerous"


def laya_label(extra: dict) -> str:
    p = extra["p_danger"]
    return "routine" if extra["choice"] == "B" and p is not None and 1 - p >= guard.THRESHOLD else "dangerous"


def bar(p: float, width: int = 10) -> str:
    n = round(p * width)
    return "█" * n + "·" * (width - n)


def auc(pos: list[float], neg: list[float]) -> float | None:
    if not pos or not neg:
        return None
    return sum((p > n) + 0.5 * (p == n) for p in pos for n in neg) / (len(pos) * len(neg))


examples = [json.loads(line) for line in Path(a.file).read_text().splitlines() if line.strip()]
use_laya = not a.no_laya
if use_laya:
    if TTY:
        print(paint("waiting for laya-serve...", DIM), end="\r", flush=True)
    up = guard.ensure_server(120)   # more patience than the hook: a cold start loads the models
    if TTY:
        print(" " * 40, end="\r")
    if not up:
        print(paint(f"laya-serve is not responding on port {guard.PORT}; Laya results will be errors", YELLOW))

print(paint(f"rules={a.rules}  model={a.model or guard.MODEL}  threshold P(routine)>={guard.THRESHOLD}  "
            f"file={Path(a.file).name}", DIM))
print(paint(f"   {'expected':9} {'guard':6} {'by':8} {'example':44} {'Laya P(danger)':22}", BOLD))

rows = []
for ex in examples:
    cwd = ex.get("cwd") or DEFAULT_CWD
    os.environ["CLAUDE_PROJECT_DIR"] = cwd   # guard.project_dir() reads it on every call
    data = {"tool_name": ex["tool_name"], "tool_input": ex["tool_input"], "cwd": cwd}
    decision, why, source, extra, _ = guard.decide(data, use_laya=use_laya, rules=a.rules, model_pref=a.model)
    counted = source != "laya-off"
    hit = label(decision) == ex["expected"]
    rows.append({"ex": ex, "decision": decision, "why": why, "source": source, "extra": extra,
                 "counted": counted, "hit": hit})

    mark = paint("·", DIM) if not counted else (paint("✓", GREEN) if hit else paint("✗", RED))
    exp = paint(f"{ex['expected'][:9]:9}", RED if ex["expected"] == "dangerous" else GREEN)
    dec = paint(f"{decision:6}", {"pass": GREEN, "ask": YELLOW, "deny": RED}.get(decision, ""))
    col = ""
    if extra and extra["p_danger"] is not None:
        p, lhit = extra["p_danger"], laya_label(extra) == ex["expected"]
        col = f"{p:.2f} {bar(p)} {extra['model'][:2]} " + (paint("✓", GREEN) if lhit else paint("✗", RED))
    elif source == "error":
        col = paint(why[:60], YELLOW)
    print(f" {mark} {exp} {dec} {source:8} {ex['note'][:44]:44} {col}")
    if a.verbose and source != "error":
        print(paint(f"{'':28}{why}", DIM))

# ---------------------------------------------------------------- summary
counted = [r for r in rows if r["counted"]]
errors = [r for r in rows if r["source"] == "error"]
dang = [r for r in counted if r["ex"]["expected"] == "dangerous"]
rout = [r for r in counted if r["ex"]["expected"] == "routine"]
missed = [r for r in dang if not r["hit"]]      # dangerous that passed: the costly mistake
nagged = [r for r in rout if not r["hit"]]      # routine that asked: annoying, not harmful

print()
ok = sum(r["hit"] for r in counted)
print(paint(f"guard: {ok}/{len(counted)} correct", BOLD)
      + f"   dangerous caught {len(dang) - len(missed)}/{len(dang)}"
      + f"   routine passed {len(rout) - len(nagged)}/{len(rout)}"
      + (paint(f"   errors {len(errors)}", YELLOW) if errors else ""))
for src in sorted({r["source"] for r in counted}):
    sub = [r for r in counted if r["source"] == src]
    print(paint(f"  by {src:8} {sum(r['hit'] for r in sub)}/{len(sub)}", DIM))
if missed:
    print(paint("  dangerous actions that PASSED:", RED))
    for r in missed:
        print(f"    - {r['ex']['note']}  ({r['why']})")
if nagged:
    print(paint("  routine actions that were stopped:", YELLOW))
    for r in nagged:
        print(f"    - {r['ex']['note']}  ({r['source']}: {r['why'][:70]})")

scored = [r for r in rows if r["extra"] and r["extra"]["p_danger"] is not None]
if scored:
    lok = sum(laya_label(r["extra"]) == r["ex"]["expected"] for r in scored)
    pos = [r["extra"]["p_danger"] for r in scored if r["ex"]["expected"] == "dangerous"]
    neg = [r["extra"]["p_danger"] for r in scored if r["ex"]["expected"] == "routine"]
    auc_v = auc(pos, neg)
    print()
    print(paint(f"Laya:  {lok}/{len(scored)} correct on the examples it saw", BOLD)
          + (f"   AUC {auc_v:.2f}" if auc_v is not None else ""))
    if pos and neg:
        print(paint(f"  P(danger) routine max {max(neg):.2f} | dangerous min {min(pos):.2f}"
                    f"  (separable if routine max < dangerous min)", DIM))
