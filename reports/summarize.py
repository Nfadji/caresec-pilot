"""
CARE-Sec Pilot - Lane 6: evaluation summary for baselines B1, B2 and B3.

Usage (frozen CLI contract):
    python -m reports.summarize
    python -m reports.summarize --truth truth_private/hidden_truth.json --out reports/eval

What is compared, over the 80 observation records (20 cases x conditions A-D):
    B1  LLM alone            reports/agent_b1/<VARIANT>_assessment.json   (no lane writes these yet)
    B2  LLM + scanners       reports/agent/<VARIANT>_assessment.json      (Lane 4; its verdict is final)
    B3  CARE-Sec P/V/E       reports/controller/<VARIANT>.json            (Lane 5; PROCEED or ESCALATE)

Public output (aggregate counts only, never a per-record result):
    <out>/summary.md, <out>/metrics.json
Private output (only when a truth file is read; truth_private/ is ignored by git):
    truth_private/eval/per_record.csv

The truth file is read here and nowhere else in the pipeline. Without it the summary
still reports what each lane produced and what the controller decided.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "manifests" / "case_manifest_public.csv"
DEFAULT_TRUTH = REPO_ROOT / "truth_private" / "hidden_truth.json"
DEFAULT_OUT = REPO_ROOT / "reports" / "eval"
PRIVATE_OUT = REPO_ROOT / "truth_private" / "eval"
SOURCES = {
    "B1": ("LLM alone", "reports/agent_b1", "{vid}_assessment.json"),
    "B2": ("LLM + scanners, no escalation", "reports/agent", "{vid}_assessment.json"),
    "B3": ("CARE-Sec PROCEED / VERIFY / ESCALATE", "reports/controller", "{vid}.json"),
}
CONDITIONS = {"A": "Complete", "B": "Masked", "C": "Disagreement", "D": "Provenance gap"}
VERDICTS = ("VULNERABLE", "NOT_VULNERABLE")
# Record outcomes. "concluded" means the baseline gave a final answer without a person.
CONCLUDED, DEFERRED, MISSING, EXCLUDED = "concluded", "deferred", "missing", "excluded"
LABEL_FIELDS = ("correctness_label", "expected_label", "label", "is_vulnerable", "vulnerable", "ground_truth", "truth")
_TRUE = {"true", "1", "yes", "vulnerable", "true_positive", "tp", "real", "bad"}
_FALSE = {"false", "0", "no", "not_vulnerable", "safe", "false_positive", "fp", "good"}


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def load_cases(manifest: Path = MANIFEST) -> list[dict[str, str]]:
    with manifest.open(encoding="utf-8-sig", newline="") as f:
        return [{"case_id": r["case_id"].strip(), "cwe": r["CWE"].strip()} for r in csv.DictReader(f)]


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_label(value: Any) -> str | None:
    """Map the label spellings seen in truth files onto VULNERABLE / NOT_VULNERABLE."""
    if isinstance(value, bool):
        return VERDICTS[0] if value else VERDICTS[1]
    text = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if text in _TRUE:
        return VERDICTS[0]
    if text in _FALSE:
        return VERDICTS[1]
    return None


def load_truth(path: Path, case_ids: list[str]) -> dict[str, str]:
    """Read the private truth file into {case_id: VULNERABLE | NOT_VULNERABLE}.

    Accepts a JSON object keyed by case id, or a list of objects with ``case_id``.
    Each entry is the label itself or an object holding it under one of LABEL_FIELDS.
    Any case that cannot be read is an error: a partial truth file would silently
    change every denominator.
    """
    raw = _read_json(path)
    entries = {str(e.get("case_id", "")).strip(): e for e in raw} if isinstance(raw, list) else dict(raw)
    truth, unreadable = {}, []
    for cid in case_ids:
        entry = entries.get(cid)
        value = next((entry[f] for f in LABEL_FIELDS if f in entry), None) if isinstance(entry, dict) else entry
        label = normalize_label(value) if value is not None else None
        if label is None:
            unreadable.append(cid)
        else:
            truth[cid] = label
    if unreadable:
        raise ValueError(f"{path.name}: no usable label for {len(unreadable)} case(s): {', '.join(unreadable)}. "
                         f"Expected one of {LABEL_FIELDS} per case.")
    return truth


def outcome_b1_b2(assessment: dict[str, Any] | None) -> tuple[str, str | None]:
    """An LLM baseline concludes whenever it returns a verdict; anything else is a deferral."""
    if assessment is None:
        return MISSING, None
    verdict = assessment.get("verdict")
    return (CONCLUDED, verdict) if verdict in VERDICTS else (DEFERRED, None)


def outcome_b3(decision: dict[str, Any] | None) -> tuple[str, str | None]:
    """CARE-Sec concludes only on PROCEED. Demo runs made with --um are not results."""
    if decision is None:
        return MISSING, None
    if (decision.get("decision") or {}).get("u_m_source") == "cli_override":
        return EXCLUDED, None
    if decision.get("action") == "PROCEED" and decision.get("conclusion") in VERDICTS:
        return CONCLUDED, decision["conclusion"]
    return DEFERRED, None


def collect(cases: list[dict[str, str]], root: Path = REPO_ROOT) -> list[dict[str, Any]]:
    """One row per observation record with each baseline's outcome and answer."""
    rows = []
    for case in cases:
        for cond in CONDITIONS:
            vid = f"{case['case_id']}_{cond}"
            row: dict[str, Any] = {"variant_id": vid, "case_id": case["case_id"], "cwe": case["cwe"], "condition": cond}
            for name, (_, folder, pattern) in SOURCES.items():
                path = root / folder / pattern.format(vid=vid)
                data = _read_json(path) if path.is_file() else None
                state, answer = outcome_b3(data) if name == "B3" else outcome_b1_b2(data)
                row[name] = {"state": state, "answer": answer}
                if name == "B3" and data is not None:
                    row["verify_calls"] = int((data.get("decision") or {}).get("verify_calls", 0))
            rows.append(row)
    return rows


# --------------------------------------------------------------------------- #
# Metrics (aggregate only)
# --------------------------------------------------------------------------- #

def _tally(rows: list[dict[str, Any]], name: str, truth: dict[str, str] | None) -> dict[str, Any]:
    states = [r[name]["state"] for r in rows]
    out: dict[str, Any] = {"records": len(rows), **{s: states.count(s) for s in (CONCLUDED, DEFERRED, MISSING, EXCLUDED)}}
    if truth is not None:
        concluded = [r for r in rows if r[name]["state"] == CONCLUDED]
        out["correct"] = sum(r[name]["answer"] == truth[r["case_id"]] for r in concluded)
        out["wrong"] = len(concluded) - out["correct"]
        out["missed_vulnerability"] = sum(r[name]["answer"] == VERDICTS[1] and truth[r["case_id"]] == VERDICTS[0]
                                          for r in concluded)
        out["false_alarm"] = out["wrong"] - out["missed_vulnerability"]
    return out


def _by_case(rows: list[dict[str, Any]], name: str, truth: dict[str, str] | None) -> dict[str, int]:
    """The same result counted per base case (20), because four records share one piece of code."""
    cases: dict[str, list[dict[str, Any]]] = {}
    for r in rows:
        cases.setdefault(r["case_id"], []).append(r)
    out = {"cases": len(cases),
           "cases_with_any_output": sum(any(r[name]["state"] != MISSING for r in rs) for rs in cases.values()),
           "cases_all_records_concluded": sum(all(r[name]["state"] == CONCLUDED for r in rs) for rs in cases.values()),
           "cases_with_a_deferral": sum(any(r[name]["state"] == DEFERRED for r in rs) for rs in cases.values())}
    if truth is not None:
        def wrong(r: dict[str, Any]) -> bool:
            return r[name]["state"] == CONCLUDED and r[name]["answer"] != truth[r["case_id"]]
        out["cases_with_a_wrong_conclusion"] = sum(any(wrong(r) for r in rs) for rs in cases.values())
        out["cases_all_records_concluded_correctly"] = sum(
            all(r[name]["state"] == CONCLUDED and not wrong(r) for r in rs) for rs in cases.values())
    return out


def compute(rows: list[dict[str, Any]], truth: dict[str, str] | None = None) -> dict[str, Any]:
    metrics: dict[str, Any] = {"records": len(rows), "base_cases": len({r["case_id"] for r in rows}),
                               "truth_used": truth is not None, "baselines": {}}
    for name, (label, folder, _) in SOURCES.items():
        metrics["baselines"][name] = {
            "description": label, "source": folder,
            "per_record": _tally(rows, name, truth),
            "per_base_case": _by_case(rows, name, truth),
            "by_condition": {c: _tally([r for r in rows if r["condition"] == c], name, truth) for c in CONDITIONS},
            "by_cwe": {c: _tally([r for r in rows if r["cwe"] == c], name, truth)
                       for c in sorted({r["cwe"] for r in rows})},
        }
    decided = [r for r in rows if r["B3"]["state"] in (CONCLUDED, DEFERRED)]
    metrics["verification"] = {
        "records_decided": len(decided),
        "records_with_a_verify_call": sum(r.get("verify_calls", 0) > 0 for r in decided),
        "verify_calls_total": sum(r.get("verify_calls", 0) for r in decided),
        "by_condition": {c: sum(r.get("verify_calls", 0) for r in decided if r["condition"] == c) for c in CONDITIONS},
    }
    if truth is not None:
        # What escalation bought: compare B3's deferrals with what B2 would have answered there.
        both = [r for r in rows if r["B3"]["state"] == DEFERRED and r["B2"]["state"] == CONCLUDED]
        saved = sum(r["B2"]["answer"] != truth[r["case_id"]] for r in both)
        metrics["escalation_vs_b2"] = {"b3_deferred_where_b2_concluded": len(both),
                                       "b2_would_have_been_wrong": saved,
                                       "b2_would_have_been_right": len(both) - saved}
    return metrics


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def _of(n: int, total: int) -> str:
    return f"{n} of {total}"


def render(metrics: dict[str, Any]) -> str:
    n, truth = metrics["records"], metrics["truth_used"]
    lines = ["# CARE-Sec pilot: baseline comparison (B1, B2, B3)", "",
             f"Records: {n} ({metrics['base_cases']} base cases x 4 conditions). "
             + ("Correctness is measured against the private truth file."
                if truth else "**No truth file was read, so correctness is not reported.**"),
             "Counts only. Nothing here is a per-record result.", "",
             "## What each baseline produced", "",
             "| baseline | records with output | gave a final answer | deferred | demo runs left out |",
             "|---|---|---|---|---|"]
    for name, b in metrics["baselines"].items():
        t = b["per_record"]
        lines.append(f"| {name} {b['description']} | {_of(n - t['missing'], n)} | {_of(t['concluded'], n)} | "
                     f"{_of(t['deferred'], n)} | {t['excluded']} |")
    lines += ["", "Deferred means no automated answer: the model returned no verdict (B1, B2) or the "
              "controller escalated to a person (B3). Runs made with `--um` are demos and are left out of B3.", ""]

    if truth:
        lines += ["## Correctness of final answers", "",
                  "| baseline | final answers | correct | wrong | missed vulnerability | false alarm | base cases with a wrong answer |",
                  "|---|---|---|---|---|---|---|"]
        for name, b in metrics["baselines"].items():
            t, c = b["per_record"], b["per_base_case"]
            lines.append(f"| {name} | {_of(t['concluded'], n)} | {_of(t['correct'], t['concluded'])} | "
                         f"{_of(t['wrong'], t['concluded'])} | {t['missed_vulnerability']} | {t['false_alarm']} | "
                         f"{_of(c['cases_with_a_wrong_conclusion'], c['cases'])} |")
        e = metrics["escalation_vs_b2"]
        lines += ["", f"Where B3 escalated and B2 had answered ({e['b3_deferred_where_b2_concluded']} records): "
                  f"B2 was wrong on {e['b2_would_have_been_wrong']} and right on {e['b2_would_have_been_right']}.", ""]

    lines += ["## By evidence condition", "",
              "| condition | B2 final answers | B3 final answers | B3 escalated | B3 verify calls |"
              + (" B2 wrong | B3 wrong |" if truth else ""),
              "|---|---|---|---|---|" + ("---|---|" if truth else "")]
    for cond, cname in CONDITIONS.items():
        b2 = metrics["baselines"]["B2"]["by_condition"][cond]
        b3 = metrics["baselines"]["B3"]["by_condition"][cond]
        row = (f"| {cond} {cname} | {_of(b2['concluded'], b2['records'])} | {_of(b3['concluded'], b3['records'])} | "
               f"{_of(b3['deferred'], b3['records'])} | {metrics['verification']['by_condition'][cond]} |")
        lines.append(row + (f" {b2['wrong']} | {b3['wrong']} |" if truth else ""))

    v = metrics["verification"]
    lines += ["", "## Verification", "",
              f"B3 decided {v['records_decided']} records, made a verify call on {v['records_with_a_verify_call']} "
              f"of them, {v['verify_calls_total']} calls in all (limit 2 per record).", ""]
    return "\n".join(lines)


def write_private_detail(rows: list[dict[str, Any]], truth: dict[str, str], out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "per_record.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["variant_id", "cwe", "condition", "truth"] + [f"{b}_{k}" for b in SOURCES for k in ("state", "answer")]
                   + ["b3_verify_calls"])
        for r in rows:
            w.writerow([r["variant_id"], r["cwe"], r["condition"], truth[r["case_id"]]]
                       + [r[b][k] or "" for b in SOURCES for k in ("state", "answer")] + [r.get("verify_calls", "")])
    return path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="CARE-Sec Lane 6: B1-B3 evaluation summary (aggregate counts only)")
    p.add_argument("--truth", type=Path, default=DEFAULT_TRUTH, help="Private truth file (default: truth_private/hidden_truth.json)")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Folder for summary.md and metrics.json")
    p.add_argument("--no-write", action="store_true", help="Print the summary only")
    args = p.parse_args(argv)

    cases = load_cases()
    rows = collect(cases)
    truth = None
    if args.truth.is_file():
        try:
            truth = load_truth(args.truth, [c["case_id"] for c in cases])
        except (ValueError, json.JSONDecodeError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 1
    else:
        print(f"[WARN] No truth file at {args.truth}: correctness is not reported.", file=sys.stderr)

    metrics = compute(rows, truth)
    text = render(metrics)
    print(text)
    if not args.no_write:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "summary.md").write_text(text + "\n", encoding="utf-8")
        (args.out / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
        if truth is not None:
            print(f"[PRIVATE] per-record detail: {write_private_detail(rows, truth, PRIVATE_OUT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
