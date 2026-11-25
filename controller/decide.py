"""
CARE-Sec Pilot - Lane 5: PROCEED / VERIFY / ESCALATE decision controller.

Usage (frozen CLI contract):
    python -m controller.decide --run CASE_01_A
    python -m controller.decide --starter                 # CASE_01..05, condition A
    python -m controller.decide --all                     # all 20 cases, condition A
    python -m controller.decide --all --conditions ABCD   # all 80 observation records

Inputs (read-only):
    reports/ledger/<CASE>_A.json              Lane 3 Evidence Ledger (condition A)
    reports/ledger/scanner_evidence.json      Lane 3 evidence, fed to Lane 2's variants.build for B/C/D
    reports/agent/<VARIANT>_assessment.json   Lane 4 assessment (verdict, u_M, u_E), if present
    scanners.verify_hooks.call_hook           Lane 3 read-only hooks, max 2 calls per record

Output:
    reports/controller/<VARIANT>.json         ledger record + u_m_level, u_e_level, action, decision trace
    reports/controller/summary.md             one-row-per-record table
    (--update-ledger also writes action/u-levels/trace back into reports/ledger/<VARIANT>.json)

Policy (pilot deck, slide 17; rule-based engineering baseline, not calibrated):
    1. u_M HIGH                                   -> ESCALATE (more evidence cannot fix model competence)
    2. no evidence gaps and u_M LOW               -> PROCEED
    3. a gap has an unused read-only hook, budget -> VERIFY, re-evaluate
    4. otherwise (gap unresolved, budget spent,
       u_M MEDIUM, or no validated model output)  -> ESCALATE with reviewer packet
The controller never reads truth_private/ or hidden labels.
"""

from __future__ import annotations

import argparse
import contextlib
import functools
import io
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_DIR = REPO_ROOT / "reports" / "ledger"
AGENT_DIR = REPO_ROOT / "reports" / "agent"
OUT_DIR = REPO_ROOT / "reports" / "controller"
MANIFEST = REPO_ROOT / "manifests" / "case_manifest_public.csv"
SCANNER_EVIDENCE = LEDGER_DIR / "scanner_evidence.json"

POLICY_VERSION = "lane5-rules-v1"
MAX_VERIFY_STEPS = 2
LEVELS = ("LOW", "MEDIUM", "HIGH")
SCANNERS = ("semgrep", "codeql")
CONDITION_NAMES = {"A": "A_COMPLETE", "B": "B_MASKED", "C": "C_DISAGREEMENT", "D": "D_PROVENANCE_GAP"}

# Which read-only hook can help with which evidence gap, in order of preference.
# Hooks not exposed by scanners.verify_hooks.HOOKS are skipped. Lane 3 currently has no
# CodeQL hook (CodeQL runs from pre-built SARIF), so CodeQL gaps end in ESCALATE until a
# read-only "reload_codeql_sarif" hook exists; the controller picks it up automatically.
RESOLVERS: dict[str, list[str]] = {
    "codeql_missing": ["reload_codeql_sarif"],
    "codeql_failed": ["reload_codeql_sarif"],
    "codeql_provenance": ["reload_codeql_sarif"],
    "semgrep_missing": ["rerun_pinned_semgrep"],
    "semgrep_failed": ["rerun_pinned_semgrep"],
    "semgrep_provenance": ["rerun_pinned_semgrep"],
    "source_masked": ["fetch_code_slice"],
    # A disagreement is first re-checked, then the disputed code is attached for the reviewer.
    "scanner_conflict": ["rerun_pinned_semgrep", "inspect_enclosing_method"],
}


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #

def parse_variant_id(variant_id: str) -> tuple[str, str]:
    vid = variant_id.strip().upper()
    case_id, _, cond = vid.rpartition("_")
    if not case_id.startswith("CASE_") or cond not in CONDITION_NAMES:
        raise ValueError(f"Invalid variant id '{variant_id}': expected CASE_NN_[A-D].")
    return case_id, cond


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


@functools.lru_cache(maxsize=1)
def _lane2_variants() -> tuple[dict[str, Any], ...]:
    """Build all B/C/D records once with Lane 2's generator (its hash warnings are muted)."""
    from variants.build import build  # Lane 2 generator, reused as-is

    with contextlib.redirect_stdout(io.StringIO()):
        return tuple(build(MANIFEST, SCANNER_EVIDENCE if SCANNER_EVIDENCE.is_file() else None))


def load_record(variant_id: str) -> dict[str, Any]:
    """Return an agent-visible ledger record for one observation variant.

    Condition A is the Lane 3 ledger file. B/C/D are derived in memory with Lane 2's
    ``variants.build`` from the same scanner evidence, so the controller sees exactly
    what that condition is allowed to show.
    """
    case_id, cond = parse_variant_id(variant_id)
    base_path = LEDGER_DIR / f"{case_id}_A.json"
    if not base_path.is_file():
        raise FileNotFoundError(f"No Evidence Ledger record at {base_path} (run `python -m scanners.run`).")
    base = _read_json(base_path)
    if cond == "A":
        return base

    variants = _lane2_variants()
    vid = f"{case_id}_{cond}"
    var = next((v for v in variants if v["record_id"] == vid), None)
    if var is None:
        raise KeyError(f"variants.build produced no record {vid}")
    ev = var.get("evidence") or {}
    rec = {k: v for k, v in base.items() if k not in SCANNERS}
    rec.update({
        "variant_id": vid,
        "evidence_condition": CONDITION_NAMES[cond],
        "variant_status": var.get("variant_status"),
        "semgrep": ev.get("semgrep"),
        "codeql": ev.get("codeql"),
    })
    for extra in ("masked_fields", "removed_provenance_fields"):
        if extra in var:
            rec[extra] = var[extra]
    return rec


def load_assessment(variant_id: str) -> dict[str, Any] | None:
    """Lane 4 output (``reports/agent/<VARIANT>_assessment.json``), or None if absent."""
    for name in (f"{variant_id}_assessment.json", f"{variant_id}.json"):
        path = AGENT_DIR / name
        if path.is_file():
            return _read_json(path)
    return None


def _level(value: Any) -> str:
    return value if value in LEVELS else "UNSET"


def agent_signals(assessment: dict[str, Any] | None) -> dict[str, Any]:
    """Normalize Lane 4's assessment into the fields the policy uses."""
    if not assessment:
        return {"u_m": "UNSET", "u_e": "UNSET", "verdict": None, "status": "NO_ASSESSMENT_FILE"}
    return {
        "u_m": _level((assessment.get("u_m") or {}).get("u_m_level")),
        "u_e": _level((assessment.get("u_e") or {}).get("u_e_level")),
        "verdict": assessment.get("verdict"),
        "status": assessment.get("assessment_status", "UNKNOWN"),
    }


# --------------------------------------------------------------------------- #
# Evidence state (u_E proxy) and policy
# --------------------------------------------------------------------------- #

def evidence_gaps(rec: dict[str, Any], verdict: str | None = None) -> list[str]:
    """List what is missing, failed, unattributed or contradictory in the record."""
    gaps: list[str] = []
    statuses = {}
    for s in SCANNERS:
        r = rec.get(s)
        if not isinstance(r, dict) or not r.get("status"):
            gaps.append(f"{s}_missing")
            continue
        status = r["status"]
        if status == "tool_failed":
            gaps.append(f"{s}_failed")
            continue
        statuses[s] = status
        if not r.get("version") or (status == "finding" and not r.get("rule_id")):
            gaps.append(f"{s}_provenance")
    if len(statuses) == 2 and len(set(statuses.values())) == 2:
        gaps.append("scanner_conflict")
    if rec.get("source_available") is False:
        gaps.append("source_masked")
    if rec.get("manifest_hash_match") == "mismatch":
        gaps.append("source_integrity")
    # Lane 4 verdict that contradicts unanimous scanners is a material discrepancy.
    if verdict and len(statuses) == 2 and len(set(statuses.values())) == 1:
        consensus = next(iter(statuses.values()))
        if (verdict == "VULNERABLE" and consensus == "no_finding") or (
            verdict == "NOT_VULNERABLE" and consensus == "finding"
        ):
            gaps.append("agent_scanner_conflict")
    if verdict == "INSUFFICIENT_EVIDENCE":
        gaps.append("agent_insufficient_evidence")
    return gaps


def u_e_level(gaps: list[str]) -> str:
    return "LOW" if not gaps else ("MEDIUM" if len(gaps) == 1 else "HIGH")


def next_hook(gaps: list[str], used: list[str], available: frozenset[str] | None = None) -> tuple[str, str] | None:
    """First (gap, hook) pair whose hook exists and has not been tried yet."""
    for gap in gaps:
        for hook in RESOLVERS.get(gap, []):
            if hook not in used and (available is None or hook in available):
                return gap, hook
    return None


def decide_step(u_m: str, gaps: list[str], used: list[str],
                available: frozenset[str] | None = None) -> tuple[str, str]:
    if u_m == "HIGH":
        return "ESCALATE", "model-competence risk HIGH; more evidence would not resolve it"
    if not gaps:
        if u_m == "LOW":
            return "PROCEED", "evidence complete and consistent; model risk LOW"
        if u_m == "MEDIUM":
            return "ESCALATE", "evidence complete but model risk MEDIUM"
        return "ESCALATE", "evidence complete but no validated model assessment (u_M UNSET)"
    if len(used) < MAX_VERIFY_STEPS and next_hook(gaps, used, available):
        return "VERIFY", f"bounded read-only check available for: {', '.join(gaps)}"
    if len(used) >= MAX_VERIFY_STEPS:
        return "ESCALATE", f"verification budget ({MAX_VERIFY_STEPS}) exhausted; unresolved: {', '.join(gaps)}"
    if used:
        return "ESCALATE", f"verification did not resolve: {', '.join(gaps)}"
    return "ESCALATE", f"no permitted read-only check can resolve: {', '.join(gaps)}"


# --------------------------------------------------------------------------- #
# Verification (read-only hooks from Lane 3)
# --------------------------------------------------------------------------- #

def _first_line(rng: Any) -> int | None:
    try:
        return int(str(rng).split("-")[0])
    except (TypeError, ValueError):
        return None


def hook_kwargs(hook: str, rec: dict[str, Any]) -> dict[str, Any]:
    case_id = rec["case_id"]
    if hook in ("rerun_pinned_semgrep", "reload_codeql_sarif"):
        return {"case_id": case_id, "cwe": rec["cwe"]}
    if hook == "fetch_code_slice":
        start = _first_line(rec.get("line_range")) or 1
        end = _first_line(str(rec.get("line_range", "")).split("-")[-1]) or start + 10
        return {"case_id": case_id, "start_line": start, "end_line": end}
    if hook == "inspect_enclosing_method":
        # Disputed line = where the scanner that fired points; else the manifest range.
        line = None
        for s in SCANNERS:
            r = rec.get(s) or {}
            if r.get("status") == "finding":
                line = _first_line(r.get("matched_lines"))
                if line:
                    break
        return {"case_id": case_id, "target_line": line or _first_line(rec.get("line_range")) or 1}
    raise ValueError(f"No argument builder for hook '{hook}'")


def apply_hook_result(rec: dict[str, Any], hook: str, result: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Fold a hook result into a copy of the record; return (record, short note)."""
    new = json.loads(json.dumps(rec))
    if not result.get("ok"):
        return new, f"hook failed: {result.get('error') or (result.get('scanner_result') or {}).get('error', 'unknown')}"
    if result.get("source_hash") and rec.get("source_hash") and result["source_hash"] != rec["source_hash"]:
        new["manifest_hash_match"] = "mismatch"
        return new, "source hash differs from ledger; source integrity in question"
    if hook == "rerun_pinned_semgrep":
        sr = result["scanner_result"]
        new["semgrep"] = sr
        return new, f"semgrep rerun -> {sr.get('status')} (rule={sr.get('rule_id')}, v{sr.get('version')})"
    if hook == "reload_codeql_sarif":
        sr = result["scanner_result"]
        new["codeql"] = sr
        return new, f"codeql SARIF reloaded -> {sr.get('status')} (rule={sr.get('rule_id')}, v{sr.get('version')})"
    if hook == "fetch_code_slice":
        new["source_available"] = True
        return new, f"retrieved source lines {result.get('line_range')}"
    if hook == "inspect_enclosing_method":
        return new, f"enclosing method lines {result.get('line_range')} attached for reviewer"
    return new, "ok"


# --------------------------------------------------------------------------- #
# Decision loop
# --------------------------------------------------------------------------- #

HookFn = Callable[..., dict]


def _default_hook() -> HookFn:
    from scanners.verify_hooks import call_hook
    return call_hook


def _available_hooks() -> frozenset[str]:
    from scanners.verify_hooks import HOOKS
    return frozenset(HOOKS)


def _scanner_consensus(rec: dict[str, Any]) -> str | None:
    st = {(rec.get(s) or {}).get("status") for s in SCANNERS}
    if st == {"finding"}:
        return "VULNERABLE"
    if st == {"no_finding"}:
        return "NOT_VULNERABLE"
    return None


def run_controller(
    rec: dict[str, Any],
    assessment: dict[str, Any] | None = None,
    um_override: str | None = None,
    hook_fn: HookFn | None = None,
    available: frozenset[str] | None = None,
) -> dict[str, Any]:
    """Decide one record. Returns the record with action, u-levels and a full trace."""
    if hook_fn is None:
        hook_fn, available = _default_hook(), available or _available_hooks()
    sig = agent_signals(assessment)
    u_m, u_m_source = sig["u_m"], "lane4" if sig["u_m"] != "UNSET" else "unset"
    if um_override:
        u_m, u_m_source = um_override, "cli_override"

    state = json.loads(json.dumps(rec))
    initial_gaps = evidence_gaps(state, sig["verdict"])
    trace: list[dict[str, Any]] = []
    evidence_collected: list[dict[str, Any]] = []
    used: list[str] = []

    while True:
        gaps = evidence_gaps(state, sig["verdict"])
        action, reason = decide_step(u_m, gaps, used, available)
        step = {"step": len(trace) + 1, "u_m_level": u_m, "u_e_level": u_e_level(gaps),
                "evidence_gaps": gaps, "action": action, "reason": reason}
        trace.append(step)
        if action != "VERIFY":
            break
        gap, hook = next_hook(gaps, used, available)
        kwargs = hook_kwargs(hook, state)
        result = hook_fn(hook, **kwargs)
        used.append(hook)
        state, note = apply_hook_result(state, hook, result)
        step.update({"target_gap": gap, "hook": hook, "hook_args": kwargs,
                     "hook_ok": bool(result.get("ok")), "hook_result": note})
        evidence_collected.append({k: v for k, v in result.items() if k != "code_slice"} |
                                  ({"code_slice": result["code_slice"]} if "code_slice" in result else {}))

    final_gaps = trace[-1]["evidence_gaps"]
    out = json.loads(json.dumps(rec))  # original evidence stays as observed
    conclusion = None
    if action == "PROCEED":
        conclusion = sig["verdict"] if sig["verdict"] in ("VULNERABLE", "NOT_VULNERABLE") else _scanner_consensus(state)
    out.update({
        "u_m_level": u_m,
        "u_e_level": u_e_level(final_gaps),
        "action": action,
        "conclusion": conclusion,
        "decision": {
            "policy_version": POLICY_VERSION,
            "u_m_source": u_m_source,
            "agent_assessment_status": sig["status"],
            "agent_verdict": sig["verdict"],
            "agent_u_e_level": sig["u_e"],
            "initial_u_e_level": u_e_level(initial_gaps),
            "initial_evidence_gaps": initial_gaps,
            "final_evidence_gaps": final_gaps,
            "verify_calls": len(used),
            "max_verify_calls": MAX_VERIFY_STEPS,
            "final_reason": trace[-1]["reason"],
            "trace": trace,
            "evidence_collected": evidence_collected,
            "decided_at_utc": datetime.now(timezone.utc).isoformat(),
        },
    })
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def select_variants(args: argparse.Namespace) -> list[str]:
    if args.run:
        parse_variant_id(args.run)
        return [args.run.strip().upper()]
    cases = sorted(p.stem[:-2] for p in LEDGER_DIR.glob("CASE_*_A.json"))
    if args.starter:
        cases = cases[:5]
    conds = [c for c in args.conditions.upper() if c in CONDITION_NAMES]
    return [f"{c}_{k}" for c in cases for k in conds]


def write_summary(rows: list[dict[str, Any]]) -> Path:
    lines = [
        "| variant | cwe | semgrep | codeql | u_M (source) | u_E start->end | verify | action | reason |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        d = r["decision"]
        sg = (r.get("semgrep") or {}).get("status", "masked")
        cq = (r.get("codeql") or {}).get("status", "masked")
        lines.append(
            f"| {r['variant_id']} | {r['cwe']} | {sg} | {cq} | {r['u_m_level']} ({d['u_m_source']}) | "
            f"{d['initial_u_e_level']}->{r['u_e_level']} | {d['verify_calls']} | **{r['action']}** | {d['final_reason']} |"
        )
    counts = {a: sum(r["action"] == a for r in rows) for a in ("PROCEED", "VERIFY", "ESCALATE")}
    lines += ["", f"Records: {len(rows)}. Final actions: {counts}. Policy {POLICY_VERSION}; "
              "max 2 read-only verify calls. No ground-truth labels are read or shown."]
    path = OUT_DIR / "summary.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="CARE-Sec Lane 5: PROCEED / VERIFY / ESCALATE controller")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--run", help="One variant, e.g. CASE_01_A")
    g.add_argument("--starter", action="store_true", help="CASE_01..CASE_05")
    g.add_argument("--all", action="store_true", help="All cases in reports/ledger")
    p.add_argument("--conditions", default="A", help="Conditions for --starter/--all, e.g. ABCD (default A)")
    p.add_argument("--um", choices=LEVELS, help="Override u_M for demos when Lane 4 output is missing (logged)")
    p.add_argument("--update-ledger", action="store_true",
                   help="Also write action/u-levels/trace into reports/ledger/<VARIANT>.json when it exists")
    p.add_argument("--no-write", action="store_true", help="Print decisions only")
    args = p.parse_args(argv)

    variant_ids = select_variants(args)
    if not variant_ids:
        p.error("No Evidence Ledger records found in reports/ledger/.")
    if args.um:
        print(f"[WARN] u_M overridden to {args.um} for all records (demo mode; recorded as cli_override).")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    hook_fn, available = _default_hook(), _available_hooks()
    rows, failures = [], 0
    print(f"{'VARIANT':<11} {'u_M':<7} {'u_E':<13} {'VERIFY':<7} {'ACTION':<9} REASON")
    print("-" * 100)
    for vid in variant_ids:
        try:
            rec = load_record(vid)
            out = run_controller(rec, load_assessment(vid), args.um, hook_fn, available)
        except (OSError, ValueError, KeyError) as exc:
            failures += 1
            print(f"[ERROR] {vid}: {exc}", file=sys.stderr)
            continue
        d = out["decision"]
        print(f"{vid:<11} {out['u_m_level']:<7} {d['initial_u_e_level'] + '->' + out['u_e_level']:<13} "
              f"{d['verify_calls']:<7} {out['action']:<9} {d['final_reason']}")
        rows.append(out)
        if args.no_write:
            continue
        (OUT_DIR / f"{vid}.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        ledger_path = LEDGER_DIR / f"{vid}.json"
        if args.update_ledger and ledger_path.is_file():
            ledger = _read_json(ledger_path)
            ledger.update({"u_m_level": out["u_m_level"], "u_e_level": out["u_e_level"],
                           "action": out["action"], "decision_trace": d["trace"],
                           "decision_policy": POLICY_VERSION})
            ledger_path.write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")

    if rows and not args.no_write:
        print(f"\n[DONE] {len(rows)} decision record(s) in {OUT_DIR.relative_to(REPO_ROOT)}/; "
              f"table: {write_summary(rows).relative_to(REPO_ROOT)}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
