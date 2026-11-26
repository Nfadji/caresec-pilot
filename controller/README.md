# Lane 5 — Decision Controller (`controller/`)

Owner: Aldara González Riaño. Issue: Nfadji/caresec-pilot#4. Branch: `lane5-controller`.

Turns each observation record into **PROCEED**, **VERIFY** or **ESCALATE**. VERIFY runs at most
**two** read-only Lane 3 hooks, re-evaluates the evidence after each one, and then makes a final
decision. Every step is logged. Nothing here reads `truth_private/` or hidden labels.

## Commands (frozen CLI contract: `python -m controller.decide --run CASE_01_A`)

| Command | What it does |
|---|---|
| `python -m controller.decide --run CASE_01_A` | One record (any condition `A`–`D`) |
| `python -m controller.decide --starter` | CASE_01–CASE_05, condition A |
| `python -m controller.decide --all --conditions ABCD` | All 80 observation records |
| `... --um LOW` | Demo only: overrides u_M while Lane 4 output is missing. Logged as `cli_override` in `reports/controller/`; the Evidence Ledger is **not** updated in this mode |
| `... --no-ledger` | Skips filling `u_m_level`, `u_e_level`, `action` and `decision_trace` in `reports/ledger/<VARIANT>.json` (filled by default) |
| `... --no-write` | Prints the decisions without writing files |
| `python -m pytest tests/test_controller.py -q` | Unit tests (hooks are faked, so no scanners are needed) |

`rerun_pinned_semgrep` needs `semgrep==1.185.0` on PATH. Without it, the hook returns
`ok: False`. The controller logs the failure, does not count it as new evidence, and escalates.

## Inputs

| Source | Used for |
|---|---|
| `reports/ledger/<CASE>_A.json` (Lane 3) | Condition A evidence |
| `variants.build` (Lane 2) + `reports/ledger/scanner_evidence.json` | Conditions B/C/D, built in memory |
| `reports/agent/<VARIANT>_assessment.json` (Lane 4) | `verdict`, `u_m.u_m_level`, `u_e.u_e_level` |
| `scanners.verify_hooks.call_hook` (Lane 3) | Read-only verification |

## Policy `lane5-rules-v1`

The controller computes its own evidence-gap list (u_E proxy): missing, failed or unattributed
output from either scanner, scanner disagreement, masked source, source-hash mismatch, and a Lane 4
verdict that contradicts both scanners. u_E is LOW with 0 gaps, MEDIUM with 1 and HIGH with 2 or more.

1. u_M **HIGH** → ESCALATE. The model is the problem, so more evidence won't help.
2. No gaps and u_M **LOW** → PROCEED. The conclusion is the Lane 4 verdict.
3. A gap has an unused read-only hook and the budget (2) remains → **VERIFY**, then re-evaluate.
4. Otherwise → ESCALATE with the reason and the collected evidence (the reviewer packet). This covers an unresolved gap, a spent budget, u_M MEDIUM, and u_M UNSET.

| Gap | Hook tried |
|---|---|
| `semgrep_missing` / `_failed` / `_provenance` | `rerun_pinned_semgrep` |
| `scanner_conflict` | `rerun_pinned_semgrep`, then `inspect_enclosing_method` at the disputed line (context for the reviewer) |
| `source_masked` | `fetch_code_slice` |
| `codeql_*` | `reload_codeql_sarif`, **used automatically once Lane 3 adds it**. Until then, these gaps escalate |

## Output

`reports/controller/<VARIANT>.json` keeps the original ledger record as observed, then adds:

- `u_m_level`, `u_e_level`, `action` and `conclusion`
- a `decision` block with `u_m_source`, the initial and final gaps, `verify_calls`, the per-step `trace` (hook, arguments and result), `evidence_collected` and a timestamp.

`reports/controller/summary.md` has one row per record.

The Evidence Ledger records (`reports/ledger/<VARIANT>.json`, when the file exists) are also
updated in place: the `u_m_level`, `u_e_level` and `action` fields that Lane 3 leaves for Lanes 4–5
are filled in, and `decision_trace`, `decision_policy` and `decision_u_m_source` are added. Scanner
evidence in the ledger is never changed. Runs with `--um` never write to the ledger, so a demo
override cannot be mistaken for a real Lane 4 value. `python -m scanners.run` rewrites the ledger
and resets these fields, so re-run the controller after re-scanning.

Conditions B, C and D are built from the condition A record's evidence only. Condition A's
decision fields are reset (`UNSET` / `PENDING`) and its trace is dropped, so a masked record never
carries a trace that mentions the evidence it hides.

## Status and dependencies (Nov 25)

- **Lane 4 → u_M is UNSET for every record.** `agent.evaluate` skips the model whenever
  `reports/integrity/<CASE>_integrity.json` is missing. No file there exists, and Gemini needs
  `GEMINI_API_KEY`. As a result, the controller escalates everything for now, which is the safe default.
  Running `--um LOW` shows the intended behaviour.
- **CodeQL cannot be re-checked.** Conditions B and D always escalate until a read-only CodeQL hook exists.
- `tests/test_lane4.py` still expects the old `tool_failed` ledger and an integrity report. It
  also fails to import without `google-genai`.
