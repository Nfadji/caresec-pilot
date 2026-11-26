# Lane 6 — Evaluation, anti-leakage checks and reporting (`tests/`, `reports/`)

Issue: Nfadji/caresec-pilot#10. Everything here runs without a scanner, a model, an API key
or a private file. The schemas and the baseline definitions below are proposals for the
team to confirm; they describe what the code on `main` does today.

## Commands

| Command | What it does |
|---|---|
| `python -m pytest tests -q` | All lane tests. `tests/test_lane4.py` needs `google-genai` installed |
| `python -m pytest tests/test_schemas.py -q` | Manifest, evidence records and lane outputs against `tests/schemas/` |
| `python -m pytest tests/test_anti_leakage.py -q` | Private files, public files, the model prompt and a full 80-record decision run |
| `python -m reports.summarize` | B1–B3 comparison (frozen CLI). Writes `reports/eval/summary.md` and `metrics.json` |
| `python -m reports.blind_packet --n 8` | Blinded reviewer packet in `reports/review_packet/` |

## Schemas (`tests/schemas/`, drafts)

| File | Checks |
|---|---|
| `case_manifest_public.schema.json` | Each row of `manifests/case_manifest_public.csv`. No extra column is allowed |
| `evidence_record.schema.json` | `reports/ledger/<CASE>_A.json`. No extra field is allowed |
| `controller_decision.schema.json` | `reports/controller/<VARIANT>.json` (fields the evaluation reads) |
| `agent_assessment.schema.json` | `reports/agent/<VARIANT>_assessment.json` (fields Lanes 5 and 6 read) |

`tests/schema_check.py` is a small checker for these files, so no extra package is needed.
The tests also cross-check the records against the manifest, the code in `cases/`, the
scanner index and Lane 2's 80 variants.

## Anti-leakage checks (`tests/test_anti_leakage.py`)

- `truth_private/` and `manifests/case_manifest.csv` are ignored by git and not tracked.
- No public data file has a label field, an upstream test name, or a filled-in review sheet.
- The case sources carry no label hint from the upstream suites.
- The Lane 4 prompt is captured with a stand-in client. Labels and Lane 5 decisions planted
  in a record do not reach it.
- A full decision run over all 80 records (Lanes 2, 3 and 5) opens no private file. This
  uses a Python audit hook, so it sees every file the process opens.
- One test is marked as an expected failure: conditions B, C and D currently inherit
  condition A's `decision_trace` (see the review of PR #11). The marker comes off when
  that is fixed.

## Baselines as `reports.summarize` reads them (proposal)

| Baseline | Input | A record counts as a final answer when |
|---|---|---|
| B1 LLM alone | `reports/agent_b1/<VARIANT>_assessment.json` | the verdict is VULNERABLE or NOT_VULNERABLE |
| B2 LLM + scanners, no escalation | `reports/agent/<VARIANT>_assessment.json` | the verdict is VULNERABLE or NOT_VULNERABLE |
| B3 CARE-Sec | `reports/controller/<VARIANT>.json` | the action is PROCEED |

Open points for the team:

- No lane writes B1 output yet. The folder name above is a placeholder.
- Lane 4 reads `reports/ledger/<VARIANT>.json`, which exists for condition A only, so B2
  can cover 20 of the 80 records until conditions B–D are written out as files.
- Controller runs made with `--um` are demos. They are left out of B3 and counted separately.
- The truth file format is not fixed. `summarize` accepts an object keyed by case id or a
  list with `case_id`, with the label under `correctness_label`, `expected_label`, `label`,
  `is_vulnerable`, `vulnerable`, `ground_truth` or `truth`. It stops if any case has no
  usable label.

Results are given per record (80) and per base case (20), because the four records of a
case share one piece of code.

## What is public and what is private

`reports/eval/summary.md` and `metrics.json` hold counts only and name no record. When a
truth file is read, the per-record detail goes to `truth_private/eval/per_record.csv`.
The reviewer packet replaces case ids with item numbers in a shuffled order and contains
no scanner output, verdict, decision or label. Its item-to-case key goes to
`truth_private/review_key.csv`. `truth_private/` is ignored by git.
