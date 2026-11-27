# Lane 2 — Controlled Evidence Variants (`variants/`)

Owner: Ephrem Asmamawu (`@asmamawu-ai21`).

Takes Lane 3's scanner evidence for the 20 public cases and builds four
versions of each case, one per evidence condition (20 × 4 = 80 records). The
code and its true label never change between the four versions; **only the
evidence the agent sees changes.** This is what lets the pilot show that the
same case can get a different decision when only its evidence changes.
Nothing in this lane reads `truth_private/`.

## Setup

No extra install: the standard library only. Lane 3's evidence must exist
first (`reports/ledger/scanner_evidence.json`, written by
`python -m scanners.run --all`).

## Commands

| Command | What it does |
|---|---|
| `python -m variants.build` | Builds the 80 records → `variants/variants_preview.json` |
| `python -m variants.build --scanner-json FILE` | Same, from another evidence file |
| `python -m variants.build --write-ledger` | Also writes `reports/ledger/<CASE>_{B,C,D}.json` for Lane 4 (optional) |
| `python -m variants.scanner_adapter` | Local helper: my own scan files (`scanners/semgrep_all20.json` + a CodeQL SARIF, not committed) → `variants/scanner_evidence_local.json`. The team build uses Lane 3's evidence instead. |
| `python -m pytest tests/test_variants.py -q` | Lane 2 tests (no scanners, no network) |

Lane 5 does not need the files: `controller.decide.load_record` calls
`variants.build.build()` directly and gets the same 80 records in memory.

## The four conditions

| Condition | Name | What the agent sees | What is taken away |
|---|---|---|---|
| **A** | Complete | Lane 3's evidence as observed | nothing |
| **B** | Masked | no scanner results, source marked unavailable | both scanner results; the code from the start of the sink's method to the line before the sink (`masked_lines`) |
| **C** | Disagreement | the two scanners give opposite verdicts | the agreement between the tools |
| **D** | Provenance gap | the verdicts only | version, rule id, matched lines, CodeQL build mode and suite |

### How each condition is made

- **B — Masked.** `evidence` is empty, `source_available` is `false`, and
  `masked_lines` names the hidden span. That span is where the value reaching
  the sink comes from and how it is processed — exactly what an analyst needs
  to judge the case. The span is found automatically from the first SQL or
  file sink (comments are skipped).
- **C — Disagreement.** If Semgrep and CodeQL already disagree, the record is
  kept as it is (`conflict_origin: natural`, 11 cases). If they agree, one
  tool's verdict is flipped (`conflict_origin: synthetic`, 9 cases). The tool
  is chosen by a fixed seed per case (`SEED = 447`), so every rebuild gives
  the same result. A flipped *finding* reuses a real rule id that tool
  reported for the same CWE, so the fake result looks like a real one.
- **D — Provenance gap.** Each tool keeps its `status` (`finding` /
  `no_finding` / `tool_failed`), but everything that says *where the result
  came from* is removed (`removed_provenance_fields` lists them).

## Outputs

| Path | Content | Committed |
|---|---|---|
| `variants/variants_preview.json` | all 80 records, including evaluation-only fields | yes |
| `reports/ledger/<CASE>_{B,C,D}.json` | agent-visible B/C/D records in the shape of Lane 3's `_A` file (`--write-ledger`) | not by this lane |
| `variants/scanner_evidence_local.json` | output of my local adapter | no |

### Record fields

| Field | Meaning |
|---|---|
| `record_id` | `CASE_XX_<condition>` |
| `condition`, `condition_name` | `A`–`D` and its name |
| `CWE`, `source_path`, `line_range` | copied from the public manifest; same in all four conditions |
| `evidence` | `{semgrep, codeql}` after the condition is applied |
| `variant_status` | `ready`, or `awaiting_scanner_evidence` if Lane 3 has no evidence for the case |
| `masked_fields`, `masked_lines`, `source_available` | condition B only |
| `removed_provenance_fields` | condition D only |
| `conflict_origin`, `synthetic_tool` | condition C only — **evaluation-only**, never written to the ledger files the agent reads |

## Rules this lane keeps

- The agent must not be able to tell a record's condition from its id or
  hidden fields: evaluation-only fields stay out of the ledger files.
- B/C/D ledger files start with `u_m_level`/`u_e_level` = `UNSET` and
  `action` = `PENDING`. They never inherit Lane 4/5 results from condition A.
- Deterministic: the same evidence always gives the same 80 records.
- The manifest hash check accepts LF and CRLF (see Lane 3's note on CRLF
  hashes); any other difference prints a warning.

## Notes for other lanes

- **Lane 3:** Lane 2 reads only `reports/ledger/scanner_evidence.json` and the
  `_A` ledger files; it never changes them.
- **Lane 4:** in condition B, do not show the code from `masked_lines`; the
  agent should see that evidence is missing, not guess around it.
- **Lane 5:** the interface used by `load_record` is unchanged: `record_id`,
  `evidence`, `variant_status`, `masked_fields`, `removed_provenance_fields`.
- **Lane 6:** use `conflict_origin` to report natural and synthetic
  disagreements separately.
- `scanner_adapter.py` no longer needs the Windows-only `%TEMP%` variable: it
  uses the system temp folder, or `CARESEC_CODEQL_SARIF` if set.
