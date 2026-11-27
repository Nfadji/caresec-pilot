# Lane 2 — Controlled Evidence Variants (`variants/`)

Owner: Ephrem Asmamawu (`@asmamawu-ai21`).

Takes Lane 3's scanner evidence for the 20 public cases and builds four
versions of each case, one per evidence condition (20 × 4 = 80 records). The
code and its true label never change between the four versions; **only the
evidence changes.** This is what lets the pilot show that the same case can
get a different decision when only its evidence changes. Nothing in this lane
reads `truth_private/`.

## Setup

No extra install: the standard library only. Lane 3's evidence must exist
first (`reports/ledger/scanner_evidence.json`, written by
`python -m scanners.run --all`).

## Commands

| Command | What it does |
|---|---|
| `python -m variants.build --scanner-json reports/ledger/scanner_evidence.json` | Builds the 80 records → `variants/variants_preview.json` |
| `python -m variants.build` | Same, without scanner evidence (every record is `awaiting_scanner_evidence`) |
| `python -m variants.build --output FILE` | Writes the records to another file |
| `python -m variants.scanner_adapter` | Local helper: my own scan files (`scanners/semgrep_all20.json` + a CodeQL SARIF in `%TEMP%`, not committed) → `variants/scanner_evidence_local.json` |

Lane 5 does not need the file: `controller.decide.load_record` calls
`variants.build.build()` directly and gets the same records in memory.

## The four conditions

| Condition | Name | What changes in `evidence` | Extra field |
|---|---|---|---|
| **A** | Complete | nothing: Lane 3's evidence as observed | — |
| **B** | Masked | emptied (`{}`): the agent sees no scanner results | `masked_fields` = the tools that were hidden |
| **C** | Disagreement | kept as observed; the record is `ready` only when one tool says `finding` and the other `no_finding` | — |
| **D** | Provenance gap | each tool's result kept, with `source`, `source_url`, `provenance`, `tool_version` and `rule_id` removed | `removed_provenance_fields` |

## Outputs

| Path | Content | Committed |
|---|---|---|
| `variants/variants_preview.json` | all 80 records | yes |
| `variants/scanner_evidence_local.json` | output of my local adapter | no |

### Record fields

| Field | Meaning |
|---|---|
| `record_id` | `CASE_XX_<condition>` |
| `condition`, `condition_name` | `A`–`D` and its name |
| `CWE`, `source_path`, `line_range` | copied from the public manifest; same in all four conditions |
| `evidence` | `{semgrep, codeql}` after the condition is applied |
| `variant_status` | see below |
| `masked_fields` | condition B only |
| `removed_provenance_fields` | condition D only |

Status values: `ready` — the record can be used;
`awaiting_scanner_evidence` — Lane 3 has no evidence for the case yet;
`awaiting_verified_disagreement` — condition C, but the two scanners agree, so
there is no real conflict to show.

## Current result (with Lane 3's evidence of Nov 20)

- 71 of 80 records are `ready`.
- Condition C: 11 cases have a natural disagreement; 9 are
  `awaiting_verified_disagreement`.

## Known issues for other lanes

- **Manifest hashes are CRLF hashes (Lane 1).** The check compares raw bytes,
  so every case prints a SHA-256 warning on a fresh clone. The records are
  still built; this is the same issue Lane 3 reports.
- **Condition C for the 9 agreeing cases** is not built yet. Options: flip
  one tool's verdict by a fixed seed, or use only the 11 natural conflicts.
  Team to decide.
- **Condition D field names.** Lane 3 writes `version`, `matched_lines`,
  `build_mode` and `suite`; these are not in the removed list yet, so a D
  record still shows them.
- **Condition B** hides the scanner results but does not mark the source as
  unavailable (no `source_available` field).
- `scanner_adapter.py` reads the Windows-only `%TEMP%` path;
  `reports/ledger/scanner_evidence.json` from Lane 3 is the portable input.
