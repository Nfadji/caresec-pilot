# Lane 3 — Static Scanners & Evidence Ledger (`scanners/`)

Owner: Kathryn Walker (`@kwalerk`). Issue: Nfadji/caresec-pilot#2.

Runs Semgrep CE and CodeQL on the 20 public cases, normalizes both outputs
into one record per case, writes the Condition A Evidence Ledger records, and
exposes read-only verification hooks for the Lane 5 controller. Nothing in this
lane reads `truth_private/`.

## Setup

```bash
pip install -r scanners/requirements.txt        # semgrep==1.185.0, pytest
# CodeQL CLI 2.27.4 bundle on PATH (https://github.com/github/codeql-cli-binaries/releases)
# JDK 17 on PATH for the compile build mode
```

## Commands (frozen CLI contract: `python -m scanners.run --starter`)

| Command | What it does |
|---|---|
| `python -m scanners.run --starter` | Semgrep + CodeQL (from SARIF) on CASE_01–CASE_05 |
| `python -m scanners.run --all` | All 20 cases; also writes `reports/ledger/scanner_evidence.json` |
| `python -m scanners.run --case CASE_07` | One case |
| `python -m scanners.codeql_build` | Build the CodeQL database and export per-case SARIF |
| `python -m scanners.report_table --starter` | Markdown table for the weekly report |
| `python -m pytest tests/ -q` | Unit tests (no scanners needed) |

Run `codeql_build` **before** `run`: `run` never invokes the CodeQL CLI itself,
it reads `reports/codeql_sarif/CASE_XX.sarif`. Without those files the CodeQL
column reports `tool_failed` with the missing path.

## Outputs

| Path | Content | Committed |
|---|---|---|
| `reports/scanners/CASE_XX_scan.json` | normalized Semgrep + CodeQL result for the target CWE | yes |
| `reports/ledger/CASE_XX_A.json` | Condition A ledger record (`u_m_level`/`u_e_level`/`action` left for Lanes 4–5) | yes |
| `reports/ledger/scanner_evidence.json` | `{case_id: {semgrep, codeql}}` — the shape `variants.build --scanner-json` takes | yes |
| `reports/codeql_sarif/CASE_XX.sarif` + `_run.json` | per-case SARIF 2.1.0 and the run record (versions, packs, build mode) | yes |
| `reports/codeql_work/` | source tree, database, combined SARIF, log | no (git-ignored) |

Status values: `finding` / `no_finding` are about the case's **target CWE only**
(`other_findings` counts the rest); `tool_failed` means the tool did not run or
its output could not be parsed, which the controller should treat as missing
evidence, not as a clean result.

## CodeQL build modes

`codeql_build` compiles the cases when it can find the helper sources, and
falls back to `--build-mode=none` otherwise. Compile mode is what the
committed SARIF was produced with; it needs three inputs, given by flag or
environment variable:

| Input | Env var | Why |
|---|---|---|
| OWASP BenchmarkJava checkout | `CARESEC_BENCHMARK_SRC` | `org.owasp.benchmark.helpers.*` used by CASE_01–12 |
| NIST Juliet Java 1.3 zip | `CARESEC_JULIET_ZIP` | `testcasesupport.*` and `lib/*.jar` used by CASE_13–20 |
| Benchmark Maven classpath file | `CARESEC_CLASSPATH_FILE` | servlet/JDBC/ESAPI jars; generated with Maven if absent |

`scanners/codeql_shims/` replaces Juliet's two abstract base classes inside the
build tree only: Lane 1 collapsed `bad()`/`good()` into `processRequest()` to
stop method names leaking the label, so the upstream bases no longer compile
against the cases. The shims keep the package and `runTest` entry point.

## Verification hooks (Lane 3 → Lane 5)

`scanners/verify_hooks.py` exposes four read-only hooks and a dispatcher:

```python
from scanners.verify_hooks import call_hook
call_hook("fetch_code_slice", case_id="CASE_01", start_line=48, end_line=54)
call_hook("inspect_enclosing_method", case_id="CASE_01", target_line=55)
call_hook("rerun_pinned_semgrep", case_id="CASE_01", cwe="CWE-22")
call_hook("reload_codeql_sarif", case_id="CASE_01", cwe="CWE-22")
```

Every result is a dict with `ok`; failures (unknown hook, bad arguments, blocked
path) come back as `{"ok": False, "error": ...}` instead of raising, so a bad
call costs the controller one budget unit but never aborts a run. Hooks accept
only `CASE_NN` ids and only read under `cases/` (`reload_codeql_sarif` also reads that
case's stored `reports/codeql_sarif/<CASE>.sarif`); `truth_private/`,
`hidden_truth` and `case_manifest.csv` are blocked by name as well. The
controller owns the two-call budget (`tests/test_scanners.py` has a loop
simulation).

`reload_codeql_sarif` does not run CodeQL again. It re-reads the stored SARIF and returns
the same normalized result Lane 3 recorded (status, rule id, version), plus the SARIF hash
and the current source hash, so Lane 5 can recover CodeQL evidence in conditions B and D.

## Known issues for other lanes

- **Manifest hashes are CRLF hashes (Lane 1).** Git stores the cases with LF,
  so `file_hash` in `case_manifest_public.csv` never matches a fresh clone
  byte-for-byte. `run` reports `crlf_normalized` when the hash matches after a
  line-ending swap and only flags `mismatch` otherwise; regenerating the hashes
  from the repository bytes (or adding a `.gitattributes`) would make it exact.
- **CodeQL terms.** The CLI bundle's licence permits academic research use;
  this is a manual research run, not CI. PI to confirm before any wider use.
- `variants/scanner_adapter.py` (Lane 2) reads a Windows `%TEMP%` SARIF path;
  `reports/ledger/scanner_evidence.json` is the portable replacement.
