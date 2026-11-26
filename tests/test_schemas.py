"""Lane 6: schema and interface checks for the manifest, evidence records and lane outputs.

Run with: python -m pytest tests/test_schemas.py -q
No scanner, model or private file is needed. The schemas in tests/schemas/ are drafts
(see their descriptions) until the team freezes them.
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
from pathlib import Path

import pytest

from scanners.run import compute_sha256, verify_hash
from tests.schema_check import load_schema, validate

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "manifests" / "case_manifest_public.csv"
PRIVATE_MANIFEST = REPO_ROOT / "manifests" / "case_manifest.csv"
LEDGER_DIR = REPO_ROOT / "reports" / "ledger"
CONTROLLER_DIR = REPO_ROOT / "reports" / "controller"
AGENT_DIR = REPO_ROOT / "reports" / "agent"
EXPECTED_CASES = [f"CASE_{n:02d}" for n in range(1, 21)]
MANIFEST_COLUMNS = ["case_id", "CWE", "source_path", "line_range", "project_group_id", "java_version",
                    "scan_status", "file_hash"]


def manifest_rows() -> list[dict]:
    with MANIFEST.open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def evidence_records() -> dict[str, dict]:
    return {p.stem[:-2]: json.loads(p.read_text(encoding="utf-8")) for p in sorted(LEDGER_DIR.glob("CASE_*_A.json"))}


# --------------------------------------------------------------------------- #
# The checker itself
# --------------------------------------------------------------------------- #

def test_checker_reports_each_kind_of_problem():
    schema = {"type": "object", "required": ["a"], "additionalProperties": False,
              "properties": {"a": {"type": "string", "pattern": "^x"}, "n": {"type": "integer", "maximum": 2},
                             "e": {"enum": ["P", "Q"]}, "l": {"type": "array", "maxItems": 1}}}
    assert validate({"a": "xy", "n": 2, "e": "P", "l": [1]}, schema) == []
    problems = validate({"a": "no", "n": 3, "e": "Z", "l": [1, 2], "extra": 1}, schema)
    assert len(problems) == 5
    assert validate({}, schema) == ["$: missing required field 'a'"]
    assert validate({"a": True}, schema) == ["$.a: expected string, got bool"]
    assert validate(True, {"type": "integer"}) != []  # a boolean is not an integer


def test_checker_refuses_keywords_it_does_not_check():
    with pytest.raises(ValueError, match="not supported"):
        validate({}, {"type": "object", "oneOf": []})


# --------------------------------------------------------------------------- #
# Public manifest
# --------------------------------------------------------------------------- #

def test_manifest_has_the_agreed_columns_and_twenty_cases():
    rows = manifest_rows()
    assert list(rows[0].keys()) == MANIFEST_COLUMNS
    assert [r["case_id"] for r in rows] == EXPECTED_CASES


def test_manifest_rows_fit_the_schema():
    schema = load_schema("case_manifest_public.schema.json")
    problems = [e for r in manifest_rows() for e in validate(r, schema, r.get("case_id", "?"))]
    assert problems == []


def test_manifest_rows_point_at_real_code():
    for row in manifest_rows():
        path = REPO_ROOT / row["source_path"]
        assert path.is_file(), row["source_path"]
        assert path.stem == row["case_id"]
        start, end = (int(x) for x in row["line_range"].split("-"))
        n_lines = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        assert 1 <= start <= end <= n_lines, f"{row['case_id']}: lines {row['line_range']} of {n_lines}"
        # Same tolerance as Lane 3: the manifest hash may be the CRLF form of the file git stores as LF.
        match = verify_hash(compute_sha256(path), row["file_hash"], path.read_bytes())
        assert match in ("exact", "crlf_normalized"), f"{row['case_id']}: file does not match manifest hash"


def test_manifest_balance_is_ten_and_ten():
    cwes = [r["CWE"] for r in manifest_rows()]
    assert cwes.count("CWE-22") == 10 and cwes.count("CWE-89") == 10


def test_private_manifest_lists_the_same_cases_when_present():
    if not PRIVATE_MANIFEST.is_file():
        pytest.skip("manifests/case_manifest.csv is local-only and not on this machine")
    with PRIVATE_MANIFEST.open(encoding="utf-8-sig", newline="") as f:
        ids = [r["case_id"].strip() for r in csv.DictReader(f)]
    assert sorted(ids) == EXPECTED_CASES


# --------------------------------------------------------------------------- #
# Evidence records (Lane 3 output, later filled in by Lane 5)
# --------------------------------------------------------------------------- #

def test_one_evidence_record_per_case():
    assert list(evidence_records()) == EXPECTED_CASES


def test_evidence_records_fit_the_schema():
    schema = load_schema("evidence_record.schema.json")
    problems = [e for cid, rec in evidence_records().items() for e in validate(rec, schema, cid)]
    assert problems == []


def test_evidence_records_agree_with_the_manifest_and_the_code():
    rows = {r["case_id"]: r for r in manifest_rows()}
    for cid, rec in evidence_records().items():
        row = rows[cid]
        assert rec["case_id"] == cid and rec["variant_id"] == f"{cid}_A"
        assert (rec["cwe"], rec["file"], rec["line_range"]) == (row["CWE"], row["source_path"], row["line_range"])
        assert rec["claim"] == {"CWE-22": "possible_path_traversal", "CWE-89": "possible_sql_injection"}[rec["cwe"]]
        path = REPO_ROOT / rec["file"]
        assert verify_hash(compute_sha256(path), rec["source_hash"], path.read_bytes()) != "mismatch", cid
        assert rec["manifest_hash_match"] != "mismatch", cid


def test_scanner_blocks_are_internally_consistent():
    for cid, rec in evidence_records().items():
        for name in ("semgrep", "codeql"):
            block = rec[name]
            if block["status"] == "finding":
                assert block["rule_id"] and block["matched_lines"] and block["finding_count"] >= 1, (cid, name)
            elif block["status"] == "no_finding":
                assert block["rule_id"] is None and block["finding_count"] == 0, (cid, name)
            else:
                assert block.get("error"), (cid, name)


def test_scanner_index_matches_the_evidence_records():
    index = json.loads((LEDGER_DIR / "scanner_evidence.json").read_text(encoding="utf-8"))
    assert sorted(index) == EXPECTED_CASES
    for cid, rec in evidence_records().items():
        assert index[cid]["semgrep"] == rec["semgrep"] and index[cid]["codeql"] == rec["codeql"], cid


def test_filled_in_decisions_are_complete():
    """Once Lane 5 has decided a record, the decision fields must all be there and agree."""
    for cid, rec in evidence_records().items():
        if rec["action"] == "PENDING":
            assert "decision_trace" not in rec and "decision_policy" not in rec, cid
            continue
        assert rec["action"] in ("PROCEED", "ESCALATE"), f"{cid}: VERIFY is a step, not a final action"
        assert rec.get("decision_policy"), cid
        trace = rec["decision_trace"]
        assert [s["step"] for s in trace] == list(range(1, len(trace) + 1)), cid
        assert trace[-1]["action"] == rec["action"] and trace[-1]["u_e_level"] == rec["u_e_level"], cid
        assert sum(s["action"] == "VERIFY" for s in trace) <= 2, f"{cid}: more than two verify calls"
        assert all(s["action"] == "VERIFY" for s in trace[:-1]), cid


# --------------------------------------------------------------------------- #
# Lane 2 variants built from the same evidence (interface check, 80 records)
# --------------------------------------------------------------------------- #

def lane2_variants() -> list[dict]:
    from variants.build import build
    with contextlib.redirect_stdout(io.StringIO()):
        return build(MANIFEST, LEDGER_DIR / "scanner_evidence.json")


def test_variants_are_twenty_cases_by_four_conditions():
    ids = [v["record_id"] for v in lane2_variants()]
    assert sorted(ids) == sorted(f"{c}_{k}" for c in EXPECTED_CASES for k in "ABCD")


def test_variant_conditions_show_only_what_they_should():
    records = evidence_records()
    for var in lane2_variants():
        cid, cond, ev = var["case_id"], var["condition"], var.get("evidence") or {}
        if cond == "A":
            assert ev == {"semgrep": records[cid]["semgrep"], "codeql": records[cid]["codeql"]}, var["record_id"]
        elif cond == "B":
            assert ev == {} and sorted(var["masked_fields"]) == ["codeql", "semgrep"], var["record_id"]
        elif cond == "D":
            assert set(ev) == {"semgrep", "codeql"}, var["record_id"]
            assert all("rule_id" not in block for block in ev.values()), var["record_id"]


# --------------------------------------------------------------------------- #
# Lane 4 and Lane 5 outputs (checked whenever they exist on this machine)
# --------------------------------------------------------------------------- #

def _check_outputs(directory: Path, pattern: str, schema_name: str) -> int:
    files = sorted(directory.glob(pattern)) if directory.is_dir() else []
    schema = load_schema(schema_name)
    problems = [e for p in files for e in validate(json.loads(p.read_text(encoding="utf-8")), schema, p.name)]
    assert problems == []
    return len(files)


def test_controller_outputs_fit_the_schema_when_present():
    if _check_outputs(CONTROLLER_DIR, "CASE_*_[A-D].json", "controller_decision.schema.json") == 0:
        pytest.skip("no reports/controller/<VARIANT>.json files on this machine")


def test_agent_outputs_fit_the_schema_when_present():
    if _check_outputs(AGENT_DIR, "CASE_*_assessment.json", "agent_assessment.schema.json") == 0:
        pytest.skip("no reports/agent/<VARIANT>_assessment.json files on this machine")
