"""Unit tests for Lane 3 (scanners/). Run with: python -m pytest tests/ -q

These tests never call Semgrep or CodeQL; they cover the pure normalization
and anti-leakage logic so they run anywhere in well under a second.
"""

import hashlib
import json
from pathlib import Path

import pytest

from scanners import codeql_build, run, verify_hooks

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# scanners.run
# --------------------------------------------------------------------------- #

def test_load_manifest_strips_utf8_bom():
    rows = run.load_manifest(REPO_ROOT)
    assert rows, "public manifest should have rows"
    assert "case_id" in rows[0], f"BOM not stripped: {list(rows[0])[:1]}"
    assert len(rows) == 20


@pytest.mark.parametrize("text,cwe,expected", [
    ("caresec.java.cwe89.sql-injection-sink", "CWE-89", True),
    ("java/sql-injection external/cwe/cwe-089", "CWE-89", True),
    ("java/path-injection", "CWE-22", True),
    ("java/zipslip external/cwe/cwe-022", "CWE-22", True),
    ("java/path-injection external/cwe/cwe-022", "CWE-89", False),
    ("java/sql-injection", "CWE-22", False),
    ("java/xss external/cwe/cwe-079", "CWE-89", False),
    ("anything", "CWE-999", False),
])
def test_match_cwe(text, cwe, expected):
    assert run.match_cwe(text, cwe) is expected


def test_codeql_result_matches_uses_rule_tags():
    rules = {"java/path-injection": {"id": "java/path-injection",
                                     "properties": {"tags": ["security", "external/cwe/cwe-022"]}}}
    result = {"ruleId": "java/path-injection"}
    assert run.codeql_result_matches(result, rules, "CWE-22")
    assert not run.codeql_result_matches(result, rules, "CWE-89")


def test_sarif_rule_index_merges_driver_and_extensions():
    sarif_run = {"tool": {"driver": {"rules": [{"id": "a"}]},
                          "extensions": [{"rules": [{"id": "b"}]}, {"rules": [{"id": "c"}]}]}}
    assert set(run.sarif_rule_index(sarif_run)) == {"a", "b", "c"}


def test_verify_hash_exact_crlf_and_mismatch():
    lf = b"class A {\n}\n"
    crlf = lf.replace(b"\n", b"\r\n")
    h_lf, h_crlf = hashlib.sha256(lf).hexdigest(), hashlib.sha256(crlf).hexdigest()
    assert run.verify_hash(h_lf, h_lf, lf) == "exact"
    assert run.verify_hash(h_lf, h_crlf, lf) == "crlf_normalized"
    assert run.verify_hash(h_crlf, h_lf, crlf) == "crlf_normalized"
    assert run.verify_hash(h_lf, "0" * 64, lf) == "mismatch"


def test_run_codeql_reads_per_case_sarif(tmp_path):
    sarif = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "semanticVersion": "2.27.4", "rules": []},
                 "extensions": [{"name": "codeql/java-queries", "rules": [
                     {"id": "java/path-injection", "properties": {"tags": ["external/cwe/cwe-022"]}},
                     {"id": "java/xss", "properties": {"tags": ["external/cwe/cwe-079"]}}]}]},
        "results": [
            {"ruleId": "java/xss", "locations": [{"physicalLocation": {"region": {"startLine": 5}}}]},
            {"ruleId": "java/path-injection",
             "locations": [{"physicalLocation": {"region": {"startLine": 55, "endLine": 55}}}]},
        ]}]}
    (tmp_path / "CASE_01.sarif").write_text(json.dumps(sarif))
    (tmp_path / "_run.json").write_text(json.dumps({"build_mode": "compile", "suite": "s"}))
    res = run.run_codeql(Path("cases/CASE_01.java"), "CWE-22", tmp_path)
    assert res["status"] == "finding"
    assert res["rule_id"] == "java/path-injection"
    assert res["matched_lines"] == "55-55"
    assert res["finding_count"] == 1 and res["other_findings"] == 1
    assert res["build_mode"] == "compile"

    res = run.run_codeql(Path("cases/CASE_01.java"), "CWE-89", tmp_path)
    assert res["status"] == "no_finding" and res["other_findings"] == 2

    res = run.run_codeql(Path("cases/CASE_02.java"), "CWE-22", tmp_path)
    assert res["status"] == "tool_failed"


def test_ledger_record_shape():
    row = {"case_id": "CASE_03", "CWE": "CWE-89", "source_path": "cases/CASE_03.java", "line_range": "38-44"}
    rec = run.build_base_ledger_record(row, {"status": "finding"}, {"status": "no_finding"}, "abc", "crlf_normalized")
    assert rec["variant_id"] == "CASE_03_A"
    assert rec["evidence_condition"] == "A_COMPLETE"
    assert rec["claim"] == "possible_sql_injection"
    assert rec["manifest_hash_match"] == "crlf_normalized"
    assert rec["action"] == "PENDING"
    assert "expected_label" not in rec and "correctness_label" not in rec


# --------------------------------------------------------------------------- #
# scanners.codeql_build
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("uri,expected", [
    ("org/owasp/benchmark/testcode/CASE_01.java", "CASE_01"),
    ("testcases\\CWE89_SQL_Injection\\s02\\CASE_13.java", "CASE_13"),
    ("CASE_20.java", "CASE_20"),
    ("org/owasp/benchmark/helpers/Utils.java", None),
    ("CASE_1.java", None),
])
def test_case_id_from_uri(uri, expected):
    assert codeql_build.case_id_from_uri(uri) == expected


def test_package_dir():
    assert codeql_build.package_dir("package testcases.CWE89_SQL_Injection.s02;\nclass X {}") == \
        Path("testcases/CWE89_SQL_Injection/s02")
    assert codeql_build.package_dir("class X {}") == Path()


def test_split_sarif_keeps_only_referenced_rules_and_right_results():
    sarif = {"$schema": "x", "version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL", "rules": []},
                 "extensions": [{"name": "codeql/java-queries",
                                 "locations": [{"uri": "file:///home/someone/qlpacks/"}],
                                 "rules": [
                     {"id": "java/sql-injection"}, {"id": "java/xss"}, {"id": "java/unused"}]}]},
        "results": [
            {"ruleId": "java/sql-injection", "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "org/owasp/benchmark/testcode/CASE_03.java"}}}]},
            {"ruleId": "java/xss", "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "org/owasp/benchmark/testcode/CASE_03.java"}}}]},
            {"ruleId": "java/xss", "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "org/owasp/benchmark/helpers/Utils.java"}}}]},
        ]}]}
    out = codeql_build.split_sarif(sarif, ["CASE_01", "CASE_03"])
    assert set(out) == {"CASE_01", "CASE_03"}
    assert out["CASE_01"]["runs"][0]["results"] == []
    c3 = out["CASE_03"]["runs"][0]
    assert len(c3["results"]) == 2
    ext_rules = {r["id"] for r in c3["tool"]["extensions"][0]["rules"]}
    assert ext_rules == {"java/sql-injection", "java/xss"}
    assert "locations" not in c3["tool"]["extensions"][0], "machine paths must not be exported"
    assert c3["automationDetails"]["id"].endswith("CASE_03")


# --------------------------------------------------------------------------- #
# scanners.verify_hooks (anti-leakage)
# --------------------------------------------------------------------------- #

def test_fetch_code_slice_reads_public_case():
    res = verify_hooks.fetch_code_slice("CASE_01", 48, 54)
    assert res["ok"] and res["file"] == "cases/CASE_01.java"
    assert res["line_range"] == "48-54"
    assert res["code_slice"].startswith("48: ")
    assert len(res["source_hash"]) == 64


def test_inspect_enclosing_method_walks_back_to_signature():
    res = verify_hooks.inspect_enclosing_method("CASE_01", 55)
    assert res["ok"]
    start = int(res["line_range"].split("-")[0])
    assert start <= 55
    assert "doPost" in res["code_slice"]


@pytest.mark.parametrize("bad", ["../truth_private/hidden_truth", "../manifests/case_manifest",
                                 "CASE_01/../../README", "cases", "CASE_1", "", "DROP TABLE"])
def test_hooks_reject_non_case_ids(bad):
    with pytest.raises((ValueError, PermissionError)):
        verify_hooks.fetch_code_slice(bad, 1, 5)
    with pytest.raises((ValueError, PermissionError)):
        verify_hooks.inspect_enclosing_method(bad, 1)


def test_guard_blocks_truth_private_even_for_valid_shape(tmp_path, monkeypatch):
    monkeypatch.setattr(verify_hooks, "REPO_ROOT", tmp_path)
    (tmp_path / "cases").mkdir()
    with pytest.raises(PermissionError):
        verify_hooks._guard_path(tmp_path / "truth_private" / "CASE_01.java")
    with pytest.raises(PermissionError):
        verify_hooks._guard_path(tmp_path / "CASE_01.java")  # outside cases/
    verify_hooks._guard_path(tmp_path / "cases" / "CASE_01.java")  # allowed


def test_missing_case_is_reported_not_raised():
    res = verify_hooks.fetch_code_slice("CASE_99", 1, 5)
    assert res == {"ok": False, "error": "Source file not found for CASE_99"}


# --------------------------------------------------------------------------- #
# Hook dispatcher used by Lane 5's bounded verification loop
# --------------------------------------------------------------------------- #

def test_call_hook_dispatches_and_reports_errors():
    ok = verify_hooks.call_hook("fetch_code_slice", case_id="CASE_03", start_line=38, end_line=44)
    assert ok["ok"] and ok["hook"] == "fetch_code_slice"

    unknown = verify_hooks.call_hook("read_hidden_truth", case_id="CASE_03")
    assert unknown["ok"] is False and "Unknown hook" in unknown["error"]

    blocked = verify_hooks.call_hook("fetch_code_slice", case_id="../truth_private/hidden_truth", start_line=1, end_line=2)
    assert blocked["ok"] is False and "ValueError" in blocked["error"]

    bad_args = verify_hooks.call_hook("fetch_code_slice", case_id="CASE_03")
    assert bad_args["ok"] is False and "TypeError" in bad_args["error"]


def test_bounded_verification_loop_simulation():
    """Mimic Lane 5's loop: at most two hook calls per record, then a decision."""
    budget, calls = 2, []
    plan = [("fetch_code_slice", {"case_id": "CASE_01", "start_line": 48, "end_line": 54}),
            ("inspect_enclosing_method", {"case_id": "CASE_01", "target_line": 55}),
            ("fetch_code_slice", {"case_id": "CASE_01", "start_line": 1, "end_line": 10})]  # over budget
    for name, kwargs in plan:
        if len(calls) >= budget:
            break
        calls.append(verify_hooks.call_hook(name, **kwargs))
    assert len(calls) == 2 and all(c["ok"] for c in calls)
    assert {c["source_hash"] for c in calls} == {calls[0]["source_hash"]}  # same file, same hash


def test_reload_codeql_sarif_matches_the_stored_scan():
    """The hook must return exactly what Lane 3 recorded for every case (no CodeQL needed)."""
    ledger_dir = REPO_ROOT / "reports" / "ledger"
    records = sorted(ledger_dir.glob("CASE_*_A.json"))
    assert len(records) == 20
    for path in records:
        rec = json.loads(path.read_text(encoding="utf-8"))
        res = verify_hooks.call_hook("reload_codeql_sarif", case_id=rec["case_id"], cwe=rec["cwe"])
        assert res["ok"] and res["hook"] == "reload_codeql_sarif"
        assert res["scanner_result"] == rec["codeql"]
        assert res["source_hash"] == rec["source_hash"]
        assert res["sarif_file"] == f"reports/codeql_sarif/{rec['case_id']}.sarif"
        assert len(res["sarif_hash"]) == 64


def test_reload_codeql_sarif_reports_missing_and_blocks_bad_ids(tmp_path, monkeypatch):
    missing = verify_hooks.call_hook("reload_codeql_sarif", case_id="CASE_99", cwe="CWE-89")
    assert missing == {"ok": False, "error": "Source file not found for CASE_99"}

    for bad in ("../truth_private/hidden_truth", "CASE_01/../../README", "CASE_1", ""):
        res = verify_hooks.call_hook("reload_codeql_sarif", case_id=bad, cwe="CWE-89")
        assert res["ok"] is False and "ValueError" in res["error"]

    # A case with source but no stored SARIF is a failed check, not a crash.
    monkeypatch.setattr(verify_hooks, "REPO_ROOT", tmp_path)
    (tmp_path / "cases").mkdir()
    (tmp_path / "cases" / "CASE_01.java").write_text("class A {}\n", encoding="utf-8")
    res = verify_hooks.call_hook("reload_codeql_sarif", case_id="CASE_01", cwe="CWE-22")
    assert res["ok"] is False and "No stored CodeQL SARIF" in res["error"]


@pytest.mark.skipif(__import__("shutil").which("semgrep") is None, reason="semgrep not installed")
def test_rerun_pinned_semgrep_live():
    res = verify_hooks.call_hook("rerun_pinned_semgrep", case_id="CASE_03", cwe="CWE-89")
    assert res["ok"]
    assert res["scanner_result"]["status"] in ("finding", "no_finding")
    assert res["scanner_result"]["version"]
