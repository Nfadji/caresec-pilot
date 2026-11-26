"""Lane 5 controller tests. No scanners, LLM or network needed: hooks are faked."""

import json

import pytest

from controller import decide as ctl

LANE3_HOOKS = frozenset({"fetch_code_slice", "inspect_enclosing_method", "rerun_pinned_semgrep"})


def scan(status, rule="rule.x", version="1.0", lines="40-40"):
    return {"status": status, "rule_id": rule if status == "finding" else None,
            "version": version, "matched_lines": lines if status == "finding" else None}


def record(semgrep=None, codeql=None, **extra):
    rec = {"case_id": "CASE_03", "variant_id": "CASE_03_A", "cwe": "CWE-89",
           "file": "cases/CASE_03.java", "line_range": "38-44", "source_available": True,
           "source_hash": "abc", "manifest_hash_match": "crlf_normalized",
           "semgrep": semgrep if semgrep is not None else scan("finding"),
           "codeql": codeql if codeql is not None else scan("finding")}
    rec.update(extra)
    return rec


def assessment(u_m="LOW", verdict="VULNERABLE"):
    return {"verdict": verdict, "assessment_status": "MODEL_ASSESSED",
            "u_m": {"u_m_level": u_m}, "u_e": {"u_e_level": "LOW"}}


class FakeHooks:
    """Records calls; returns scripted results per hook name."""

    def __init__(self, **results):
        self.results, self.calls = results, []

    def __call__(self, name, **kwargs):
        self.calls.append((name, kwargs))
        res = self.results.get(name, {"ok": True, "hook": name, "source_hash": "abc"})
        return json.loads(json.dumps(res))


def run(rec, asmt=None, hooks=None, available=LANE3_HOOKS, um=None):
    hooks = hooks or FakeHooks()
    return ctl.run_controller(rec, asmt, um, hooks, available), hooks


# --------------------------------------------------------------------------- #

def test_complete_evidence_low_model_risk_proceeds():
    out, hooks = run(record(), assessment("LOW"))
    assert out["action"] == "PROCEED" and out["conclusion"] == "VULNERABLE"
    assert out["u_m_level"] == "LOW" and out["u_e_level"] == "LOW"
    assert hooks.calls == []


def test_high_model_risk_escalates_without_verifying():
    out, hooks = run(record(semgrep=scan("no_finding")), assessment("HIGH"))
    assert out["action"] == "ESCALATE" and hooks.calls == []
    assert "model-competence" in out["decision"]["final_reason"]


def test_unset_model_risk_never_proceeds():
    out, _ = run(record(), None)
    assert out["action"] == "ESCALATE"
    assert out["decision"]["u_m_source"] == "unset"


def test_cli_override_is_recorded():
    out, _ = run(record(), None, um="LOW")
    assert out["action"] == "PROCEED" and out["decision"]["u_m_source"] == "cli_override"


def test_masked_semgrep_is_recovered_by_rerun_then_proceeds():
    rerun = {"ok": True, "hook": "rerun_pinned_semgrep", "source_hash": "abc",
             "scanner_result": scan("finding")}
    out, hooks = run(record(semgrep={}), assessment("LOW"), FakeHooks(rerun_pinned_semgrep=rerun))
    assert [c[0] for c in hooks.calls] == ["rerun_pinned_semgrep"]
    assert [s["action"] for s in out["decision"]["trace"]] == ["VERIFY", "PROCEED"]


def test_conflict_uses_two_hooks_then_escalates():
    rerun = {"ok": True, "hook": "rerun_pinned_semgrep", "source_hash": "abc",
             "scanner_result": scan("no_finding")}  # disagreement persists
    out, hooks = run(record(semgrep=scan("no_finding")), assessment("LOW"),
                     FakeHooks(rerun_pinned_semgrep=rerun))
    assert [c[0] for c in hooks.calls] == ["rerun_pinned_semgrep", "inspect_enclosing_method"]
    assert out["action"] == "ESCALATE" and out["decision"]["verify_calls"] == 2
    # disputed line comes from the scanner that fired (codeql at line 40)
    assert hooks.calls[1][1]["target_line"] == 40


def test_budget_never_exceeds_two_calls():
    failing = {"ok": False, "error": "semgrep not found"}
    rec = record(semgrep=scan("no_finding"), source_available=False)
    out, hooks = run(rec, assessment("LOW"), FakeHooks(rerun_pinned_semgrep=failing))
    assert len(hooks.calls) == 2 and out["decision"]["verify_calls"] == 2
    assert out["action"] == "ESCALATE"


def test_failed_hook_is_not_new_evidence():
    failing = {"ok": False, "error": "semgrep not found"}
    out, _ = run(record(semgrep={"status": "tool_failed"}), assessment("LOW"),
                 FakeHooks(rerun_pinned_semgrep=failing))
    assert out["action"] == "ESCALATE"
    assert "semgrep_failed" in out["decision"]["final_evidence_gaps"]


def test_codeql_gap_without_codeql_hook_escalates_immediately():
    out, hooks = run(record(codeql=scan("finding", rule=None)), assessment("LOW"))
    assert hooks.calls == [] and out["action"] == "ESCALATE"
    assert "no permitted read-only check" in out["decision"]["final_reason"]


def test_codeql_hook_is_used_when_lane3_adds_it():
    reload = {"ok": True, "hook": "reload_codeql_sarif", "source_hash": "abc", "scanner_result": scan("finding")}
    out, hooks = run(record(codeql={}), assessment("LOW"), FakeHooks(reload_codeql_sarif=reload),
                     available=LANE3_HOOKS | {"reload_codeql_sarif"})
    assert [c[0] for c in hooks.calls] == ["reload_codeql_sarif"] and out["action"] == "PROCEED"


def test_agent_contradicting_unanimous_scanners_escalates():
    out, _ = run(record(), assessment("LOW", verdict="NOT_VULNERABLE"))
    assert out["action"] == "ESCALATE"
    assert "agent_scanner_conflict" in out["decision"]["final_evidence_gaps"]


def test_hash_change_during_verify_flags_integrity():
    changed = {"ok": True, "hook": "fetch_code_slice", "source_hash": "zzz", "line_range": "38-44"}
    out, _ = run(record(source_available=False), assessment("LOW"), FakeHooks(fetch_code_slice=changed))
    assert out["action"] == "ESCALATE" and "source_integrity" in out["decision"]["final_evidence_gaps"]


def test_original_evidence_is_not_overwritten():
    rerun = {"ok": True, "hook": "rerun_pinned_semgrep", "source_hash": "abc", "scanner_result": scan("finding")}
    rec = record(semgrep={})
    out, _ = run(rec, assessment("LOW"), FakeHooks(rerun_pinned_semgrep=rerun))
    assert rec["semgrep"] == {} and out["semgrep"] == {}
    assert out["decision"]["evidence_collected"][0]["scanner_result"]["status"] == "finding"


@pytest.mark.parametrize("bad", ["CASE_01", "CASE_01_E", "../truth_private/x_A"])
def test_variant_id_validation(bad):
    with pytest.raises(ValueError):
        ctl.parse_variant_id(bad)


def test_variants_bcd_come_from_lane2_and_ledger():
    b = ctl.load_record("CASE_02_B")
    d = ctl.load_record("CASE_02_D")
    assert b["semgrep"] is None and b["codeql"] is None and b["evidence_condition"] == "B_MASKED"
    assert "rule_id" not in d["codeql"] and d["evidence_condition"] == "D_PROVENANCE_GAP"


def test_controller_never_reads_hidden_truth(monkeypatch):
    opened = []
    real_open = open

    def spy(path, *a, **k):
        opened.append(str(path))
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", spy)
    ctl.load_record("CASE_01_C")
    assert not any("truth_private" in p or "hidden_truth" in p for p in opened)


def test_bcd_do_not_inherit_condition_a_decision(monkeypatch, tmp_path):
    a = record(variant_id="CASE_02_A", u_m_level="LOW", u_e_level="MEDIUM", action="ESCALATE",
               decision_trace=[{"hook_result": "semgrep rerun -> no_finding"}],
               decision_policy="lane5-rules-v1")
    a["case_id"] = "CASE_02"
    (tmp_path / "CASE_02_A.json").write_text(json.dumps(a), encoding="utf-8")
    monkeypatch.setattr(ctl, "LEDGER_DIR", tmp_path)
    monkeypatch.setattr(ctl, "_lane2_variants", lambda: (
        {"record_id": "CASE_02_B", "evidence": {}, "variant_status": "ready", "masked_fields": ["semgrep"]},))
    b = ctl.load_record("CASE_02_B")
    assert not {"decision_trace", "decision_policy"} & set(b)
    assert (b["u_m_level"], b["u_e_level"], b["action"]) == ("UNSET", "UNSET", "PENDING")


def test_um_override_never_writes_the_ledger(monkeypatch, tmp_path):
    ledger = tmp_path / "ledger"
    ledger.mkdir()
    rec = record(u_m_level="UNSET", u_e_level="UNSET", action="PENDING")
    (ledger / "CASE_03_A.json").write_text(json.dumps(rec), encoding="utf-8")
    before = (ledger / "CASE_03_A.json").read_text(encoding="utf-8")
    monkeypatch.setattr(ctl, "LEDGER_DIR", ledger)
    monkeypatch.setattr(ctl, "OUT_DIR", tmp_path / "out")
    monkeypatch.setattr(ctl, "AGENT_DIR", tmp_path / "agent")
    monkeypatch.setattr(ctl, "_default_hook", lambda: FakeHooks())
    monkeypatch.setattr(ctl, "_available_hooks", lambda: LANE3_HOOKS)
    monkeypatch.setattr(ctl, "REPO_ROOT", tmp_path)
    assert ctl.main(["--run", "CASE_03_A", "--um", "LOW"]) == 0
    assert (ledger / "CASE_03_A.json").read_text(encoding="utf-8") == before
    assert json.loads((tmp_path / "out" / "CASE_03_A.json").read_text())["decision"]["u_m_source"] == "cli_override"
    assert ctl.main(["--run", "CASE_03_A"]) == 0  # without --um the ledger is filled in
    written = json.loads((ledger / "CASE_03_A.json").read_text(encoding="utf-8"))
    assert written["action"] == "ESCALATE" and written["u_m_level"] == "UNSET"


def test_condition_a_ignores_an_earlier_decision(monkeypatch, tmp_path):
    a = record(u_m_level="LOW", action="PROCEED", decision_trace=[{"step": 1}], decision_policy="old")
    (tmp_path / "CASE_03_A.json").write_text(json.dumps(a), encoding="utf-8")
    monkeypatch.setattr(ctl, "LEDGER_DIR", tmp_path)
    rec = ctl.load_record("CASE_03_A")
    assert "decision_trace" not in rec and rec["action"] == "PENDING" and rec["u_m_level"] == "UNSET"
