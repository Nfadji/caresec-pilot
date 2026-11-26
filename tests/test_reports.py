"""Lane 6: tests for the evaluation summary and the blinded reviewer packet.

Run with: python -m pytest tests/test_reports.py -q
Everything runs on made-up outputs in a temporary folder. The labels used here are
invented for the tests and say nothing about the real cases.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from reports import blind_packet, summarize

CASES = [{"case_id": "CASE_01", "cwe": "CWE-22"}, {"case_id": "CASE_02", "cwe": "CWE-89"}]
MADE_UP_TRUTH = {"CASE_01": "VULNERABLE", "CASE_02": "NOT_VULNERABLE"}


def _agent(root: Path, vid: str, verdict: str, folder: str = "reports/agent") -> None:
    path = root / folder / f"{vid}_assessment.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"variant_id": vid, "verdict": verdict}), encoding="utf-8")


def _controller(root: Path, vid: str, action: str, conclusion: str | None = None, calls: int = 0,
                source: str = "lane4") -> None:
    path = root / "reports" / "controller" / f"{vid}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"variant_id": vid, "action": action, "conclusion": conclusion,
                                "decision": {"u_m_source": source, "verify_calls": calls}}), encoding="utf-8")


@pytest.fixture
def made_up_run(tmp_path: Path) -> Path:
    """Two cases, eight records. B2 answers everything; B3 escalates the hard ones."""
    for vid, verdict in {"CASE_01_A": "VULNERABLE", "CASE_01_B": "NOT_VULNERABLE", "CASE_01_C": "VULNERABLE",
                         "CASE_01_D": "INSUFFICIENT_EVIDENCE", "CASE_02_A": "NOT_VULNERABLE",
                         "CASE_02_B": "VULNERABLE", "CASE_02_C": "NOT_VULNERABLE", "CASE_02_D": "NOT_VULNERABLE"}.items():
        _agent(tmp_path, vid, verdict)
    _controller(tmp_path, "CASE_01_A", "PROCEED", "VULNERABLE")
    _controller(tmp_path, "CASE_01_B", "ESCALATE", calls=1)        # B2 was wrong here
    _controller(tmp_path, "CASE_01_C", "ESCALATE", calls=2)        # B2 was right here
    _controller(tmp_path, "CASE_01_D", "ESCALATE", calls=1)
    _controller(tmp_path, "CASE_02_A", "PROCEED", "NOT_VULNERABLE")
    _controller(tmp_path, "CASE_02_B", "PROCEED", "VULNERABLE", calls=1)   # a wrong final answer
    _controller(tmp_path, "CASE_02_C", "PROCEED", "NOT_VULNERABLE", source="cli_override")  # demo run
    # CASE_02_D: no controller output at all
    return tmp_path


# --------------------------------------------------------------------------- #
# reports.summarize
# --------------------------------------------------------------------------- #

def test_counts_without_truth(made_up_run):
    m = summarize.compute(summarize.collect(CASES, made_up_run))
    assert m["records"] == 8 and m["base_cases"] == 2 and m["truth_used"] is False
    assert m["baselines"]["B1"]["per_record"] == {"records": 8, "concluded": 0, "deferred": 0, "missing": 8, "excluded": 0}
    assert m["baselines"]["B2"]["per_record"] == {"records": 8, "concluded": 7, "deferred": 1, "missing": 0, "excluded": 0}
    assert m["baselines"]["B3"]["per_record"] == {"records": 8, "concluded": 3, "deferred": 3, "missing": 1, "excluded": 1}
    assert m["verification"] == {"records_decided": 6, "records_with_a_verify_call": 4, "verify_calls_total": 5,
                                 "by_condition": {"A": 0, "B": 2, "C": 2, "D": 1}}
    assert "escalation_vs_b2" not in m and "correct" not in m["baselines"]["B2"]["per_record"]


def test_correctness_with_truth_on_both_denominators(made_up_run):
    m = summarize.compute(summarize.collect(CASES, made_up_run), MADE_UP_TRUTH)
    b2, b3 = m["baselines"]["B2"], m["baselines"]["B3"]
    assert (b2["per_record"]["correct"], b2["per_record"]["wrong"]) == (5, 2)
    assert (b2["per_record"]["missed_vulnerability"], b2["per_record"]["false_alarm"]) == (1, 1)
    assert (b3["per_record"]["correct"], b3["per_record"]["wrong"]) == (2, 1)
    assert (b3["per_record"]["missed_vulnerability"], b3["per_record"]["false_alarm"]) == (0, 1)
    assert b2["per_base_case"]["cases_with_a_wrong_conclusion"] == 2
    assert b3["per_base_case"]["cases_with_a_wrong_conclusion"] == 1
    assert b3["per_base_case"]["cases_all_records_concluded_correctly"] == 0
    assert m["escalation_vs_b2"] == {"b3_deferred_where_b2_concluded": 2, "b2_would_have_been_wrong": 1,
                                     "b2_would_have_been_right": 1}
    assert b3["by_condition"]["B"]["wrong"] == 1 and b3["by_cwe"]["CWE-89"]["wrong"] == 1


def test_demo_override_runs_are_never_counted_as_results(made_up_run):
    rows = summarize.collect(CASES, made_up_run)
    row = next(r for r in rows if r["variant_id"] == "CASE_02_C")
    assert row["B3"] == {"state": "excluded", "answer": None}


def test_b1_is_read_when_a_lane_starts_writing_it(made_up_run):
    _agent(made_up_run, "CASE_01_A", "VULNERABLE", folder="reports/agent_b1")
    m = summarize.compute(summarize.collect(CASES, made_up_run), MADE_UP_TRUTH)
    assert m["baselines"]["B1"]["per_record"]["concluded"] == 1 and m["baselines"]["B1"]["per_record"]["correct"] == 1


def test_public_summary_is_aggregate_only(made_up_run):
    metrics = summarize.compute(summarize.collect(CASES, made_up_run), MADE_UP_TRUTH)
    public = summarize.render(metrics) + json.dumps(metrics)
    assert "CASE_" not in public                      # no record or case is named
    assert "8 (2 base cases x 4 conditions)" in public and "Correctness of final answers" in public
    no_truth = summarize.render(summarize.compute(summarize.collect(CASES, made_up_run)))
    assert "correctness is not reported" in no_truth and "Correctness of final answers" not in no_truth


def test_truth_file_shapes_and_spellings(tmp_path):
    ids = ["CASE_01", "CASE_02", "CASE_03"]
    as_object = tmp_path / "a.json"
    as_object.write_text(json.dumps({"CASE_01": {"correctness_label": "true_positive"},
                                     "CASE_02": {"expected_label": False}, "CASE_03": "Not Vulnerable"}), encoding="utf-8")
    assert summarize.load_truth(as_object, ids) == {"CASE_01": "VULNERABLE", "CASE_02": "NOT_VULNERABLE",
                                                    "CASE_03": "NOT_VULNERABLE"}
    as_list = tmp_path / "b.json"
    as_list.write_text(json.dumps([{"case_id": "CASE_01", "label": "vulnerable"}, {"case_id": "CASE_02", "label": "safe"},
                                   {"case_id": "CASE_03", "is_vulnerable": True}]), encoding="utf-8")
    assert summarize.load_truth(as_list, ids)["CASE_03"] == "VULNERABLE"


def test_partial_or_unreadable_truth_is_an_error_not_a_smaller_denominator(tmp_path):
    path = tmp_path / "t.json"
    path.write_text(json.dumps({"CASE_01": {"correctness_label": "maybe"}, "CASE_02": {"notes": "none"}}), encoding="utf-8")
    with pytest.raises(ValueError, match="no usable label for 3 case"):
        summarize.load_truth(path, ["CASE_01", "CASE_02", "CASE_03"])


def test_cli_writes_public_counts_and_keeps_detail_private(made_up_run, tmp_path, monkeypatch, capsys):
    truth = tmp_path / "private" / "hidden_truth.json"
    truth.parent.mkdir()
    truth.write_text(json.dumps({c: {"correctness_label": v} for c, v in MADE_UP_TRUTH.items()}), encoding="utf-8")
    monkeypatch.setattr(summarize, "load_cases", lambda: CASES)
    monkeypatch.setattr(summarize, "REPO_ROOT", made_up_run)
    monkeypatch.setattr(summarize, "collect", lambda cases, root=made_up_run, _c=summarize.collect: _c(cases, root))
    monkeypatch.setattr(summarize, "PRIVATE_OUT", tmp_path / "private" / "eval")
    out = tmp_path / "public"

    assert summarize.main(["--truth", str(truth), "--out", str(out)]) == 0
    public = (out / "summary.md").read_text(encoding="utf-8") + (out / "metrics.json").read_text(encoding="utf-8")
    assert "CASE_" not in public and sorted(p.name for p in out.iterdir()) == ["metrics.json", "summary.md"]
    with (tmp_path / "private" / "eval" / "per_record.csv").open(encoding="utf-8", newline="") as f:
        detail = list(csv.DictReader(f))
    assert len(detail) == 8 and detail[0]["truth"] == "VULNERABLE"

    assert summarize.main(["--truth", str(tmp_path / "absent.json"), "--no-write"]) == 0
    assert "No truth file" in capsys.readouterr().err


def test_summary_runs_on_the_real_repository_as_it_is():
    """Whatever the lanes have produced so far, the frozen CLI must run and name no record."""
    metrics = summarize.compute(summarize.collect(summarize.load_cases()))
    assert metrics["records"] == 80 and metrics["base_cases"] == 20
    assert "CASE_" not in summarize.render(metrics)


# --------------------------------------------------------------------------- #
# reports.blind_packet
# --------------------------------------------------------------------------- #

def test_packet_is_balanced_shuffled_and_repeatable():
    rows = blind_packet.load_manifest()
    picked = blind_packet.choose_cases(rows, 8, seed=1)
    assert len({r["case_id"] for r in picked}) == 8
    assert sorted(r["CWE"] for r in picked) == ["CWE-22"] * 4 + ["CWE-89"] * 4
    assert [r["case_id"] for r in picked] == [r["case_id"] for r in blind_packet.choose_cases(rows, 8, seed=1)]
    assert [r["case_id"] for r in picked] != [r["case_id"] for r in blind_packet.choose_cases(rows, 8, seed=2)]
    assert len(blind_packet.choose_cases(rows, 20, seed=1)) == 20
    with pytest.raises(ValueError):
        blind_packet.choose_cases(rows, 21, seed=1)


def test_packet_hides_case_ids_and_every_system_output():
    packet, sheet, key = blind_packet.build(blind_packet.load_manifest(), 20, seed=3)
    assert "CASE_" not in packet and "CASE_" not in json.dumps(sheet)
    for word in ("semgrep", "codeql", "PROCEED", "ESCALATE", "u_m_level", "verdict", "finding"):
        assert word.lower() not in packet.lower(), word
    assert [s["item_id"] for s in sheet] == [f"ITEM_{i:02d}" for i in range(1, 21)]
    assert all(s["reviewer_label"] == "" and s["reviewer_confidence"] == "" for s in sheet)
    assert sorted(k["case_id"] for k in key) == [f"CASE_{i:02d}" for i in range(1, 21)]
    assert [k["case_id"] for k in key] != sorted(k["case_id"] for k in key)  # order is shuffled


def test_packet_line_numbers_match_the_claim():
    rows = [r for r in blind_packet.load_manifest() if r["case_id"] == "CASE_01"]
    packet, sheet, _ = blind_packet.build(rows, 1, seed=0)
    source = (blind_packet.REPO_ROOT / "cases" / "CASE_01.java").read_text(encoding="utf-8").splitlines()
    start = int(sheet[0]["lines_in_question"].split("-")[0])
    expected = blind_packet.CASE_TOKEN.sub("ITEM_01", source[start - 1])
    assert f"{start}  {expected}" in packet


def test_packet_cli_keeps_the_key_out_of_the_public_folder(tmp_path):
    out, key = tmp_path / "review_packet", tmp_path / "truth_private" / "review_key.csv"
    assert blind_packet.main(["--n", "4", "--out", str(out), "--key", str(key)]) == 0
    assert sorted(p.name for p in out.iterdir()) == ["packet.md", "review_sheet.csv"]
    with key.open(encoding="utf-8", newline="") as f:
        assert len(list(csv.DictReader(f))) == 4
    with (out / "review_sheet.csv").open(encoding="utf-8", newline="") as f:
        assert next(csv.reader(f)) == blind_packet.SHEET_COLUMNS
