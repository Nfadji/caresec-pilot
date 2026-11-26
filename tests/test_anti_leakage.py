"""Lane 6: anti-leakage checks.

The hidden truth (truth_private/hidden_truth.json, manifests/case_manifest.csv) and the
upstream benchmark labels must never reach an agent prompt or a public file.

Run with: python -m pytest tests/test_anti_leakage.py -q
No scanner, model, API key or private file is needed.
"""

from __future__ import annotations

import csv
import importlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_DIR = REPO_ROOT / "reports" / "ledger"
CASES = [f"CASE_{n:02d}" for n in range(1, 21)]

PRIVATE_PATH_TOKENS = ("truth_private", "hidden_truth", "manifests/case_manifest.csv")
# Field names that carry a label in the private files. None may appear as a JSON key
# or a CSV column in anything public.
LABEL_FIELDS = {"expected_label", "correctness_label", "ground_truth", "hidden_truth", "true_label",
                "is_vulnerable", "label", "label_source", "original_test", "expected_result",
                "expected_review", "adjudication_notes", "benchmark_label", "real_vulnerability"}
# Upstream test names map straight to a published label (OWASP Benchmark expected-results
# file, Juliet good/bad naming), so they are as sensitive as the label itself.
UPSTREAM_NAMES = re.compile(r"BenchmarkTest\d{3,}|CWE\d+_[A-Za-z_]+__\w+")
SOURCE_HINTS = re.compile(r"POTENTIAL FLAW|\bFIX:|INCIDENTAL|\bgood(G2B|B2G)?\d*\s*\(|\bbad\s*\(")
DATA_DIRS = ("cases", "manifests", "reports", "variants")
DATA_SUFFIXES = {".json", ".sarif", ".csv", ".md", ".txt", ".java"}


def public_data_files() -> list[Path]:
    """Files under the data folders that git publishes (or, without git, that exist here)."""
    if shutil.which("git") and (REPO_ROOT / ".git").exists():
        out = subprocess.run(["git", "ls-files", "-z", "--", *DATA_DIRS], cwd=REPO_ROOT,
                             capture_output=True, check=True).stdout.decode("utf-8")
        paths = [REPO_ROOT / p for p in out.split("\0") if p]
    else:
        paths = [p for d in DATA_DIRS for p in (REPO_ROOT / d).rglob("*") if p.is_file()]
        paths = [p for p in paths if "truth_private" not in p.parts and p.name != "case_manifest.csv"]
    return sorted(p for p in paths if p.suffix.lower() in DATA_SUFFIXES and p.is_file())


def json_keys(node, found: set[str]) -> set[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            found.add(str(key).lower())
            json_keys(value, found)
    elif isinstance(node, list):
        for item in node:
            json_keys(item, found)
    return found


# --------------------------------------------------------------------------- #
# Private files stay private
# --------------------------------------------------------------------------- #

def test_private_files_are_ignored_by_git():
    ignored = {line.strip() for line in (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()}
    assert "/truth_private/" in ignored
    assert "/manifests/case_manifest.csv" in ignored


def test_no_private_file_is_tracked():
    if not (shutil.which("git") and (REPO_ROOT / ".git").exists()):
        pytest.skip("not a git checkout")
    tracked = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout
    leaked = [p for p in tracked.splitlines() if any(t in p for t in PRIVATE_PATH_TOKENS)]
    assert leaked == []


# --------------------------------------------------------------------------- #
# Public files carry no label
# --------------------------------------------------------------------------- #

def test_there_is_public_data_to_check():
    files = public_data_files()
    assert len([p for p in files if p.suffix == ".java"]) == 20
    assert len([p for p in files if p.parent == LEDGER_DIR]) >= 21


def test_public_data_files_have_no_label_fields():
    offenders = []
    for path in public_data_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if path.suffix.lower() in (".json", ".sarif"):
            keys = json_keys(json.loads(path.read_text(encoding="utf-8")), set())
        elif path.suffix.lower() == ".csv":
            with path.open(encoding="utf-8-sig", newline="") as f:
                keys = {c.strip().lower() for c in next(csv.reader(f), [])}
        else:
            continue
        offenders += [f"{rel}: {k}" for k in sorted(keys & LABEL_FIELDS)]
    assert offenders == []


def test_public_data_files_have_no_upstream_test_names():
    offenders = []
    for path in public_data_files():
        match = UPSTREAM_NAMES.search(path.read_text(encoding="utf-8", errors="replace"))
        if match:
            offenders.append(f"{path.relative_to(REPO_ROOT).as_posix()}: {match.group(0)}")
    assert offenders == []


def test_case_sources_have_no_label_hints():
    offenders = []
    for cid in CASES:
        match = SOURCE_HINTS.search((REPO_ROOT / "cases" / f"{cid}.java").read_text(encoding="utf-8", errors="replace"))
        if match:
            offenders.append(f"{cid}: {match.group(0)}")
    assert offenders == []


def test_no_filled_in_review_sheet_is_public():
    """Reviewer answers are labels. A review sheet may be published only while it is empty."""
    offenders = []
    for path in public_data_files():
        if path.suffix.lower() != ".csv":
            continue
        with path.open(encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
        if rows and "reviewer_label" in rows[0] and any((r.get("reviewer_label") or "").strip() for r in rows):
            offenders.append(path.relative_to(REPO_ROOT).as_posix())
    assert offenders == []


# --------------------------------------------------------------------------- #
# What the model is shown (Lane 4)
# --------------------------------------------------------------------------- #

@pytest.fixture
def agent_with_recorder(monkeypatch):
    """agent.evaluate with the Gemini client swapped for a recorder: no network, no key."""
    prompts: list[str] = []

    class _Models:
        def generate_content(self, model=None, contents=None, config=None):
            prompts.append(contents)
            return SimpleNamespace(text=json.dumps({
                "verdict": "NOT_VULNERABLE", "reasoning": "recorded", "u_m_level": "LOW",
                "uncertainty_reason": "recorded"}))

    class _Client:
        def __init__(self, *args, **kwargs):
            self.models = _Models()

    genai = ModuleType("google.genai")
    genai.Client = _Client
    genai.types = ModuleType("google.genai.types")
    genai.types.GenerateContentConfig = lambda **kwargs: kwargs
    genai.errors = ModuleType("google.genai.errors")
    genai.errors.ServerError = type("ServerError", (Exception,), {"code": 0})
    google = ModuleType("google")
    google.genai = genai
    for name, module in (("google", google), ("google.genai", genai),
                         ("google.genai.types", genai.types), ("google.genai.errors", genai.errors)):
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.delitem(sys.modules, "agent.evaluate", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "not-a-real-key")
    module = importlib.import_module("agent.evaluate")
    yield module, prompts
    sys.modules.pop("agent.evaluate", None)  # never leave the recorder-backed module behind


def test_agent_prompt_shows_evidence_but_no_label_and_no_decision(agent_with_recorder):
    agent, prompts = agent_with_recorder
    assert hasattr(agent, "assess_with_gemini"), "Lane 4 changed its model call; update this check"
    record = json.loads((LEDGER_DIR / "CASE_02_A.json").read_text(encoding="utf-8"))
    record.update({
        "expected_label": "CANARY_LABEL_7f3a",
        "correctness_label": "CANARY_LABEL_7f3a",
        "original_test": "CANARY_UPSTREAM_91c2",
        "hidden_truth": {"anything": "CANARY_TRUTH_55d0"},
        "decision_trace": [{"step": 1, "action": "ESCALATE", "reason": "CANARY_DECISION_c0de"}],
        "decision_policy": "CANARY_POLICY_0a1b",
    })
    agent.assess_with_gemini(record)

    assert len(prompts) == 1
    prompt = prompts[0]
    assert "CASE_02_A" in prompt and "java/path-injection" in prompt  # the real evidence is there
    for planted in ("CANARY_LABEL_7f3a", "CANARY_UPSTREAM_91c2", "CANARY_TRUTH_55d0",
                    "CANARY_DECISION_c0de", "CANARY_POLICY_0a1b"):
        assert planted not in prompt
    for field in ("expected_label", "correctness_label", "hidden_truth", "decision_trace", "decision_policy"):
        assert field not in prompt


# --------------------------------------------------------------------------- #
# What the pipeline reads (Lanes 2, 3 and 5 together, all 80 records)
# --------------------------------------------------------------------------- #

_opened: list[str] | None = None
_hook_installed = False


def _record_opens(event: str, args: tuple) -> None:
    if _opened is not None and event == "open" and args and isinstance(args[0], (str, bytes, Path)):
        name = args[0].decode("utf-8", "replace") if isinstance(args[0], bytes) else str(args[0])
        _opened.append(name.replace("\\", "/"))


@pytest.fixture
def opened_files():
    """Every file the Python process opens while the test runs (audit hook, not a patch of open)."""
    global _opened, _hook_installed
    if not _hook_installed:
        sys.addaudithook(_record_opens)
        _hook_installed = True
    _opened = []
    yield _opened
    _opened = None


def _private(paths: list[str]) -> list[str]:
    return sorted({p for p in paths if any(t in p for t in PRIVATE_PATH_TOKENS)})


def test_the_open_recorder_would_catch_a_private_read(opened_files, tmp_path):
    decoy = tmp_path / "truth_private" / "hidden_truth.json"
    decoy.parent.mkdir()
    decoy.write_text("{}", encoding="utf-8")
    opened_files.clear()
    json.loads(decoy.read_text(encoding="utf-8"))
    assert _private(opened_files) != []


def test_full_decision_run_opens_no_private_file_and_emits_no_label(opened_files):
    from controller import decide
    from scanners import verify_hooks

    def hook(name: str, **kwargs) -> dict:
        if name == "rerun_pinned_semgrep":
            # The real hook needs the Semgrep CLI. Answer from the stored scan instead.
            rec = json.loads((LEDGER_DIR / f"{kwargs['case_id']}_A.json").read_text(encoding="utf-8"))
            return {"ok": True, "hook": name, "case_id": kwargs["case_id"],
                    "source_hash": rec["source_hash"], "scanner_result": rec["semgrep"]}
        return verify_hooks.call_hook(name, **kwargs)

    decide._lane2_variants.cache_clear()  # make Lane 2's generator read its inputs again
    outputs = []
    for vid in (f"{c}_{k}" for c in CASES for k in "ABCD"):
        record = decide.load_record(vid)
        outputs.append(decide.run_controller(record, decide.load_assessment(vid), "LOW", hook,
                                             frozenset(verify_hooks.HOOKS)))

    assert len(outputs) == 80
    assert {o["action"] for o in outputs} <= {"PROCEED", "ESCALATE"}
    assert all(o["decision"]["verify_calls"] <= 2 for o in outputs)
    assert sum("reports/ledger/CASE_" in p for p in opened_files) >= 20  # the recorder saw real reads
    assert _private(opened_files) == []
    assert json_keys(outputs, set()) & LABEL_FIELDS == set()
    assert not UPSTREAM_NAMES.search(json.dumps(outputs))


# --------------------------------------------------------------------------- #
# Conditions stay separate
# --------------------------------------------------------------------------- #

def test_masked_condition_shows_no_scanner_evidence():
    from controller import decide
    for cid in CASES:
        record = decide.load_record(f"{cid}_B")
        assert record["evidence_condition"] == "B_MASKED"
        assert not record.get("semgrep") and not record.get("codeql"), cid


@pytest.mark.xfail(strict=True, reason=(
    "controller.decide.load_record copies decision_trace and decision_policy from the condition A "
    "file into the B, C and D records (reported in the review of PR #11). "
    "Remove this marker once that is fixed."))
def test_other_conditions_do_not_inherit_the_condition_a_decision():
    from controller import decide
    carried = [f"{cid}_{k}" for cid in CASES for k in "BCD"
               if {"decision_trace", "decision_policy"} & set(decide.load_record(f"{cid}_{k}"))]
    assert carried == []
