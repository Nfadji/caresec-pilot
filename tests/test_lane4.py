
from agent.evaluate import estimate_model_uncertainty


def test_model_uncertainty_when_assessment_missing():
    """Missing model assessment should be reported as unset."""

    result = estimate_model_uncertainty()

    assert result["u_m_level"] == "UNSET"
    assert result["method"] == "not_evaluated"


def test_model_uncertainty_when_evidence_insufficient():
    """Insufficient evidence should produce high model uncertainty."""

    model_response = {
        "verdict": "INSUFFICIENT_EVIDENCE",
        "reasoning": "No actionable scanner findings.",
        "u_m_level": "HIGH",
        "uncertainty_reason": "Insufficient evidence to assess vulnerability."
    }

    result = estimate_model_uncertainty(model_response)

    assert result["u_m_level"] == "HIGH"

from agent.evaluate import (
    validate_evidence,
    estimate_evidence_uncertainty,
)


def test_failed_scanners_produce_high_uncertainty():
    """Scanner failures must be treated as missing evidence."""

    validation = {
        "schema_valid": True,
        "missing_fields": [],
        "scanner_statuses": {
            "semgrep": "tool_failed",
            "codeql": "tool_failed",
        },
        "failed_scanners": ["semgrep", "codeql"],
        "evidence_complete": False,
    }

    result = estimate_evidence_uncertainty(validation)

    assert result["u_e_level"] == "HIGH"
    assert result["method"] == "scanner_availability_v1"


def test_case01_evidence_validation():
    """CASE_01_A must report failed scanners accurately."""

    from agent.evaluate import load_evidence

    evidence = load_evidence("CASE_01_A")
    validation = validate_evidence(evidence)

    assert validation["schema_valid"] is True
    assert validation["evidence_complete"] is False
    assert "semgrep" in validation["failed_scanners"]
    assert "codeql" in validation["failed_scanners"]

from agent.evaluate import load_integrity_report


def test_case01_integrity_mismatch():
    """Lane 4 must preserve the reported source hash mismatch."""

    integrity = load_integrity_report("CASE_01")

    assert integrity["status"] == "MISMATCH"

    assert integrity["manifest_sha256"] != integrity["actual_sha256"]

    assert len(integrity["manifest_sha256"]) == 64
    assert len(integrity["actual_sha256"]) == 64

from unittest.mock import patch
from agent.evaluate import evaluate_variant


def test_lane4_pipeline_with_mocked_gemini():
    """Test Lane 4 with verified integrity and mocked Gemini."""

    from unittest.mock import patch
    from agent.evaluate import evaluate_variant

    fake_response = {
        "verdict": "INSUFFICIENT_EVIDENCE",
        "reasoning": "Both scanners failed.",
        "u_m_level": "HIGH",
        "uncertainty_reason": "No actionable evidence available.",
    }

    verified_integrity = {
        "status": "MATCH",
        "manifest_sha256": "test_hash",
        "actual_sha256": "test_hash",
    }

    with patch(
        "agent.evaluate.load_integrity_report",
        return_value=verified_integrity,
    ), patch(
        "agent.evaluate.assess_with_gemini",
        return_value=fake_response,
    ) as mocked_gemini:

        result = evaluate_variant("CASE_01_A")

        mocked_gemini.assert_called_once()

    assert result["case_id"] == "CASE_01"
    assert result["variant_id"] == "CASE_01_A"
    assert result["integrity"]["status"] == "MATCH"
    assert result["u_e"]["u_e_level"] == "HIGH"
    assert result["u_m"]["u_m_level"] == "HIGH"
    assert result["verdict"] == "INSUFFICIENT_EVIDENCE"
    assert result["assessment_status"] == "MODEL_ASSESSED"
    assert result["model_assessment"] == fake_response



def test_lane4_handles_gemini_failure():
    """An API failure must not become a vulnerability verdict."""

    from unittest.mock import patch
    from agent.evaluate import evaluate_variant

    verified_integrity = {
        "status": "MATCH",
        "manifest_sha256": "test_hash",
        "actual_sha256": "test_hash",
    }

    with patch(
        "agent.evaluate.load_integrity_report",
        return_value=verified_integrity,
    ), patch(
        "agent.evaluate.assess_with_gemini",
        side_effect=RuntimeError("503 UNAVAILABLE"),
    ) as mocked_gemini:

        result = evaluate_variant("CASE_01_A")

        mocked_gemini.assert_called_once()

    assert result["case_id"] == "CASE_01"
    assert result["variant_id"] == "CASE_01_A"
    assert result["integrity"]["status"] == "MATCH"
    assert result["verdict"] == "NOT_ASSESSED"
    assert result["assessment_status"] == "MODEL_ASSESSMENT_FAILED"
    assert result["u_m"]["u_m_level"] == "UNSET"
    assert "503 UNAVAILABLE" in result["model_assessment"]["error"]


def test_lane4_blocks_gemini_on_integrity_mismatch():
    """Gemini must never run when source integrity is unverified."""

    with patch(
        "agent.evaluate.assess_with_gemini",
        side_effect=AssertionError("Gemini must not be called"),
    ) as mocked_gemini:

        result = evaluate_variant("CASE_01_A")

    mocked_gemini.assert_not_called()

    assert result["integrity"]["status"] == "MISMATCH"
    assert result["verdict"] == "NOT_ASSESSED"
    assert result["assessment_status"] == "INTEGRITY_CHECK_FAILED"
    assert result["u_m"]["u_m_level"] == "UNSET"
