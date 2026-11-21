import json
import os
from pathlib import Path

from google import genai
from google.genai import types

import time
from google.genai import errors

REPO_ROOT = Path(__file__).resolve().parent.parent
LEDGER_DIR = REPO_ROOT / "reports" / "ledger"


def load_evidence(variant_id: str) -> dict:
    """Load an evidence record without modifying the original file."""

    evidence_path = LEDGER_DIR / f"{variant_id}.json"

    if not evidence_path.is_file():
        raise FileNotFoundError(
            f"Evidence not found for variant: {variant_id}"
        )

    with evidence_path.open("r", encoding="utf-8") as file:
        evidence = json.load(file)

    if not isinstance(evidence, dict):
        raise ValueError("Evidence record must be a JSON object.")

    return evidence

def validate_evidence(evidence: dict) -> dict:
    """Check whether the evidence record contains usable scanner results."""

    required_fields = [
        "case_id",
        "variant_id",
        "cwe",
        "file",
        "source_hash",
        "semgrep",
        "codeql",
    ]

    missing_fields = [
        field for field in required_fields
        if field not in evidence
    ]

    semgrep_status = evidence.get("semgrep", {}).get("status")
    codeql_status = evidence.get("codeql", {}).get("status")

    scanner_statuses = {
        "semgrep": semgrep_status,
        "codeql": codeql_status,
    }

    failed_scanners = [
        name for name, status in scanner_statuses.items()
        if status in (None, "tool_failed")
    ]

    return {
        "schema_valid": len(missing_fields) == 0,
        "missing_fields": missing_fields,
        "scanner_statuses": scanner_statuses,
        "failed_scanners": failed_scanners,
        "evidence_complete": (
            len(missing_fields) == 0
            and len(failed_scanners) == 0
        ),
    }

def estimate_evidence_uncertainty(validation: dict) -> dict:
    """
    Estimate evidence uncertainty from scanner availability.

    This is a provisional rule-based scale, not a
    calibrated probability of vulnerability.
    """

    if not validation["schema_valid"]:
        level = "HIGH"
        reason = "Required evidence fields are missing."

    else:
        failed_count = len(validation["failed_scanners"])

        if failed_count == 2:
            level = "HIGH"
            reason = "Both static scanners failed or are unavailable."

        elif failed_count == 1:
            level = "MEDIUM"
            reason = "One static scanner failed or is unavailable."

        else:
            level = "LOW"
            reason = "Both static scanners returned results."

    return {
        "u_e_level": level,
        "reason": reason,
        "method": "scanner_availability_v1",
    }

def estimate_model_uncertainty(model_response: dict | None = None) -> dict:
    """
    Return model uncertainty when a validated
    model assessment is available.

    Do not fabricate model confidence.
    """

    if model_response is None:
        return {
            "u_m_level": "UNSET",
            "reason": "No model assessment has been performed.",
            "method": "not_evaluated",
        }

    level = model_response.get("u_m_level")

    if level not in {"LOW", "MEDIUM", "HIGH"}:
        return {
            "u_m_level": "UNSET",
            "reason": "No valid model uncertainty level was provided.",
            "method": "not_evaluated",
        }

    return {
        "u_m_level": level,
        "reason": model_response.get(
            "uncertainty_reason",
            "No explanation provided."
        ),
        "method": "model_reported_provisional",
    }

def assess_with_gemini(evidence: dict) -> dict:
    """
    Ask Gemini to provide a provisional security assessment
    using the available Lane 3 evidence.

    This function does not modify the original ledger.
    """

    if not os.getenv("GEMINI_API_KEY"):
        raise RuntimeError(
            "GEMINI_API_KEY is not configured."
        )

    client = genai.Client()

    scanner_context = {
        "case_id": evidence["case_id"],
        "variant_id": evidence["variant_id"],
        "cwe": evidence["cwe"],
        "claim": evidence.get("claim"),
        "file": evidence["file"],
        "line_range": evidence.get("line_range"),
        "semgrep": evidence.get("semgrep"),
        "codeql": evidence.get("codeql"),
    }

    prompt = f"""
You are a Java application security analyst.

Analyze the supplied security evidence for:
- CWE-89: SQL Injection
- CWE-22: Path Traversal

Evidence:
{json.dumps(scanner_context, indent=2)}

IMPORTANT RULES:
1. Treat scanner failures as missing evidence, not proof
   of a vulnerability.
2. Do not invent scanner findings or source-code behavior.
3. If evidence is insufficient, return INSUFFICIENT_EVIDENCE.
4. Distinguish vulnerability assessment from uncertainty.
5. Your uncertainty rating is provisional and uncalibrated.

Return a JSON object containing:
- verdict: VULNERABLE, NOT_VULNERABLE, or INSUFFICIENT_EVIDENCE
- reasoning: concise explanation
- u_m_level: LOW, MEDIUM, or HIGH
- uncertainty_reason: explanation of model uncertainty
"""
    response = None

    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite"),
                contents=prompt,
                config=types.GenerateContentConfig(
                    temperature=0,
                    max_output_tokens=1000,
                    response_mime_type="application/json",
                ),
            )
            break

        except errors.ServerError as error:
            if error.code not in (500, 502, 503, 504):
                raise

            if attempt == 2:
                raise

            wait_time = 2 ** (attempt + 1)
            print(
                f"Gemini temporarily unavailable. "
                f"Retrying in {wait_time} seconds..."
            )
            time.sleep(wait_time)

    if not response or not response.text:
        raise ValueError("Gemini returned an empty response.")

    result = json.loads(response.text)

    if not response.text:
        raise ValueError("Gemini returned an empty response.")

    result = json.loads(response.text)

    allowed_verdicts = {
        "VULNERABLE",
        "NOT_VULNERABLE",
        "INSUFFICIENT_EVIDENCE",
    }

    allowed_uncertainty = {"LOW", "MEDIUM", "HIGH"}

    if not isinstance(result, dict):
        raise ValueError("Gemini response must be a JSON object.")

    if result.get("verdict") not in allowed_verdicts:
        raise ValueError("Invalid Gemini verdict.")

    if result.get("u_m_level") not in allowed_uncertainty:
        raise ValueError("Invalid model uncertainty level.")

    if not isinstance(result.get("reasoning"), str):
        raise ValueError("Missing model reasoning.")

    if not isinstance(result.get("uncertainty_reason"), str):
        raise ValueError("Missing uncertainty explanation.")

    return result

def load_integrity_report(case_id: str) -> dict:
    """
    Load a separately generated source-integrity report
    without modifying the original Evidence Ledger.
    """
    report_path = (
        REPO_ROOT
        / "reports"
        / "integrity"
        / f"{case_id}_integrity.json"
    )

    if not report_path.is_file():
        return {
            "status": "NOT_CHECKED",
            "reason": "No integrity report is available.",
        }

    try:
        with report_path.open("r", encoding="utf-8") as file:
            report = json.load(file)

        if report.get("case_id") != case_id:
            raise ValueError("Integrity report case ID mismatch.")

        return {
            "status": report.get("integrity_status", "UNKNOWN"),
            "manifest_sha256": report.get("manifest_sha256"),
            "actual_sha256": report.get("actual_sha256"),
            "checked_at_utc": report.get("checked_at_utc"),
        }

    except (OSError, ValueError, TypeError) as error:
        return {
            "status": "ERROR",
            "reason": str(error),
        }

def evaluate_variant(variant_id: str) -> dict:
    """
    Combine evidence validation and uncertainty assessments
    without modifying the original Evidence Ledger.
    """

    evidence = load_evidence(variant_id)
    integrity = load_integrity_report(evidence["case_id"])

    validation = validate_evidence(evidence)

    evidence_uncertainty = estimate_evidence_uncertainty(
        validation
    )

        # Integrity safeguard: do not issue a definitive verdict
    # when the source integrity is not verified.
    if integrity.get("status") != "MATCH":
        return {
            "case_id": evidence["case_id"],
            "variant_id": evidence["variant_id"],
            "cwe": evidence["cwe"],
            "integrity": integrity,
            "evidence_validation": validation,
            "u_e": estimate_evidence_uncertainty(validation),
            "u_m": estimate_model_uncertainty(),
            "verdict": "NOT_ASSESSED",
            "assessment_status": "INTEGRITY_CHECK_FAILED",
            "model_assessment": {
                "error": "Source integrity is not verified. Model assessment skipped."
            },
        }

    try:
        model_response = assess_with_gemini(evidence)

        model_uncertainty = estimate_model_uncertainty(
            model_response
        )

        verdict = model_response["verdict"]
        assessment_status = "MODEL_ASSESSED"

    except Exception as error:
        model_response = {
            "error": str(error)
        }

        model_uncertainty = estimate_model_uncertainty()

        verdict = "NOT_ASSESSED"
        assessment_status = "MODEL_ASSESSMENT_FAILED"

    return {
    "case_id": evidence["case_id"],
    "variant_id": evidence["variant_id"],
    "cwe": evidence["cwe"],
    "integrity": integrity,
    "evidence_validation": validation,
    "u_e": evidence_uncertainty,
    "u_m": model_uncertainty,
    "verdict": verdict,
    "assessment_status": assessment_status,
    "model_assessment": model_response,


    }
