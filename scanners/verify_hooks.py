"""
CARE-Sec Pilot — Read-Only Verification Hooks (Lane 3 -> Lane 5 Interface)
"""

import re
from pathlib import Path
from scanners.run import compute_sha256, run_codeql, run_semgrep

REPO_ROOT = Path(__file__).resolve().parent.parent
FORBIDDEN_TOKENS = ("truth_private", "hidden_truth", "case_manifest.csv")
CASE_ID_RE = re.compile(r"^CASE_\d{2}$")


def _guard_path(path: Path) -> None:
    resolved = str(path.resolve()).replace("\\", "/")
    for token in FORBIDDEN_TOKENS:
        if token in resolved:
            raise PermissionError(f"Anti-leakage block: access to '{token}' is forbidden.")
    # Hooks may only read the public case files, never anything else in the repo.
    if not resolved.startswith(str(REPO_ROOT.resolve() / "cases").replace("\\", "/") + "/"):
        raise PermissionError("Anti-leakage block: hooks may only read files under cases/.")


def _case_path(case_id: str) -> Path:
    """Resolve a case id to its source file, rejecting anything that is not ``CASE_NN``."""
    cid = case_id.strip().upper()
    if not CASE_ID_RE.match(cid):
        raise ValueError(f"Invalid case_id '{case_id}': expected CASE_NN.")
    java_path = REPO_ROOT / "cases" / f"{cid}.java"
    _guard_path(java_path)
    return java_path


def _sarif_path(case_id: str) -> Path:
    """Resolve a case id to its stored CodeQL SARIF; the only non-case file a hook may read."""
    cid = case_id.strip().upper()
    if not CASE_ID_RE.match(cid):
        raise ValueError(f"Invalid case_id '{case_id}': expected CASE_NN.")
    sarif_dir = REPO_ROOT / "reports" / "codeql_sarif"
    sarif_path = sarif_dir / f"{cid}.sarif"
    resolved = str(sarif_path.resolve()).replace("\\", "/")
    for token in FORBIDDEN_TOKENS:
        if token in resolved:
            raise PermissionError(f"Anti-leakage block: access to '{token}' is forbidden.")
    if not resolved.startswith(str(sarif_dir.resolve()).replace("\\", "/") + "/"):
        raise PermissionError("Anti-leakage block: SARIF must be under reports/codeql_sarif/.")
    return sarif_path


def fetch_code_slice(case_id: str, start_line: int, end_line: int) -> dict:
    java_path = _case_path(case_id)
    if not java_path.exists():
        return {"ok": False, "error": f"Source file not found for {case_id}"}
    lines = java_path.read_text(encoding="utf-8", errors="replace").splitlines()
    s, e = max(1, start_line), min(len(lines), end_line)
    numbered = [f"{idx}: {lines[idx - 1]}" for idx in range(s, e + 1)]
    return {
        "ok": True,
        "hook": "fetch_code_slice",
        "case_id": case_id,
        "file": f"cases/{java_path.name}",
        "line_range": f"{s}-{e}",
        "source_hash": compute_sha256(java_path),
        "code_slice": "\n".join(numbered),
    }


def inspect_enclosing_method(case_id: str, target_line: int) -> dict:
    java_path = _case_path(case_id)
    if not java_path.exists():
        return {"ok": False, "error": f"Source file not found for {case_id}"}
    lines = java_path.read_text(encoding="utf-8", errors="replace").splitlines()
    idx = max(0, min(len(lines) - 1, target_line - 1))
    start_idx = idx
    while start_idx > 0 and not re.search(r"\b(public|private|protected)\s+", lines[start_idx]):
        start_idx -= 1
    end_idx = min(len(lines), idx + 20)
    numbered = [f"{i + 1}: {lines[i]}" for i in range(start_idx, end_idx)]
    return {
        "ok": True,
        "hook": "inspect_enclosing_method",
        "case_id": case_id,
        "file": f"cases/{java_path.name}",
        "line_range": f"{start_idx + 1}-{end_idx}",
        "source_hash": compute_sha256(java_path),
        "code_slice": "\n".join(numbered),
    }


def rerun_pinned_semgrep(case_id: str, cwe: str) -> dict:
    """Re-run the pinned Semgrep rules on one case (read-only; no files written)."""
    java_path = _case_path(case_id)
    if not java_path.exists():
        return {"ok": False, "error": f"Source file not found for {case_id}"}
    rules_path = Path(__file__).resolve().parent / "semgrep_rules.yaml"
    res = run_semgrep(java_path, cwe, rules_path)
    return {
        "ok": res["status"] != "tool_failed",
        "hook": "rerun_pinned_semgrep",
        "case_id": case_id,
        "source_hash": compute_sha256(java_path),
        "scanner_result": res,
    }


def reload_codeql_sarif(case_id: str, cwe: str) -> dict:
    """Re-read the stored CodeQL SARIF for one case and normalize it again (read-only).

    CodeQL itself is not run again: this returns what the scan that produced
    ``reports/codeql_sarif/<CASE>.sarif`` found, with its rule id and version.
    It lets Lane 5 recover CodeQL evidence when a record arrives without it
    (condition B) or without its provenance (condition D). ``source_hash`` is the
    hash of the case file as it is now, so the controller can tell if the source
    changed after the scan.
    """
    java_path = _case_path(case_id)
    if not java_path.exists():
        return {"ok": False, "error": f"Source file not found for {case_id}"}
    sarif_path = _sarif_path(case_id)
    if not sarif_path.exists():
        return {"ok": False, "hook": "reload_codeql_sarif", "case_id": case_id,
                "error": f"No stored CodeQL SARIF for {case_id}"}
    res = run_codeql(java_path, cwe, sarif_path.parent)
    return {
        "ok": res["status"] != "tool_failed",
        "hook": "reload_codeql_sarif",
        "case_id": case_id,
        "source_hash": compute_sha256(java_path),
        "sarif_file": f"reports/codeql_sarif/{sarif_path.name}",
        "sarif_hash": compute_sha256(sarif_path),
        "scanner_result": res,
    }


# --------------------------------------------------------------------------- #
# Dispatcher for Lane 5 (controller/)
# --------------------------------------------------------------------------- #

HOOKS = {
    "fetch_code_slice": fetch_code_slice,
    "inspect_enclosing_method": inspect_enclosing_method,
    "rerun_pinned_semgrep": rerun_pinned_semgrep,
    "reload_codeql_sarif": reload_codeql_sarif,
}


def call_hook(name: str, **kwargs) -> dict:
    """Invoke a hook by name; every failure comes back as ``{"ok": False, ...}``.

    The controller keeps the budget (max 2 calls per record); this only maps a
    name to a function and turns exceptions into a result the controller can log,
    so a bad argument never aborts a decision run.
    """
    hook = HOOKS.get(name)
    if hook is None:
        return {"ok": False, "hook": name, "error": f"Unknown hook '{name}'. Known: {sorted(HOOKS)}"}
    try:
        return hook(**kwargs)
    except (ValueError, PermissionError, TypeError) as exc:
        return {"ok": False, "hook": name, "error": f"{type(exc).__name__}: {exc}"}
