"""
CARE-Sec Pilot — Read-Only Verification Hooks (Lane 3 -> Lane 5 Interface)
"""

import re
from pathlib import Path
from scanners.run import compute_sha256, run_semgrep

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


# --------------------------------------------------------------------------- #
# Dispatcher for Lane 5 (controller/)
# --------------------------------------------------------------------------- #

HOOKS = {
    "fetch_code_slice": fetch_code_slice,
    "inspect_enclosing_method": inspect_enclosing_method,
    "rerun_pinned_semgrep": rerun_pinned_semgrep,
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
