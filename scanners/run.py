"""
CARE-Sec Pilot — Static Scanners & Evidence Ledger Builder (Lane 3)
Usage:
    python -m scanners.run --starter
    python -m scanners.run --case CASE_01
    python -m scanners.run --all
"""

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(repo_root: Path) -> list[dict]:
    public_manifest = repo_root / "manifests" / "case_manifest_public.csv"
    private_manifest = repo_root / "manifests" / "case_manifest.csv"
    manifest_path = public_manifest if public_manifest.exists() else private_manifest
    if not manifest_path.exists():
        raise FileNotFoundError(f"Could not find manifest at {public_manifest} or {private_manifest}.")
    # utf-8-sig: the public manifest is saved with a UTF-8 BOM, which would otherwise
    # turn the first column name into "\ufeffcase_id".
    with manifest_path.open("r", newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f))


def get_tool_version(cmd: list[str]) -> str | None:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True, timeout=15)
        first_line = out.strip().splitlines()[0] if out.strip() else ""
        return first_line.strip() or None
    except Exception:
        return None


def verify_hash(actual_hash: str, recorded_hash: str, file_bytes: bytes) -> str:
    """Compare a file's hash with the manifest, tolerating a line-ending swap.

    Returns ``"exact"``, ``"crlf_normalized"`` (the manifest hash matches the
    same bytes with the other line ending, which happens when the manifest was
    computed on a Windows checkout and git stores LF) or ``"mismatch"``.
    """
    recorded = recorded_hash.strip().lower()
    if actual_hash == recorded:
        return "exact"
    lf = file_bytes.replace(b"\r\n", b"\n")
    for candidate in (lf, lf.replace(b"\n", b"\r\n")):
        if hashlib.sha256(candidate).hexdigest() == recorded:
            return "crlf_normalized"
    return "mismatch"


# Tokens that identify a finding as belonging to one of the two pilot CWEs.
# They are matched against rule ids, rule tags (SARIF ``external/cwe/cwe-089``)
# and Semgrep metadata, all lower-cased.
CWE_TOKENS = {
    "CWE-89": ("cwe-89", "cwe-089", "cwe89", "sqli", "sql-injection", "sql_injection"),
    "CWE-22": ("cwe-22", "cwe-022", "cwe22", "cwe-23", "cwe-023", "path-traversal", "path_traversal",
               "path-injection", "tainted-file", "tainted-path"),
}


def match_cwe(text: str, target_cwe: str) -> bool:
    lower = text.lower()
    return any(tok in lower for tok in CWE_TOKENS.get(target_cwe, ()))


def run_semgrep(java_path: Path, target_cwe: str, local_rules: Path) -> dict:
    if shutil.which("semgrep") is None:
        return {"status": "tool_failed", "rule_id": None, "version": None, "error": "semgrep not found in PATH"}
    version = get_tool_version(["semgrep", "--version"]) or "unknown"
    configs = [str(local_rules)] if local_rules.exists() else ["p/java"]
    cmd = ["semgrep", "scan", "--json", "--quiet"]
    for cfg in configs:
        cmd.extend(["--config", cfg])
    cmd.append(str(java_path))
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if proc.returncode not in (0, 1) and not proc.stdout.strip():
            return {"status": "tool_failed", "rule_id": None, "version": version, "error": proc.stderr.strip()[:300]}
        payload = json.loads(proc.stdout)
        results = payload.get("results", [])
        matched = [r for r in results if match_cwe(f"{r.get('check_id','')} {json.dumps(r.get('extra',{}).get('metadata',{}))}", target_cwe)]
        selected = matched if matched else results
        if selected:
            top = selected[0]
            s_line = top.get("start", {}).get("line")
            e_line = top.get("end", {}).get("line")
            return {
                "status": "finding",
                "rule_id": top.get("check_id", "semgrep.java.security"),
                "version": version,
                "matched_lines": f"{s_line}-{e_line}" if s_line else None,
                "finding_count": len(selected),
            }
        return {"status": "no_finding", "rule_id": None, "version": version, "matched_lines": None, "finding_count": 0}
    except Exception as exc:
        return {"status": "tool_failed", "rule_id": None, "version": version, "error": str(exc)[:300]}


def sarif_rule_index(run: dict) -> dict[str, dict]:
    """Map rule id -> rule object across the SARIF driver and its extensions."""
    tool = run.get("tool", {})
    rules: dict[str, dict] = {}
    for comp in [tool.get("driver", {})] + tool.get("extensions", []):
        for rule in comp.get("rules", []):
            if rule.get("id"):
                rules[rule["id"]] = rule
    return rules


def codeql_result_matches(result: dict, rules: dict[str, dict], target_cwe: str) -> bool:
    """A CodeQL result counts for ``target_cwe`` if its rule id or the rule's CWE tags say so.

    CodeQL names its rules by sink (``java/path-injection``), not by CWE, and
    puts the CWE in ``properties.tags`` as ``external/cwe/cwe-022``; the tags are
    the reliable signal.
    """
    rule_id = result.get("ruleId", "")
    tags = rules.get(rule_id, {}).get("properties", {}).get("tags", [])
    return match_cwe(" ".join([rule_id, *tags]), target_cwe)


def run_codeql(java_path: Path, target_cwe: str, sarif_dir: Path) -> dict:
    """Read the per-case SARIF written by ``scanners.codeql_build`` and normalize it."""
    codeql_bin = shutil.which("codeql")
    version = get_tool_version(["codeql", "version", "--format=terse"]) if codeql_bin else None
    sarif_file = sarif_dir / f"{java_path.stem}.sarif"
    run_record = sarif_dir / "_run.json"
    if sarif_file.exists():
        try:
            sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
            runs = sarif.get("runs", [])
            if runs:
                run = runs[0]
                tool_ver = run.get("tool", {}).get("driver", {}).get("semanticVersion") or version or "unknown"
                extra = {}
                if run_record.exists():
                    rec = json.loads(run_record.read_text(encoding="utf-8"))
                    extra = {"build_mode": rec.get("build_mode"), "suite": rec.get("suite")}
                rules = sarif_rule_index(run)
                results = run.get("results", [])
                matched = [r for r in results if codeql_result_matches(r, rules, target_cwe)]
                if matched:
                    top = matched[0]
                    loc = top.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {})
                    s_line = loc.get("startLine")
                    e_line = loc.get("endLine", s_line)
                    return {
                        "status": "finding",
                        "rule_id": top.get("ruleId", "java/security"),
                        "version": tool_ver,
                        "matched_lines": f"{s_line}-{e_line}" if s_line else None,
                        "finding_count": len(matched),
                        "other_findings": len(results) - len(matched),
                        **extra,
                    }
                return {"status": "no_finding", "rule_id": None, "version": tool_ver, "matched_lines": None,
                        "finding_count": 0, "other_findings": len(results), **extra}
        except Exception as exc:
            return {"status": "tool_failed", "rule_id": None, "version": version, "error": f"Failed parsing SARIF: {exc}"}
    reason = "CodeQL CLI not found in PATH." if not codeql_bin else f"No SARIF found at {sarif_file}."
    return {"status": "tool_failed", "rule_id": None, "version": version, "error": reason}


def build_base_ledger_record(row: dict, semgrep_res: dict, codeql_res: dict, actual_hash: str,
                             hash_match: str = "exact") -> dict:
    cwe = row["CWE"].strip()
    claim_map = {"CWE-89": "possible_sql_injection", "CWE-22": "possible_path_traversal"}
    return {
        "case_id": row["case_id"].strip(),
        "variant_id": f"{row['case_id'].strip()}_A",
        "evidence_condition": "A_COMPLETE",
        "claim_id": "CLM_01",
        "cwe": cwe,
        "claim": claim_map.get(cwe, "possible_vulnerability"),
        "file": row["source_path"].strip(),
        "line_range": row["line_range"].strip(),
        "semgrep": semgrep_res,
        "codeql": codeql_res,
        "source_available": True,
        "source_hash": actual_hash,
        "manifest_hash_match": hash_match,
        "u_m_level": "UNSET",
        "u_e_level": "UNSET",
        "action": "PENDING",
        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Semgrep CE & CodeQL on CARE-Sec Java cases.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--case", type=str, help="Single case ID (e.g., CASE_01)")
    group.add_argument("--starter", action="store_true", help="Run Week 1 starter gate (CASE_01..CASE_05)")
    group.add_argument("--all", action="store_true", help="Run all 20 cases in manifest")
    parser.add_argument("--rules", type=Path, default=Path(__file__).resolve().parent / "semgrep_rules.yaml")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    rows = load_manifest(repo_root)
    if args.case:
        selected = [r for r in rows if r["case_id"].strip().upper() == args.case.strip().upper()]
    elif args.starter:
        selected = rows[:5]
    else:
        selected = rows

    if not selected:
        print("[ERROR] No matching cases found in manifest.")
        sys.exit(1)

    scan_out_dir = repo_root / "reports" / "scanners"
    ledger_out_dir = repo_root / "reports" / "ledger"
    sarif_dir = repo_root / "reports" / "codeql_sarif"
    scan_out_dir.mkdir(parents=True, exist_ok=True)
    ledger_out_dir.mkdir(parents=True, exist_ok=True)

    # Semgrep CE phones home by default; keep pilot runs offline and reproducible.
    os.environ.setdefault("SEMGREP_SEND_METRICS", "off")

    print(f"Running static scanners on {len(selected)} case(s)...\n")
    print(f"{'CASE_ID':<9} {'CWE':<8} {'SEMGREP':<14} {'CODEQL':<14} {'HASH'}")
    print("-" * 58)

    evidence_index: dict[str, dict] = {}
    for row in selected:
        cid = row["case_id"].strip()
        java_path = repo_root / Path(row["source_path"].strip())
        if not java_path.exists():
            print(f"[ERROR] Missing Java file: {java_path}")
            continue
        actual_hash = compute_sha256(java_path)
        hash_match = verify_hash(actual_hash, row["file_hash"], java_path.read_bytes())
        semgrep_res = run_semgrep(java_path, row["CWE"].strip(), args.rules)
        codeql_res = run_codeql(java_path, row["CWE"].strip(), sarif_dir)

        (scan_out_dir / f"{cid}_scan.json").write_text(json.dumps({
            "case_id": cid, "file": row["source_path"].strip(), "file_hash": actual_hash,
            "hash_verified": hash_match != "mismatch", "hash_match": hash_match,
            "cwe": row["CWE"].strip(), "semgrep": semgrep_res, "codeql": codeql_res,
        }, indent=2) + "\n", encoding="utf-8")

        (ledger_out_dir / f"{cid}_A.json").write_text(
            json.dumps(build_base_ledger_record(row, semgrep_res, codeql_res, actual_hash, hash_match), indent=2) + "\n",
            encoding="utf-8",
        )
        evidence_index[cid] = {"semgrep": semgrep_res, "codeql": codeql_res}
        print(f"{cid:<9} {row['CWE'].strip():<8} {semgrep_res['status']:<14} {codeql_res['status']:<14} {hash_match}")

    # One object keyed by case_id: the shape ``variants.build --scanner-json`` consumes.
    index_path = ledger_out_dir / ("scanner_evidence.json" if args.all else "scanner_evidence_partial.json")
    index_path.write_text(json.dumps(evidence_index, indent=2) + "\n", encoding="utf-8")

    print(f"\n[DONE] Saved normalized scan outputs to {scan_out_dir}")
    print(f"[DONE] Saved Condition A ledger records to {ledger_out_dir}")
    print(f"[DONE] Saved scanner evidence index to {index_path}")


if __name__ == "__main__":
    main()
