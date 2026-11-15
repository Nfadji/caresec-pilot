"""
CARE-Sec Pilot — Automated Dataset Curator & Sanitizer (Student 1)
Selects 20 balanced Java cases (12 OWASP, 8 Juliet across CWE-89 and CWE-22),
neutralizes label-leaking identifiers, computes SHA-256 hashes, and writes
manifests/case_manifest.csv and truth_private/hidden_truth.json.

Usage:
    python -m cases.curate_benchmarks --sources-dir ~/caresec-sources
"""

import argparse
import csv
import json
import re
import subprocess
from pathlib import Path

from cases.validate_manifest import REQUIRED_CSV_COLUMNS, compute_sha256


def get_git_commit(repo_dir: Path) -> str:
    try:
        out = subprocess.check_output(["git", "-C", str(repo_dir), "rev-parse", "HEAD"], text=True)
        return out.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def sanitize_owasp_java(code: str, new_class_name: str, old_class_name: str) -> str:
    code = re.sub(r"/\*\*[\s\S]*?\*/", "", code, count=1)
    code = re.sub(rf"\b{re.escape(old_class_name)}\b", new_class_name, code)
    return code.strip() + "\n"


def remove_java_method(code: str, method_sig_regex: str) -> str:
    """Removes a Java method block by brace-counting from its signature."""
    match = re.search(method_sig_regex, code)
    if not match:
        return code
    start = match.start()
    brace_open = code.find("{", match.end() - 1)
    if brace_open == -1:
        return code
    depth = 0
    end = brace_open
    for i in range(brace_open, len(code)):
        if code[i] == "{":
            depth += 1
        elif code[i] == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    return code[:start] + code[end:]


def sanitize_juliet_java(code: str, new_class_name: str, old_class_name: str, keep_vulnerable: bool) -> str:
    code = re.sub(r"/\*[\s\S]*?\*/", "", code)
    code = re.sub(r"//.*", "", code)

    if keep_vulnerable:
        for pat in [
            r"public\s+void\s+good\s*\([^)]*\)[^{]*\{",
            r"private\s+void\s+good[A-Za-z0-9_]*\s*\([^)]*\)[^{]*\{",
        ]:
            while re.search(pat, code):
                code = remove_java_method(code, pat)
        code = re.sub(r"\bbad\s*\(", "processRequest(", code)
        code = re.sub(r"\bbadSink\s*\(", "executeSink(", code)
    else:
        for pat in [
            r"public\s+void\s+bad\s*\([^)]*\)[^{]*\{",
            r"private\s+void\s+bad[A-Za-z0-9_]*\s*\([^)]*\)[^{]*\{",
        ]:
            while re.search(pat, code):
                code = remove_java_method(code, pat)
        code = re.sub(r"\bgood\s*\(", "processRequest(", code)
        code = re.sub(r"\bgood(G2B|B2G)(\d*)\s*\(", r"runCase\1\2(", code)
        code = re.sub(r"\bgood(G2B|B2G)(\d*)Sink\s*\(", r"executeSink\1\2(", code)

    code = re.sub(rf"\b{re.escape(old_class_name)}\b", new_class_name, code)
    code = re.sub(r"\n{3,}", "\n\n", code)
    return code.strip() + "\n"


def detect_sink_line_range(code: str, cwe: str) -> str:
    lines = code.splitlines()
    sink_keywords = (
        ("executeQuery", "executeUpdate", "execute(", "prepareStatement", "createStatement")
        if cwe == "CWE-89"
        else ("new File", "FileInputStream", "FileOutputStream", "Paths.get", "FileReader")
    )
    for idx, line in enumerate(lines, start=1):
        if any(kw in line for kw in sink_keywords):
            start = max(1, idx - 3)
            end = min(len(lines), idx + 3)
            return f"{start}-{end}"
    return f"1-{min(len(lines), 40)}"


def select_owasp_cases(owasp_dir: Path, commit_sha: str) -> list[dict]:
    csv_path = owasp_dir / "expectedresults-1.2.csv"
    testcode_dir = owasp_dir / "src/main/java/org/owasp/benchmark/testcode"
    if not csv_path.exists():
        raise FileNotFoundError(f"Could not find {csv_path}")

    quotas = {
        ("CWE-89", "vulnerable"): 3,
        ("CWE-89", "safe"): 3,
        ("CWE-22", "vulnerable"): 3,
        ("CWE-22", "safe"): 3,
    }
    selected = []

    with csv_path.open("r", encoding="utf-8") as f:
        for row in csv.reader(f):
            if not row or row[0].startswith("#"):
                continue
            test_name, _cat, is_vuln_str, cwe_num = [c.strip() for c in row[:4]]
            cwe = f"CWE-{cwe_num}"
            label = "vulnerable" if is_vuln_str.lower() == "true" else "safe"
            if (cwe, label) not in quotas or quotas[(cwe, label)] <= 0:
                continue

            java_file = testcode_dir / f"{test_name}.java"
            if not java_file.exists():
                continue
            raw_code = java_file.read_text(encoding="utf-8", errors="replace")
            line_count = len(raw_code.splitlines())
            if not (45 <= line_count <= 120):
                continue

            selected.append(
                {
                    "upstream_path": java_file,
                    "upstream_filename": java_file.name,
                    "old_class": test_name,
                    "source_dataset": "OWASP-Benchmark-1.2",
                    "source_url": "https://github.com/OWASP-Benchmark/BenchmarkJava",
                    "source_commit": commit_sha,
                    "license": "GPL-2.0",
                    "CWE": cwe,
                    "expected_label": label,
                }
            )
            quotas[(cwe, label)] -= 1
            if sum(quotas.values()) == 0:
                break

    if sum(quotas.values()) > 0:
        raise RuntimeError(f"Could not fill all OWASP quotas; remaining: {quotas}")
    return selected


def select_juliet_cases(juliet_dir: Path) -> list[dict]:
    cwe_folders = {
        "CWE-89": "CWE89_SQL_Injection",
        "CWE-22": "CWE23_Relative_Path_Traversal",
    }
    selected = []
    for cwe, folder_token in cwe_folders.items():
        candidates = sorted(
            p for p in juliet_dir.rglob("*01.java") if folder_token in str(p) and "Servlet" in p.name
        )
        if len(candidates) < 4:
            candidates = sorted(p for p in juliet_dir.rglob("*01.java") if folder_token in str(p))
        if len(candidates) < 4:
            raise RuntimeError(f"Found fewer than 4 Juliet *01.java files for {cwe} in {juliet_dir}")

        for idx, java_file in enumerate(candidates[:4]):
            label = "vulnerable" if idx < 2 else "safe"
            selected.append(
                {
                    "upstream_path": java_file,
                    "upstream_filename": java_file.name,
                    "old_class": java_file.stem,
                    "source_dataset": "NIST-Juliet-Java-1.3",
                    "source_url": "https://samate.nist.gov/SARD/test-suites/111",
                    "source_commit": "v1.3-sha256:d985f4177c2bcd7b",
                    "license": "Public-Domain-CC0",
                    "CWE": cwe,
                    "expected_label": label,
                }
            )
    return selected


def main() -> None:
    parser = argparse.ArgumentParser(description="Curate and sanitize 20 Java cases for CARE-Sec.")
    parser.add_argument(
        "--sources-dir",
        type=Path,
        default=Path.home() / "caresec-sources",
        help="Directory containing BenchmarkJava/ and juliet-java/",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    cases_dir = repo_root / "cases"
    manifest_path = repo_root / "manifests" / "case_manifest.csv"
    truth_path = repo_root / "truth_private" / "hidden_truth.json"

    owasp_dir = args.sources_dir / "BenchmarkJava"
    juliet_dir = args.sources_dir / "juliet-java"

    owasp_commit = get_git_commit(owasp_dir)
    raw_cases = select_owasp_cases(owasp_dir, owasp_commit) + select_juliet_cases(juliet_dir)

    manifest_rows = []
    hidden_truth = {}

    for idx, item in enumerate(raw_cases, start=1):
        case_id = f"CASE_{idx:02d}"
        rel_java_path = f"cases/{case_id}.java"
        out_java_path = repo_root / rel_java_path

        raw_code = item["upstream_path"].read_text(encoding="utf-8", errors="replace")
        if "OWASP" in item["source_dataset"]:
            clean_code = sanitize_owasp_java(raw_code, case_id, item["old_class"])
            note = f"Curated from {item['upstream_filename']}; class renamed to {case_id} to prevent label leakage."
        else:
            keep_vuln = item["expected_label"] == "vulnerable"
            clean_code = sanitize_juliet_java(raw_code, case_id, item["old_class"], keep_vulnerable=keep_vuln)
            branch_kept = "bad()" if keep_vuln else "good()"
            note = (
                f"Curated from {item['upstream_filename']}; isolated {branch_kept} branch and neutralized "
                f"method/class names to {case_id}."
            )

        out_java_path.write_text(clean_code, encoding="utf-8")
        file_hash = compute_sha256(out_java_path)
        line_range = detect_sink_line_range(clean_code, item["CWE"])

        manifest_rows.append(
            {
                "case_id": case_id,
                "source_dataset": item["source_dataset"],
                "source_url": item["source_url"],
                "source_commit": item["source_commit"],
                "file_hash": file_hash,
                "license": item["license"],
                "CWE": item["CWE"],
                "source_path": rel_java_path,
                "line_range": line_range,
                "expected_label": item["expected_label"],
                "project_group_id": f"GRP_{idx:02d}",
                "java_version": "17",
                "scan_status": "pending",
            }
        )

        hidden_truth[case_id] = {
            "upstream_filename": item["upstream_filename"],
            "correctness_label": item["expected_label"],
            "reference_evidence": [
                {
                    "file": rel_java_path,
                    "line_range": line_range,
                    "cwe": item["CWE"],
                }
            ],
            "expected_review_by_condition": {
                "A_COMPLETE": "PROCEED",
                "B_MASKED": "VERIFY",
                "C_DISAGREEMENT": "VERIFY",
                "D_PROVENANCE_GAP": "ESCALATE",
            },
            "adjudication_notes": note,
            "adjudicator_id": "student_1",
        }

    with manifest_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REQUIRED_CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(manifest_rows)

    truth_path.write_text(json.dumps(hidden_truth, indent=2) + "\n", encoding="utf-8")
    print(f"[DONE] Curated {len(manifest_rows)} Java cases into {cases_dir}")


if __name__ == "__main__":
    main()
