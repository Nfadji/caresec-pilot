"""
CARE-Sec Pilot — Manifest & Ground-Truth Validator (Student 1)
Usage:
    python -m cases.validate_manifest --init
    python -m cases.validate_manifest --fix-hashes
    python -m cases.validate_manifest
"""

import argparse
import csv
import hashlib
import json
import re
import sys
from pathlib import Path

REQUIRED_CSV_COLUMNS = [
    "case_id",
    "source_dataset",
    "source_url",
    "source_commit",
    "file_hash",
    "license",
    "CWE",
    "source_path",
    "line_range",
    "expected_label",
    "project_group_id",
    "java_version",
    "scan_status",
]

ALLOWED_CWES = {"CWE-89", "CWE-22"}
ALLOWED_LABELS = {"vulnerable", "safe"}
ALLOWED_SCAN_STATUSES = {"pending", "scanned", "partial", "failed"}
LEAK_PATTERNS = [
    re.compile(r"\bBenchmarkTest\d+\b"),
    re.compile(r"\bbad\s*\("),
    re.compile(r"\bgood(?:G2B|B2G)?\d*\s*\("),
]


def compute_sha256(file_path: Path) -> str:
    h = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def init_workspace(root: Path) -> None:
    dirs = [
        "cases",
        "manifests",
        "truth_private",
        "scanners",
        "variants",
        "agent",
        "controller",
        "reports",
        "tests",
    ]
    for d in dirs:
        (root / d).mkdir(parents=True, exist_ok=True)
        init_file = root / d / "__init__.py"
        if d in {"cases", "scanners", "variants", "agent", "controller", "reports", "tests"} and not init_file.exists():
            init_file.touch()

    manifest_path = root / "manifests" / "case_manifest.csv"
    if not manifest_path.exists():
        with manifest_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=REQUIRED_CSV_COLUMNS)
            writer.writeheader()
        print(f"[INIT] Created {manifest_path}")

    truth_path = root / "truth_private" / "hidden_truth.json"
    if not truth_path.exists():
        truth_path.write_text("{}\n", encoding="utf-8")
        print(f"[INIT] Created {truth_path}")

    gitignore_path = root / ".gitignore"
    if not gitignore_path.exists():
        gitignore_path.write_text("__pycache__/\n*.pyc\n.venv/\nreports/*.log\n", encoding="utf-8")
        print(f"[INIT] Created {gitignore_path}")


def validate(root: Path, fix_hashes: bool = False) -> int:
    manifest_path = root / "manifests" / "case_manifest.csv"
    truth_path = root / "truth_private" / "hidden_truth.json"

    if not manifest_path.exists():
        print(f"[ERROR] Missing {manifest_path}. Run with --init first.")
        return 1
    if not truth_path.exists():
        print(f"[ERROR] Missing {truth_path}. Run with --init first.")
        return 1

    with manifest_path.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != REQUIRED_CSV_COLUMNS:
            print(f"[ERROR] CSV columns mismatch.\n  Expected: {REQUIRED_CSV_COLUMNS}\n  Found:    {reader.fieldnames}")
            return 1
        rows = list(reader)

    try:
        hidden_truth = json.loads(truth_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid JSON in {truth_path}: {exc}")
        return 1

    if not rows:
        print("[WARN] case_manifest.csv has 0 cases yet. Add your first OWASP/Juliet pair and re-run.")
        return 0

    errors: list[str] = []
    warnings: list[str] = []
    seen_ids: set[str] = set()
    updated_rows = False

    cwe_counts = {"CWE-89": 0, "CWE-22": 0}
    label_counts = {"vulnerable": 0, "safe": 0}
    dataset_counts = {"OWASP": 0, "Juliet": 0}

    for idx, row in enumerate(rows, start=2):
        cid = row["case_id"].strip()
        if not cid:
            errors.append(f"Row {idx}: missing case_id.")
            continue
        if cid in seen_ids:
            errors.append(f"Row {idx}: duplicate case_id '{cid}'.")
        seen_ids.add(cid)

        for col in REQUIRED_CSV_COLUMNS:
            if not row[col].strip():
                errors.append(f"{cid}: empty field '{col}'.")

        cwe = row["CWE"].strip()
        if cwe not in ALLOWED_CWES:
            errors.append(f"{cid}: invalid CWE '{cwe}' (expected {sorted(ALLOWED_CWES)}).")
        else:
            cwe_counts[cwe] += 1

        label = row["expected_label"].strip()
        if label not in ALLOWED_LABELS:
            errors.append(f"{cid}: invalid expected_label '{label}' (expected {sorted(ALLOWED_LABELS)}).")
        else:
            label_counts[label] += 1

        scan_status = row["scan_status"].strip()
        if scan_status not in ALLOWED_SCAN_STATUSES:
            errors.append(f"{cid}: invalid scan_status '{scan_status}'.")

        ds = row["source_dataset"]
        if "OWASP" in ds:
            dataset_counts["OWASP"] += 1
        elif "Juliet" in ds:
            dataset_counts["Juliet"] += 1

        rel_path = Path(row["source_path"].strip())
        full_path = root / rel_path
        if not full_path.exists():
            errors.append(f"{cid}: source file not found at '{rel_path}'.")
        else:
            actual_hash = compute_sha256(full_path)
            recorded_hash = row["file_hash"].strip()
            if fix_hashes and recorded_hash != actual_hash:
                row["file_hash"] = actual_hash
                updated_rows = True
                print(f"[HASH] Updated {cid} SHA-256 -> {actual_hash[:16]}...")
            elif recorded_hash != actual_hash:
                errors.append(
                    f"{cid}: SHA-256 mismatch for '{rel_path}' (manifest={recorded_hash[:12]}..., actual={actual_hash[:12]}...). Run with --fix-hashes."
                )

            code_text = full_path.read_text(encoding="utf-8", errors="replace")
            for pat in LEAK_PATTERNS:
                if pat.search(full_path.name) or pat.search(code_text):
                    warnings.append(
                        f"{cid}: potential label-leaking identifier matching '{pat.pattern}' in '{rel_path}'."
                    )

        if cid not in hidden_truth:
            errors.append(f"{cid}: missing entry in truth_private/hidden_truth.json.")
        else:
            truth_entry = hidden_truth[cid]
            t_label = truth_entry.get("correctness_label")
            if t_label != label:
                errors.append(
                    f"{cid}: label mismatch between manifest ('{label}') and hidden_truth ('{t_label}')."
                )
            if "reference_evidence" not in truth_entry or not truth_entry["reference_evidence"]:
                errors.append(f"{cid}: missing 'reference_evidence' in hidden_truth.json.")

    if updated_rows:
        with manifest_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=REQUIRED_CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)

    print("\n=== CARE-Sec Manifest Summary ===")
    print(f"Total cases: {len(rows)} / 20 target")
    print(f"By Dataset:  OWASP={dataset_counts['OWASP']} (target 12), Juliet={dataset_counts['Juliet']} (target 8)")
    print(f"By CWE:      CWE-89={cwe_counts['CWE-89']} (target 10), CWE-22={cwe_counts['CWE-22']} (target 10)")
    print(f"By Label:    vulnerable={label_counts['vulnerable']} (target 10), safe={label_counts['safe']} (target 10)")

    for w in warnings:
        print(f"[WARN]  {w}")
    for e in errors:
        print(f"[ERROR] {e}")

    if errors:
        print(f"\nValidation FAILED with {len(errors)} error(s).")
        return 1

    print("\nValidation PASSED.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate CARE-Sec pilot case manifest and hidden truth.")
    parser.add_argument("--init", action="store_true", help="Initialize repo directory structure and starter files.")
    parser.add_argument("--fix-hashes", action="store_true", help="Auto-compute and write SHA-256 hashes into case_manifest.csv.")
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    if args.init:
        init_workspace(repo_root)
    sys.exit(validate(repo_root, fix_hashes=args.fix_hashes))


if __name__ == "__main__":
    main()
