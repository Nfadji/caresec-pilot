
from pathlib import Path
import json
import csv
import os
import re
from collections import Counter

ROOT = Path(__file__).resolve().parents[1]
SEMGREP_FILE = ROOT / "scanners" / "semgrep_all20.json"
CODEQL_FILE = Path(os.environ["TEMP"]) / "caresec-codeql-results.sarif"
MANIFEST_FILE = ROOT / "manifests" / "case_manifest_public.csv"
OUTPUT_FILE = ROOT / "variants" / "scanner_evidence_local.json"

def case_id_from_path(path):
    name = Path(str(path).replace("\\", "/")).name
    match = re.fullmatch(r"(CASE_\d{2})\.java", name)
    return match.group(1) if match else None

def main():
    with MANIFEST_FILE.open(encoding="utf-8-sig", newline="") as f:
        cases = list(csv.DictReader(f))

    evidence = {
        case["case_id"]: {
            "semgrep": {"status": "no_finding", "findings": []},
            "codeql": {"status": "no_finding", "findings": []},
        }
        for case in cases
    }

    with SEMGREP_FILE.open(encoding="utf-8") as f:
        semgrep = json.load(f)

    for result in semgrep.get("results", []):
        case_id = case_id_from_path(result.get("path", ""))
        if case_id not in evidence:
            continue

        evidence[case_id]["semgrep"]["findings"].append({
            "rule_id": result.get("check_id"),
            "line": result.get("start", {}).get("line"),
            "severity": result.get("extra", {}).get("severity"),
        })

    with CODEQL_FILE.open(encoding="utf-8") as f:
        codeql = json.load(f)

    for run in codeql.get("runs", []):
        for result in run.get("results", []):
            for location in result.get("locations", []):
                physical = location.get("physicalLocation", {})
                case_id = case_id_from_path(
                    physical.get("artifactLocation", {}).get("uri", "")
                )
                if case_id not in evidence:
                    continue

                evidence[case_id]["codeql"]["findings"].append({
                    "rule_id": result.get("ruleId"),
                    "line": physical.get("region", {}).get("startLine"),
                    "level": result.get("level"),
                })

    for scanners in evidence.values():
        for scanner in scanners.values():
            if scanner["findings"]:
                scanner["status"] = "finding"

    OUTPUT_FILE.write_text(
        json.dumps(evidence, indent=2) + "\n",
        encoding="utf-8"
    )

    print("Cases:", len(evidence))
    print("Semgrep findings:", sum(
        len(x["semgrep"]["findings"]) for x in evidence.values()
    ))
    print("CodeQL findings:", sum(
        len(x["codeql"]["findings"]) for x in evidence.values()
    ))
    print("Saved:", OUTPUT_FILE)
    print("NOTE: Provisional local evidence, not the frozen team schema.")

if __name__ == "__main__":
    main()
