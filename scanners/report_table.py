"""
CARE-Sec Pilot — Week 1 scan table (Lane 3)

Renders the normalized scan outputs in ``reports/scanners/`` as a Markdown
table for the weekly report.

Usage:
    python -m scanners.report_table                 # all cases found
    python -m scanners.report_table --starter       # CASE_01..CASE_05
    python -m scanners.report_table --out reports/week1_scan_table.md
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
COLUMNS = ["case_id", "cwe", "semgrep", "semgrep_rule", "semgrep_lines",
           "codeql", "codeql_rule", "codeql_lines", "agree", "hash"]


def _cell(tool: dict, key: str) -> str:
    value = tool.get(key)
    return "" if value is None else str(value)


def table_rows(scans: list[dict]) -> list[dict]:
    rows = []
    for s in sorted(scans, key=lambda x: x["case_id"]):
        sg, cq = s.get("semgrep", {}), s.get("codeql", {})
        both_ran = sg.get("status") in ("finding", "no_finding") and cq.get("status") in ("finding", "no_finding")
        rows.append({
            "case_id": s["case_id"],
            "cwe": s.get("cwe", ""),
            "semgrep": sg.get("status", ""),
            "semgrep_rule": _cell(sg, "rule_id").replace("scanners.", ""),
            "semgrep_lines": _cell(sg, "matched_lines"),
            "codeql": cq.get("status", ""),
            "codeql_rule": _cell(cq, "rule_id"),
            "codeql_lines": _cell(cq, "matched_lines"),
            "agree": ("yes" if sg.get("status") == cq.get("status") else "no") if both_ran else "n/a",
            "hash": s.get("hash_match", "ok" if s.get("hash_verified") else "mismatch"),
        })
    return rows


def render_markdown(rows: list[dict], scans: list[dict]) -> str:
    head = "| " + " | ".join(COLUMNS) + " |\n|" + "|".join(["---"] * len(COLUMNS)) + "|\n"
    body = "".join("| " + " | ".join(r[c] for c in COLUMNS) + " |\n" for r in rows)
    versions = {}
    for s in scans:
        for tool in ("semgrep", "codeql"):
            v = s.get(tool, {}).get("version")
            if v:
                versions[tool] = v
    counts = {t: {} for t in ("semgrep", "codeql")}
    for r in rows:
        for t in counts:
            counts[t][r[t]] = counts[t].get(r[t], 0) + 1
    agree = sum(1 for r in rows if r["agree"] == "yes")
    foot = (
        f"\nCases: {len(rows)}. Semgrep {versions.get('semgrep', '?')}: {counts['semgrep']}. "
        f"CodeQL {versions.get('codeql', '?')}: {counts['codeql']}. Scanners agree on {agree} of "
        f"{sum(1 for r in rows if r['agree'] != 'n/a')} cases where both ran.\n\n"
        "`finding` / `no_finding` refer only to the case's target CWE; `hash` is the manifest "
        "SHA-256 check (`crlf_normalized` = matches after a line-ending swap). No ground-truth "
        "labels are used or shown here.\n"
    )
    return head + body + foot


def main() -> None:
    parser = argparse.ArgumentParser(description="Render reports/scanners/*.json as a Markdown table.")
    parser.add_argument("--scan-dir", type=Path, default=REPO_ROOT / "reports" / "scanners")
    parser.add_argument("--starter", action="store_true", help="Only CASE_01..CASE_05")
    parser.add_argument("--out", type=Path, help="Write the table here instead of stdout")
    args = parser.parse_args()

    scans = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(args.scan_dir.glob("CASE_*_scan.json"))]
    if args.starter:
        scans = [s for s in scans if s["case_id"] in {f"CASE_0{i}" for i in range(1, 6)}]
    if not scans:
        raise SystemExit(f"[ERROR] No scan outputs in {args.scan_dir}; run `python -m scanners.run --starter` first.")
    md = render_markdown(table_rows(scans), scans)
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(md, encoding="utf-8")
        print(f"[DONE] Wrote {args.out}")
    else:
        print(md, end="")


if __name__ == "__main__":
    main()
