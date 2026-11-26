"""
CARE-Sec Pilot - Lane 6: blinded packet for the independent reviewer spot-check.

Usage:
    python -m reports.blind_packet                    # 8 cases, 4 per CWE
    python -m reports.blind_packet --n 20 --seed 7    # every case, another order

Writes:
    reports/review_packet/packet.md          the code to review, one numbered item per case
    reports/review_packet/review_sheet.csv   one row per item for the reviewer to fill in
    truth_private/review_key.csv             item -> case id (private; ignored by git)

Blinded means the reviewer sees only the claim and the code. The packet has no scanner
output, no model verdict, no controller decision and no label, and case ids are replaced
by item numbers in a shuffled order so nothing can be looked up in the public reports.
This script reads cases/ and the public manifest only. It never reads the truth file.
"""

from __future__ import annotations

import argparse
import csv
import random
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST = REPO_ROOT / "manifests" / "case_manifest_public.csv"
DEFAULT_OUT = REPO_ROOT / "reports" / "review_packet"
DEFAULT_KEY = REPO_ROOT / "truth_private" / "review_key.csv"
CLAIMS = {"CWE-22": "possible path traversal (CWE-22)", "CWE-89": "possible SQL injection (CWE-89)"}
CASE_TOKEN = re.compile(r"CASE_\d{2}")
SHEET_COLUMNS = ["item_id", "claim", "lines_in_question", "reviewer_label", "reviewer_confidence", "reviewer_notes"]


def load_manifest(manifest: Path = MANIFEST) -> list[dict[str, str]]:
    with manifest.open(encoding="utf-8-sig", newline="") as f:
        return [{k: v.strip() for k, v in row.items()} for row in csv.DictReader(f)]


def choose_cases(rows: list[dict[str, str]], n: int, seed: int) -> list[dict[str, str]]:
    """Pick n cases, split as evenly as possible across the CWEs, in a shuffled order."""
    rng = random.Random(seed)
    groups: dict[str, list[dict[str, str]]] = {}
    for row in sorted(rows, key=lambda r: r["case_id"]):
        groups.setdefault(row["CWE"], []).append(row)
    if not 1 <= n <= len(rows):
        raise ValueError(f"--n must be between 1 and {len(rows)}")
    for group in groups.values():
        rng.shuffle(group)
    picked: list[dict[str, str]] = []
    while len(picked) < n:  # deal one case per CWE in turn
        for cwe in sorted(groups):
            if groups[cwe] and len(picked) < n:
                picked.append(groups[cwe].pop())
    rng.shuffle(picked)
    return picked


def blind_source(text: str, item_id: str) -> str:
    """Number the lines and replace every case id (class name, servlet path) with the item id."""
    lines = CASE_TOKEN.sub(item_id, text).splitlines()
    width = len(str(len(lines)))
    return "\n".join(f"{i:>{width}}  {line}" for i, line in enumerate(lines, 1))


def build(rows: list[dict[str, str]], n: int, seed: int, root: Path = REPO_ROOT) -> tuple[str, list[dict], list[dict]]:
    """Return (packet text, review sheet rows, private key rows)."""
    picked = choose_cases(rows, n, seed)
    parts = ["# CARE-Sec pilot: reviewer spot-check packet", "",
             f"{len(picked)} items. For each item, decide whether the code in the stated lines really has the "
             "claimed weakness. Record your answer in `review_sheet.csv`: `reviewer_label` is VULNERABLE, "
             "NOT_VULNERABLE or UNSURE, and `reviewer_confidence` is LOW, MEDIUM or HIGH.",
             "Please judge from the code alone and do not look the items up in the project reports.", ""]
    sheet, key = [], []
    for i, row in enumerate(picked, 1):
        item_id = f"ITEM_{i:02d}"
        source = (root / row["source_path"]).read_text(encoding="utf-8", errors="replace")
        claim = CLAIMS.get(row["CWE"], row["CWE"])
        parts += [f"## {item_id}", "", f"Claim: {claim} at lines {row['line_range']}.", "",
                  "```java", blind_source(source, item_id), "```", ""]
        sheet.append({"item_id": item_id, "claim": claim, "lines_in_question": row["line_range"],
                      "reviewer_label": "", "reviewer_confidence": "", "reviewer_notes": ""})
        key.append({"item_id": item_id, "case_id": row["case_id"]})
    return "\n".join(parts), sheet, key


def _write_csv(path: Path, columns: list[str], rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="CARE-Sec Lane 6: blinded reviewer spot-check packet")
    p.add_argument("--n", type=int, default=8, help="Number of cases in the packet (default 8)")
    p.add_argument("--seed", type=int, default=20261125, help="Seed for the sample and the order")
    p.add_argument("--out", type=Path, default=DEFAULT_OUT, help="Folder for packet.md and review_sheet.csv")
    p.add_argument("--key", type=Path, default=DEFAULT_KEY, help="Private item -> case key (keep out of git)")
    args = p.parse_args(argv)

    try:
        packet, sheet, key = build(load_manifest(), args.n, args.seed)
    except ValueError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "packet.md").write_text(packet + "\n", encoding="utf-8")
    _write_csv(args.out / "review_sheet.csv", SHEET_COLUMNS, sheet)
    _write_csv(args.key, ["item_id", "case_id"], key)
    print(f"[DONE] {len(sheet)} items in {args.out}/ (packet.md, review_sheet.csv)")
    print(f"[PRIVATE] item -> case key: {args.key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
