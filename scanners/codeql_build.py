"""
CARE-Sec Pilot — CodeQL database builder & SARIF exporter (Lane 3)

Builds one CodeQL Java database for ``cases/``, runs the bundled
``java-security-extended`` suite, and writes one SARIF file per case to
``reports/codeql_sarif/CASE_XX.sarif`` — the layout ``scanners.run`` reads.

Usage:
    python -m scanners.codeql_build                  # full run
    python -m scanners.codeql_build --split-only reports/codeql_work/results.sarif

Two build modes:

* ``compile`` (default when the helper sources are available): the cases are
  compiled with javac against the OWASP Benchmark helper classes, the Juliet
  ``testcasesupport`` package, and the Benchmark Maven classpath. This gives
  CodeQL fully resolved types, so taint tracking through ``HttpServletRequest``
  and JDBC works as it does on the upstream projects.
* ``none`` (fallback, CodeQL >= 2.16): ``--build-mode=none`` extracts the
  sources without compiling. Unresolved helper types reduce recall, so the run
  record marks the mode and ``scanners.run`` carries it into the ledger.

Where the helper sources come from (all optional; see ``--help``):

* ``CARESEC_BENCHMARK_SRC``  path to a checkout of OWASP BenchmarkJava
* ``CARESEC_JULIET_ZIP``     path to the NIST Juliet Java 1.3 zip
* ``CARESEC_CLASSPATH_FILE`` a file with the Benchmark Maven classpath
  (``mvn dependency:build-classpath -Dmdep.outputFile=...``); generated with
  Maven when missing and ``CARESEC_BENCHMARK_SRC`` is set.

Nothing here reads ``truth_private/``.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from scanners.run import compute_sha256

REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE = "codeql/java-queries:codeql-suites/java-security-extended.qls"
CASE_FILE_RE = re.compile(r"^(CASE_\d{2})\.java$")
OWASP_HELPERS_PKG = "org/owasp/benchmark"
SHIMS_DIR = Path(__file__).resolve().parent / "codeql_shims"


# --------------------------------------------------------------------------- #
# Pure helpers (unit-tested in tests/test_codeql_build.py)
# --------------------------------------------------------------------------- #

def case_id_from_uri(uri: str) -> str | None:
    """``org/owasp/benchmark/testcode/CASE_01.java`` -> ``CASE_01``; else None."""
    name = uri.replace("\\", "/").rsplit("/", 1)[-1]
    m = CASE_FILE_RE.match(name)
    return m.group(1) if m else None


def package_dir(java_source: str) -> Path:
    """Directory a Java file must live in for javac, from its ``package`` line."""
    m = re.search(r"^\s*package\s+([\w.]+)\s*;", java_source, re.MULTILINE)
    return Path(*m.group(1).split(".")) if m else Path()


def split_sarif(sarif: dict, case_ids: list[str]) -> dict[str, dict]:
    """Return ``{case_id: sarif}`` with one single-run SARIF document per case.

    Each output keeps the SARIF version, the tool driver/extension metadata with
    only the rules its results reference, and the results whose first location
    is in that case's file. Cases with no results get an empty ``results`` list,
    so a missing file always means "not scanned", never "no finding".
    """
    run = sarif["runs"][0]
    tool = run["tool"]
    per_case: dict[str, list[dict]] = {cid: [] for cid in case_ids}
    for result in run.get("results", []):
        locs = result.get("locations") or []
        uri = (locs[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "")) if locs else ""
        cid = case_id_from_uri(uri)
        if cid in per_case:
            per_case[cid].append(result)

    out: dict[str, dict] = {}
    for cid, results in per_case.items():
        used = {r.get("ruleId") for r in results}
        components = []
        for comp in [tool["driver"]] + tool.get("extensions", []):
            # "locations" holds the machine-specific pack install paths; drop them.
            slim = {k: v for k, v in comp.items() if k not in ("rules", "locations")}
            slim["rules"] = [r for r in comp.get("rules", []) if r.get("id") in used]
            components.append(slim)
        out[cid] = {
            "$schema": sarif.get("$schema"),
            "version": sarif.get("version", "2.1.0"),
            "runs": [{
                "tool": {"driver": components[0], "extensions": components[1:]},
                "results": copy.deepcopy(results),
                "automationDetails": {"id": f"caresec-pilot/codeql/{cid}"},
            }],
        }
    return out


# --------------------------------------------------------------------------- #
# Build tree preparation
# --------------------------------------------------------------------------- #

def _sh(cmd: list, log: Path, env: dict, cwd: Path | None = None) -> int:
    with log.open("a", encoding="utf-8") as f:
        f.write(f"\n$ {' '.join(map(str, cmd))}\n")
        f.flush()
        return subprocess.run(list(map(str, cmd)), stdout=f, stderr=subprocess.STDOUT, env=env, cwd=cwd).returncode


def _copy_cases(cases_dir: Path, src: Path) -> list[Path]:
    copied = []
    for p in sorted(cases_dir.glob("CASE_*.java")):
        if not CASE_FILE_RE.match(p.name):
            continue
        text = p.read_text(encoding="utf-8", errors="replace")
        dst = src / package_dir(text) / p.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dst)
        copied.append(dst.relative_to(src))
    return copied


def _copy_benchmark_helpers(benchmark_src: Path, src: Path) -> list[Path]:
    """Copy every non-testcode package of OWASP BenchmarkJava, packages unchanged."""
    root = benchmark_src / "src/main/java" / OWASP_HELPERS_PKG
    if not root.is_dir():
        return []
    copied = []
    for p in root.rglob("*.java"):
        rel = p.relative_to(root)
        if rel.parts[0] == "testcode":
            continue
        dst = src / OWASP_HELPERS_PKG / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dst)
        copied.append(dst.relative_to(src))
    return copied


def _extract_juliet_support(juliet_zip: Path, work: Path, src: Path) -> tuple[list[Path], list[Path]]:
    """Extract ``testcasesupport/*.java`` and ``lib/*.jar`` from the Juliet zip."""
    cache = work / "juliet_support"
    if not cache.exists():
        with zipfile.ZipFile(juliet_zip) as z:
            names = [n for n in z.namelist()
                     if n.startswith("Java/src/testcasesupport/") or n.startswith("Java/lib/")]
            z.extractall(cache, names)
    copied = []
    for p in sorted((cache / "Java/src/testcasesupport").glob("*.java")):
        dst = src / "testcasesupport" / p.name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dst)
        copied.append(dst.relative_to(src))
    jars = sorted((cache / "Java/lib").glob("*.jar"))
    return copied, jars


def _overlay_shims(src: Path) -> list[Path]:
    """Copy ``scanners/codeql_shims/`` over the tree (wins over the Juliet originals).

    The shims replace the two abstract Juliet base classes whose bad()/good()
    contract the sanitized cases no longer satisfy; see the shim headers.
    """
    copied = []
    for p in sorted(SHIMS_DIR.rglob("*.java")):
        dst = src / p.relative_to(SHIMS_DIR)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(p, dst)
        copied.append(dst.relative_to(src))
    return copied


def _maven_classpath(benchmark_src: Path, cp_file: Path, log: Path, env: dict) -> bool:
    if cp_file.exists():
        return True
    if shutil.which("mvn", path=env.get("PATH")) is None:
        return False
    rc = _sh(["mvn", "-q", "-B", "-f", benchmark_src / "pom.xml", "dependency:build-classpath",
              f"-Dmdep.outputFile={cp_file}"], log, env)
    return rc == 0 and cp_file.exists()


def prepare_tree(args, work: Path, log: Path, env: dict) -> dict:
    """Populate ``work/src`` and return a record describing the chosen build mode."""
    src = work / "src"
    if src.exists():
        shutil.rmtree(src)
    src.mkdir(parents=True)
    cases = _copy_cases(args.cases_dir, src)
    if not cases:
        raise SystemExit(f"[ERROR] No CASE_XX.java files found in {args.cases_dir}")

    helpers: list[Path] = []
    jars: list[Path] = []
    cp_ok = False
    if args.benchmark_src and args.benchmark_src.is_dir():
        helpers += _copy_benchmark_helpers(args.benchmark_src, src)
        cp_ok = _maven_classpath(args.benchmark_src, args.classpath_file, log, env)
    if args.juliet_zip and args.juliet_zip.is_file():
        support, jars = _extract_juliet_support(args.juliet_zip, work, src)
        helpers += support
    shims = _overlay_shims(src)

    mode = args.build_mode
    if mode == "auto":
        mode = "compile" if (helpers and cp_ok) else "none"

    rec = {"build_mode": mode, "case_files": [str(p) for p in cases],
           "helper_files": len(helpers), "shim_files": [str(p) for p in shims], "juliet_jars": len(jars),
           "maven_classpath_used": cp_ok}
    if mode == "compile":
        cp = args.classpath_file.read_text(encoding="utf-8").strip() if cp_ok else ""
        cp = ":".join(x for x in [cp] + [str(j) for j in jars] if x)
        classes = work / "classes"
        files = [str(p) for p in cases]
        # -sourcepath lets javac pull in only the helper classes the cases reference.
        (src / "build.sh").write_text(
            "#!/usr/bin/env bash\nset -e\ncd \"$(dirname \"$0\")\"\n"
            f"rm -rf '{classes}' && mkdir -p '{classes}'\n"
            f"javac --release 8 -proc:none -nowarn -encoding UTF-8 -d '{classes}' -sourcepath . -cp '{cp}' \\\n  "
            + " \\\n  ".join(files) + "\n", encoding="utf-8")
        os.chmod(src / "build.sh", 0o755)
    return rec


# --------------------------------------------------------------------------- #
# CodeQL invocation
# --------------------------------------------------------------------------- #

def codeql_version(env: dict) -> str:
    try:
        out = subprocess.check_output(["codeql", "version", "--format=terse"], text=True, env=env, timeout=60)
        return out.strip()
    except Exception:
        return "unknown"


def create_and_analyze(work: Path, build_mode: str, threads: int, ram_mb: int, log: Path, env: dict) -> Path:
    src, db, sarif = work / "src", work / "db", work / "results.sarif"
    create = ["codeql", "database", "create", db, "--language=java", f"--source-root={src}",
              "--overwrite", f"--threads={threads}", f"--ram={ram_mb}"]
    if build_mode == "compile":
        create.append("--command=bash build.sh")
    else:
        create.append("--build-mode=none")
    if _sh(create, log, env) != 0:
        raise SystemExit(f"[ERROR] codeql database create failed; see {log}")
    analyze = ["codeql", "database", "analyze", db, SUITE, "--format=sarif-latest", f"--output={sarif}",
               f"--threads={threads}", f"--ram={ram_mb}"]
    if _sh(analyze, log, env) != 0 or not sarif.exists():
        raise SystemExit(f"[ERROR] codeql database analyze failed; see {log}")
    return sarif


def export_per_case(sarif_path: Path, cases_dir: Path, out_dir: Path) -> dict[str, int]:
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    case_ids = sorted(p.stem for p in cases_dir.glob("CASE_*.java") if CASE_FILE_RE.match(p.name))
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = {}
    for cid, doc in split_sarif(sarif, case_ids).items():
        (out_dir / f"{cid}.sarif").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        counts[cid] = len(doc["runs"][0]["results"])
    return counts


def query_pack_versions(sarif_path: Path) -> list[dict]:
    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    tool = sarif["runs"][0]["tool"]
    return [{"name": c.get("name"), "version": c.get("semanticVersion")}
            for c in [tool["driver"]] + tool.get("extensions", []) if c.get("name")]


def main() -> None:
    env_path = os.environ
    parser = argparse.ArgumentParser(description="Build a CodeQL Java database for cases/ and export per-case SARIF.")
    parser.add_argument("--cases-dir", type=Path, default=REPO_ROOT / "cases")
    parser.add_argument("--out-dir", type=Path, default=REPO_ROOT / "reports" / "codeql_sarif")
    parser.add_argument("--work-dir", type=Path, default=REPO_ROOT / "reports" / "codeql_work",
                        help="Scratch dir for the source tree, database and combined SARIF (git-ignored).")
    parser.add_argument("--benchmark-src", type=Path, default=_env_path("CARESEC_BENCHMARK_SRC"))
    parser.add_argument("--juliet-zip", type=Path, default=_env_path("CARESEC_JULIET_ZIP"))
    parser.add_argument("--classpath-file", type=Path,
                        default=_env_path("CARESEC_CLASSPATH_FILE") or REPO_ROOT / "reports" / "codeql_work" / "maven_classpath.txt")
    parser.add_argument("--build-mode", choices=["auto", "compile", "none"], default="auto")
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--ram", type=int, default=8000, help="MB handed to CodeQL")
    parser.add_argument("--split-only", type=Path, metavar="SARIF",
                        help="Skip building; just split an existing combined SARIF into per-case files.")
    args = parser.parse_args()

    if args.split_only:
        counts = export_per_case(args.split_only, args.cases_dir, args.out_dir)
        print(json.dumps(counts, indent=2))
        return

    if shutil.which("codeql") is None:
        raise SystemExit("[ERROR] codeql not found in PATH")

    work = args.work_dir
    work.mkdir(parents=True, exist_ok=True)
    log = work / "codeql.log"
    log.write_text(f"run started {datetime.now(timezone.utc).isoformat()}\n", encoding="utf-8")
    env = dict(env_path)
    env.setdefault("TMPDIR", str(work / "tmp"))
    Path(env["TMPDIR"]).mkdir(parents=True, exist_ok=True)

    started = datetime.now(timezone.utc)
    tree = prepare_tree(args, work, log, env)
    print(f"[1/3] Source tree ready: {len(tree['case_files'])} cases, build_mode={tree['build_mode']}")
    sarif = create_and_analyze(work, tree["build_mode"], args.threads, args.ram, log, env)
    print(f"[2/3] CodeQL analysis done: {sarif}")
    counts = export_per_case(sarif, args.cases_dir, args.out_dir)
    print(f"[3/3] Wrote {len(counts)} per-case SARIF files to {args.out_dir}")

    record = {
        "tool": "codeql",
        "codeql_version": codeql_version(env),
        "suite": SUITE,
        "query_packs": query_pack_versions(sarif),
        "started_utc": started.isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "threads": args.threads,
        "ram_mb": args.ram,
        "combined_sarif_sha256": compute_sha256(sarif),
        "results_per_case": counts,
        **tree,
    }
    (args.out_dir / "_run.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"[DONE] Run record: {args.out_dir / '_run.json'}")


def _env_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value).expanduser() if value else None


if __name__ == "__main__":
    main()
