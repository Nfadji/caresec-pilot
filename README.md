# CARE-Sec Four-Week Pilot (caresec-pilot)

Prototype pipeline evaluating Confidence-Aware Reasoning and Escalation (PROCEED / VERIFY / ESCALATE) across 20 curated Java cases (CWE-89 SQL Injection and CWE-22 Path Traversal).

## Ownership Lanes & Repository Layout
- **Lane 1 - N'Fadji Kake (cases/, manifests/, truth_private/):** 20 sanitized Java cases (CASE_01.java-CASE_20.java), public manifest (case_manifest_public.csv), and local-only ground truth.
- **Lane 2 - Euphreum (@asmamawu-ai21) (variants/):** Generator for Conditions A (Complete), B (Masked), C (Disagreement), and D (Provenance Gap) (~80 records).
- **Lane 3 - Kathryn Walker (@kwalerk) (scanners/):** Semgrep CE & CodeQL adapters, Evidence Ledger JSON builder, and read-only verification hooks.
- **Lane 4 - Angel (agent/):** Structured LLM triage agent + u_M (model competence) and u_E (evidence completeness) uncertainty proxies.
- **Lane 5 - Aldara (controller/):** PROCEED / VERIFY / ESCALATE decision controller with bounded verification loop (max 2 hook calls).
- **Lane 6 - Kathryn Walker (@kwalerk) and @netsiritgithub (tests/, reports/):** Schema validation, anti-leakage tests, and B1-B3 baseline evaluation summaries.

## Frozen CLI Contract
- python -m cases.validate_manifest
- python -m scanners.run --starter
- python -m variants.build --case CASE_01
- python -m agent.evaluate --variant CASE_01_A
- python -m controller.decide --run CASE_01_A
- python -m reports.summarize
