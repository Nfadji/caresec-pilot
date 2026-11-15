\# CARE-Sec Four-Week Pilot



CARE-Sec is a team pilot that evaluates how a Confidence-Aware Reasoning and Escalation system decides when to `PROCEED`, `VERIFY`, or `ESCALATE` while reviewing Java code for security vulnerabilities.



The Week 1 baseline contains 20 curated Java cases covering SQL injection (CWE-89) and path traversal (CWE-22). The shared manifest provides case metadata, line ranges, and file hashes. Ground-truth labels are kept private for evaluation.



\## Repository Layout



| Folder | Contents or planned work |

| --- | --- |

| `cases/` | 20 curated Java cases and the Python curation and validation scripts |

| `manifests/` | `case\_manifest\_public.csv` with label-free case metadata |

| `scanners/` | Semgrep CE and CodeQL adapters and the Evidence Ledger |

| `variants/` | Evidence conditions A (Complete), B (Masked), C (Disagreement), and D (Provenance Gap) |

| `agent/` | LLM triage agent and uncertainty estimates for model competence and evidence |

| `controller/` | Decision logic for `PROCEED`, `VERIFY`, and `ESCALATE`, with up to two read-only verification steps |

| `tests/` | Schema validation and tests for label leakage |

| `reports/` | Run logs, evaluation metrics, and final deliverables |



\## Team Hub



See the \[CARE-Sec Four-Week Pilot Team Hub](https://gemini.google.com/notebook/59a44c62-1147-4f56-a0e7-22bd6f7bfc58) for the project plan and lane assignments.

