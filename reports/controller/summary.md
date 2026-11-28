| variant | cwe | semgrep | codeql | u_M (source) | u_E start->end | verify | action | reason |
|---|---|---|---|---|---|---|---|---|
| CASE_01_A | CWE-22 | finding | finding | LOW (lane4) | LOW->LOW | 0 | **PROCEED** | evidence complete and consistent; model risk LOW |
| CASE_01_B | CWE-22 | masked | masked | HIGH (lane4) | HIGH->HIGH | 0 | **ESCALATE** | model-competence risk HIGH; more evidence would not resolve it |
| CASE_01_C | CWE-22 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_01_D | CWE-22 | finding | finding | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_02_A | CWE-22 | no_finding | finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_02_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_02_C | CWE-22 | no_finding | finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_02_D | CWE-22 | no_finding | finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_03_A | CWE-89 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_03_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_03_C | CWE-89 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_03_D | CWE-89 | finding | finding | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_04_A | CWE-22 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_04_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_04_C | CWE-22 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_04_D | CWE-22 | finding | finding | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_05_A | CWE-89 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_05_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_05_C | CWE-89 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_05_D | CWE-89 | finding | finding | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_06_A | CWE-89 | no_finding | finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_06_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_06_C | CWE-89 | no_finding | finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_06_D | CWE-89 | no_finding | finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_07_A | CWE-89 | no_finding | no_finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_07_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_07_C | CWE-89 | no_finding | no_finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_07_D | CWE-89 | no_finding | no_finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_08_A | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_08_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_08_C | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_08_D | CWE-22 | finding | no_finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_09_A | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_09_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_09_C | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_09_D | CWE-22 | finding | no_finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_10_A | CWE-89 | no_finding | no_finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_10_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_10_C | CWE-89 | no_finding | no_finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_10_D | CWE-89 | no_finding | no_finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_11_A | CWE-89 | no_finding | finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_11_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_11_C | CWE-89 | no_finding | finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_11_D | CWE-89 | no_finding | finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_12_A | CWE-22 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_12_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_12_C | CWE-22 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_12_D | CWE-22 | finding | finding | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_13_A | CWE-89 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_13_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_13_C | CWE-89 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_13_D | CWE-89 | finding | finding | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_14_A | CWE-89 | no_finding | finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_14_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_14_C | CWE-89 | no_finding | finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_14_D | CWE-89 | no_finding | finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_15_A | CWE-89 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_15_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_15_C | CWE-89 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_15_D | CWE-89 | finding | no_finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_16_A | CWE-89 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_16_B | CWE-89 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_16_C | CWE-89 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_16_D | CWE-89 | finding | no_finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_17_A | CWE-22 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_17_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_17_C | CWE-22 | finding | finding | UNSET (unset) | LOW->LOW | 0 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_17_D | CWE-22 | finding | finding | UNSET (unset) | HIGH->LOW | 2 | **ESCALATE** | evidence complete but no validated model assessment (u_M UNSET) |
| CASE_18_A | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_18_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_18_C | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_18_D | CWE-22 | finding | no_finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_19_A | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_19_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_19_C | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_19_D | CWE-22 | finding | no_finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_20_A | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_20_B | CWE-22 | masked | masked | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_20_C | CWE-22 | finding | no_finding | UNSET (unset) | MEDIUM->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |
| CASE_20_D | CWE-22 | finding | no_finding | UNSET (unset) | HIGH->MEDIUM | 2 | **ESCALATE** | verification budget (2) exhausted; unresolved: scanner_conflict |

Records: 80. Final actions: {'PROCEED': 1, 'VERIFY': 0, 'ESCALATE': 79}. Policy lane5-rules-v1; max 2 read-only verify calls. No ground-truth labels are read or shown.
