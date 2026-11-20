| case_id | cwe | semgrep | semgrep_rule | semgrep_lines | codeql | codeql_rule | codeql_lines | agree | hash |
|---|---|---|---|---|---|---|---|---|---|
| CASE_01 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 55-55 | finding | java/path-injection | 55-55 | yes | crlf_normalized |
| CASE_02 | CWE-22 | no_finding |  |  | finding | java/path-injection | 56-56 | no | crlf_normalized |
| CASE_03 | CWE-89 | finding | caresec.java.cwe89.sql-injection-sink | 40-40 | finding | java/sql-injection | 40-40 | yes | crlf_normalized |
| CASE_04 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 37-37 | finding | java/path-injection | 47-47 | yes | crlf_normalized |
| CASE_05 | CWE-89 | finding | caresec.java.cwe89.sql-injection-sink | 42-42 | finding | java/sql-injection | 42-42 | yes | crlf_normalized |

Cases: 5. Semgrep 1.185.0: {'finding': 4, 'no_finding': 1}. CodeQL 2.27.4: {'finding': 5}. Scanners agree on 4 of 5 cases where both ran.

`finding` / `no_finding` refer only to the case's target CWE; `hash` is the manifest SHA-256 check (`crlf_normalized` = matches after a line-ending swap). No ground-truth labels are used or shown here.
