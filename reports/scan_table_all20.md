| case_id | cwe | semgrep | semgrep_rule | semgrep_lines | codeql | codeql_rule | codeql_lines | agree | hash |
|---|---|---|---|---|---|---|---|---|---|
| CASE_01 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 55-55 | finding | java/path-injection | 55-55 | yes | crlf_normalized |
| CASE_02 | CWE-22 | no_finding |  |  | finding | java/path-injection | 56-56 | no | crlf_normalized |
| CASE_03 | CWE-89 | finding | caresec.java.cwe89.sql-injection-sink | 40-40 | finding | java/sql-injection | 40-40 | yes | crlf_normalized |
| CASE_04 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 37-37 | finding | java/path-injection | 47-47 | yes | crlf_normalized |
| CASE_05 | CWE-89 | finding | caresec.java.cwe89.sql-injection-sink | 42-42 | finding | java/sql-injection | 42-42 | yes | crlf_normalized |
| CASE_06 | CWE-89 | no_finding |  |  | finding | java/sql-injection | 37-37 | no | crlf_normalized |
| CASE_07 | CWE-89 | no_finding |  |  | no_finding |  |  | yes | crlf_normalized |
| CASE_08 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 61-61 | no_finding |  |  | no | crlf_normalized |
| CASE_09 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 62-62 | no_finding |  |  | no | crlf_normalized |
| CASE_10 | CWE-89 | no_finding |  |  | no_finding |  |  | yes | crlf_normalized |
| CASE_11 | CWE-89 | no_finding |  |  | finding | java/concatenated-sql-query | 61-61 | no | crlf_normalized |
| CASE_12 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 55-55 | finding | java/path-injection | 65-65 | yes | crlf_normalized |
| CASE_13 | CWE-89 | finding | caresec.java.cwe89.sql-injection-sink | 37-37 | finding | java/sql-injection | 37-37 | yes | crlf_normalized |
| CASE_14 | CWE-89 | no_finding |  |  | finding | java/sql-injection | 41-41 | no | crlf_normalized |
| CASE_15 | CWE-89 | finding | caresec.java.cwe89.sql-injection-sink | 38-38 | no_finding |  |  | no | crlf_normalized |
| CASE_16 | CWE-89 | finding | caresec.java.cwe89.sql-injection-sink | 37-37 | no_finding |  |  | no | crlf_normalized |
| CASE_17 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 104-104 | finding | java/path-injection | 108-108 | yes | crlf_normalized |
| CASE_18 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 84-84 | no_finding |  |  | no | crlf_normalized |
| CASE_19 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 48-48 | no_finding |  |  | no | crlf_normalized |
| CASE_20 | CWE-22 | finding | caresec.java.cwe22.path-traversal-sink | 43-43 | no_finding |  |  | no | crlf_normalized |

Cases: 20. Semgrep 1.185.0: {'finding': 14, 'no_finding': 6}. CodeQL 2.27.4: {'finding': 11, 'no_finding': 9}. Scanners agree on 9 of 20 cases where both ran.

`finding` / `no_finding` refer only to the case's target CWE; `hash` is the manifest SHA-256 check (`crlf_normalized` = matches after a line-ending swap). No ground-truth labels are used or shown here.
