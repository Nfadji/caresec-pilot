# CARE-Sec pilot: baseline comparison (B1, B2, B3)

Records: 80 (20 base cases x 4 conditions). **No truth file was read, so correctness is not reported.**
Counts only. Nothing here is a per-record result.

## What each baseline produced

| baseline | records with output | gave a final answer | deferred | demo runs left out |
|---|---|---|---|---|
| B1 LLM alone | 0 of 80 | 0 of 80 | 0 of 80 | 0 |
| B2 LLM + scanners, no escalation | 0 of 80 | 0 of 80 | 0 of 80 | 0 |
| B3 CARE-Sec PROCEED / VERIFY / ESCALATE | 80 of 80 | 0 of 80 | 80 of 80 | 0 |

Deferred means no automated answer: the model returned no verdict (B1, B2) or the controller escalated to a person (B3). Runs made with `--um` are demos and are left out of B3.

## By evidence condition

| condition | B2 final answers | B3 final answers | B3 escalated | B3 verify calls |
|---|---|---|---|---|
| A Complete | 0 of 20 | 0 of 20 | 20 of 20 | 22 |
| B Masked | 0 of 20 | 0 of 20 | 20 of 20 | 40 |
| C Disagreement | 0 of 20 | 0 of 20 | 20 of 20 | 22 |
| D Provenance gap | 0 of 20 | 0 of 20 | 20 of 20 | 36 |

## Verification

B3 decided 80 records, made a verify call on 60 of them, 120 calls in all (limit 2 per record).

