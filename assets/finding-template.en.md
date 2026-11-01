# {ID} — {Concrete finding title}

> English edition of `finding-template.md`. In the JSON file the field names and the canonical values stay in Italian (see the end of this page); only the free text may be written in English.

| Field | Value |
|---|---|
| ID | APP-001 |
| Category | e.g. Authorization / BOLA |
| Asset · environment · version | e.g. api.example.com · staging · commit abc1234 |
| **Status** | reproduced dynamically (`riprodotto dinamicamente`) · confirmed from code or configuration (`confermato da codice o configurazione`) · hypothesis to validate (`ipotesi da validare`) · not verifiable (`non verificabile`) |
| Severity | critical (`critica`) · high (`alta`) · medium (`media`) · low (`bassa`) · informational (`informativa`) — *rationale below* |
| CWE | e.g. CWE-639 |
| CVSS | version + vector + score (only if the data suffice; **never** for the mere absence of a document) |
| References | ASVS v?.?.? 4.2.1 · WSTG-ATHZ-04 · NIST … |
| Confidence | high (`alta`) · medium (`media`) · low (`bassa`) |

## Actor, prerequisites, entry point
Who can exploit it, with which privileges/conditions, from which entry point; which trust boundary is crossed.

## Minimal evidence
File:lines, configuration or **redacted** request/response (no secrets, no real personal data). Explain why the evidence supports the conclusion.

## Expected / observed
- Expected:
- Observed:
- Negative control (if useful):

## Reproduction
Steps to run **only in the authorized environment**, with synthetic identities.

## Impact
- Real (demonstrated):
- Potential:
- Conditions limiting exploitation:

## Severity rationale
Why this severity, in this context.

## Recommended action
- Fix:
- Temporary mitigation:
- Dependencies:
- Proposed owner · priority:
- Regression test / retest:

## Limits of the analysis
What was not verified and why.

---
*If the finding concerns privacy/compliance:* law and article, observed fact, applicability, risk to data subjects, question for the controller/DPO/legal counsel.

## Allowed values in the JSON (validated by `scripts/validate_findings.py`)
- `prova.tipo`: `codice`, `configurazione`, `richiesta-risposta`, `log-tool`, `documento`, `nessuna`.
- `stato`: `riprodotto dinamicamente`, `confermato da codice o configurazione`, `ipotesi da validare`, `non verificabile`.
- `privacy` (privacy/compliance findings only): `norma_articolo`, `applicabilita`, `rischio_interessati`, `da_sottoporre_a` (`titolare` = controller, `DPO`, `legale` = legal counsel, `fornitore` = vendor). No other fields are allowed: put notes in `limiti`.
- If you write English values by mistake, `scripts/canonicalize.py` maps them back to the canonical Italian ones.
