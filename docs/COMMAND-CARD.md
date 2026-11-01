# Command card · appsec-sentinel (English)

Type the command after `/appsec-sentinel` (or as the first word of your request). Every command works in English or Italian: the Italian word is in brackets. **No command skips the authorization gate:** active tests need a scope and written confirmation.
Reports, findings and chat follow your language. Machine-readable files (`findings.json`, CSV matrices) keep their canonical Italian field names and enum values because the scripts check them; the free text inside is in your language.

## The flow in six lines
1. `quick <repo>` (or `standard`, `full`): intake, rules of engagement, mode.
2. `inventory <repo>`: endpoint matrix with routes lacking evident authentication first.
3. `scanner <file…>` and, if authorized, `dynamic <config> <tests>`: scanner hypotheses and access proofs.
4. `review` and `refute`: false positives, and a verifier who tries to disprove the high findings.
5. `close` then `pdf`: delivery check (secrets, refutations, forbidden words), then the report.
6. `compare <old> <new>` after the fixes: resolved, new, changed.

## Start
| Command | What it does |
|---|---|
| `quick <repo>` (`rapido`) | Targeted triage (hours), static analysis |
| `standard <repo> [url]` | Threat model, static analysis, authorized dynamic checks, relevant ASVS controls |
| `full <repo> [url]` (`completo`) | File-by-file inventory, extended ASVS |
| `area <authz\|secrets\|dependencies\|infra\|input\|ai> <repo>` | One area only, with its coverage stated (Italian arguments `segreti`, `dipendenze` also work) |

## Analysis
| Command | What it does | Limit |
|---|---|---|
| `inventory <repo>` (`inventario`) | Draft `endpoint-matrix.csv` | Heuristic: every row still to verify |
| `openapi <file> [repo]` | Imports an OpenAPI/Swagger spec as the endpoint matrix; with the repo, diffs spec vs code | The spec states intent, not protection |
| `iac <repo>` | 14 pattern rules on Dockerfile, compose, Kubernetes, Terraform, GitHub Actions (SARIF output) | Hints only, all "hypothesis to validate" |
| `scanner` (no files) | Runs `npm audit` on the lockfile alone (no node_modules needed) and scans Git history for secrets | If a scanner cannot run, the reason and the prepared command are logged as a limit |
| `scanner <file…>` | Imports npm audit, SARIF, gitleaks, osv, semgrep, trivy, ZAP as candidates | Only "hypothesis to validate", never above "medium" |
| `dynamic <config> <tests>` (`dinamico`) | Tests access per identity | Localhost or an authorized host only; read-only by default |
| `documentary <repo>` (`documentale`) | Compares documents with code | States: consistent, inconsistent, obsolete, duplicate, missing |
| `privacy <repo>` | Hands over to `gdpr-sentinel` | Needs the sister skill |

| `prepass <repo>` | Runs every automated tool in a fixed order and pre-fills the 14-area checklist (`checklist-rapido.csv`) | Identical between runs; candidates are hypotheses, not findings |

## Verify and deliver
| Command | What it does |
|---|---|
| `review [folder]` (`revisione`) | Nonexistent references, severity without evidence, duplicates, reviewer questions |
| `report [folder]` | Validates findings and coverage, produces summary and technical report |
| `close [folder]` (`chiudi`) | Delivery check in one step; zero "FAIL" before delivering |
| `refute [folder]` (`smentita`) | A verifier other than the author tries to refute every high or critical finding |
| `redact [folder]` (`redazione`) | Looks for secrets and personal data in files and the PDF; never prints values |
| `pdf [folder]` | Corporate PDF report. Options: `--sintetico` (short), `--lang en`, `--previous`, `--nis2` |
| `export [folder]` (`esporta`) | CSV, SARIF, Markdown for issues |
| `canonicalize [folder]` (`normalizza`) | Converts English states, severities and outcomes to the canonical Italian values the scripts check; free text untouched. `close` tells you when it is needed |

| `double <repo>` (`doppio`) | Two independent `quick` runs by separate sub-agents, then merged | Use when the result matters: one run alone missed about a third of the causes on two real repositories |
| `merge <audit…>` (`unisci`) | Merges two or more independent runs on the same repo: matches by file/lines, CWE and title (never by ID), reports agreement | A cause seen by one run only is not less true: only one run looked for it |

## After the fixes
| Command | What it does |
|---|---|
| `retest <ID> [branch]` | Repeats the original case, tries alternative paths and other roles |
| `compare <old> <new>` (`confronta`) | Resolved, new, changed. "Resolved" is not "verified" |
| `resume <old> <new>` (`riprendi`) | Repeated audit: carries over unchanged coverage, marks changed items and gaps |
| `plan [folder]` (`piano`) | Action plan from the existing findings |
| `status [folder]` (`stato`) | Coverage and open findings, no new activity |

## Remember
- Finding states: *dynamically reproduced* · *confirmed from code or configuration* · *hypothesis to validate* · *not verifiable* (canonical values: `riprodotto dinamicamente`, `confermato da codice o configurazione`, `ipotesi da validare`, `non verificabile`).
- A test that was not run stays "no" in the matrix: never "proven" without output.
- Audit files and reports are confidential: keep them out of Git and public repositories.
