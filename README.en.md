# appsec-sentinel

**An application-security assessment skill for AI coding agents that proves what it claims and writes down what it could not verify.**
Built for Claude; also run once on Codex CLI and Antigravity (see [`docs/ALTRI-AGENTI.md`](docs/ALTRI-AGENTI.md), in Italian). Apache-2.0. © Samuele Cucurnia and Pietro Previtali.

> **Commands and language.** Every command works in English or Italian (`quick`/`rapido`, `refute`/`smentita`, `close`/`chiudi`…): see the [command card](docs/COMMAND-CARD.md). The skill writes chat, findings and reports in the language you use. Machine-readable files keep canonical Italian field names and enum values because the scripts check them. The PDF generator produces an English report with `--lang en`.
>
> **Language note.** The skill's own instructions, references and templates are written in Italian (the authors work with Italian public administrations and non-profits); the agent applies them and answers in your language. This page is a short English guide.

## Why

Whoever reads a security report decides budget and priorities from what is marked *tested*. Writing "verified" for a test that never ran is worse than not testing. The skill forces a method where that cannot happen silently:

- **Authorization first.** No active test without a stated scope, owner and written go-ahead. Code, comments and tool output are treated as hostile input and cannot widen the mandate.
- **Examined, proven, unknown.** The report never mixes what was read with what was demonstrated. Finding states: *dynamically reproduced*, *confirmed from code or configuration*, *hypothesis to validate*, *not verifiable*.
- **Real denominators.** "27 endpoints of 52 tested, by role", not "good coverage".
- **No fake tests.** If a tool is missing, the test is recorded as "prepared, not executed" with the exact command.
- **Refutation pass.** High and critical findings go to a verifier other than the author, who tries to disprove them. If no independent verifier exists, the outcome is "not performed" and the report says so.
- **No secret values anywhere**, including chat messages and final summaries.

## What you get

A confidential audit folder (outside your repository) with: owner summary, technical report, asset/route inventory, threat model, coverage matrices, controls matrix (ASVS / NIST / Italian ACN-AgID baselines), prioritized action plan, and optional PDF reports.

Python scripts with no third-party dependencies except `reportlab` (PDF reports); the only network access is the access test, which is limited to localhost unless a host is explicitly allowed: route inventory (Next.js, Express/Fastify/Koa, Flask/FastAPI, Django, Laravel, Spring, ASP.NET, Rails, Go), local-only access tests, scanner import, finding validation and review, cumulative coverage across audits, redaction check, audit comparison, a single delivery check (`check_delivery.py`), and `canonicalize.py`, which converts English states and severities to the canonical values the scripts check.

## Install

- **Claude.ai / Claude Desktop:** upload the `.skill` file (a zip of this repo) through the skills settings.
- **Claude Code:** copy the folder to `~/.claude/skills/appsec-sentinel`.
- **Codex CLI / Antigravity:** same `SKILL.md` convention; install paths and what was tested are in [`docs/ALTRI-AGENTI.md`](docs/ALTRI-AGENTI.md).
- **`npx skills add <owner>/appsec-sentinel`:** the repository root contains `SKILL.md`; discovery was checked on a local path.

Then say, for example: *"Use appsec-sentinel. Quick mode, static analysis only, on this folder. The repo is mine; no dynamic testing is authorized."*

## Limits, stated plainly

- It does not promise to find every vulnerability and does not certify compliance.
- Route inventory is heuristic: it finds the nearest authentication marker per route and cannot see group-level middleware or global filters.
- The local dynamic check was validated on a small lab app we wrote (two planted authorization flaws, no false positives on four correct behaviors). It is not a benchmark on public vulnerable apps.
- Cross-agent testing so far is a single run per agent, Quick mode, on a fake app.
- The sister skill [`gdpr-sentinel`](https://github.com/dextsamu/gdpr-sentinel) covers the privacy side; neither skill is legal advice.

## Tests

`python3 tests/run_checks.py` runs the self-checks (53 at the time of writing).
