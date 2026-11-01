# Rules of engagement — {project name}

> English edition of `engagement-rules-template.md`. To be filled in and **confirmed in writing by the owner** before any active test. An empty field = that activity is not authorized.

## 1. Mandate
- Owner / contact (name, role, contact details):
- Assessor:
- Start date · end date · permitted windows:
- Mode: ☐ rapido (quick) ☐ standard ☐ completo (full)
- Baseline: ☐ ASVS+NIST+ACN/AgID (default) ☐ optional (see `references/optional-baselines.md`): 

## 2. Authorized assets (exact)
| Asset (domain/IP/API/tenant/bucket/repo) | Environment | Version/commit | Notes |
|---|---|---|---|
| | | | |

Explicitly excluded (third-party services, production, IP ranges, etc.):

## 3. Authorized activities (one by one)
- ☐ Static / documentary analysis
- ☐ Active scanning
- ☐ Application pentest (synthetic identities: …)
- ☐ Tests with state effects (creating/changing synthetic data)
- ☐ Availability/load tests (requires an approved profile: see `references/availability-gated.md`)
- Forbidden unless specifically authorized: deletions, purchases, sending email/SMS, real permissions, exfiltration, irreversible actions, phishing/social engineering, brute force on real accounts, domain registration.

## 4. Numeric limits and stop conditions
Max requests · max concurrency · duration · data created · storage · vendor calls · cost ceiling: **(to be defined by the owner, no default values)**
Stop thresholds (errors, latency, saturation, backlog, quota, spend):
Kill-switch owner (name, contact, channel):
Recovery procedure:

## 5. Tools and confidentiality
Permitted tools · vendors that receive data through the tools · data that must NOT leave the perimeter:

## 6. Evidence
Approved destination · named access · encryption at rest · retention (days) · return/deletion and its verification:

## 7. Escalation
Operational contact during the tests · contact for incidents/signs of compromise:

## 8. Legal and confidentiality
- The signatory declares they are entitled to authorize testing of the assets in section 2 (ownership or written delegation by the owner; for third-party services the vendor's authorization is also needed, under its terms). Without authorization, accessing computer systems may be a criminal offence (in Italy, for example, art. 615-ter of the Penal Code).
- Non-disclosure agreement (NDA) between the parties: ☐ signed ☐ not needed
- If the assessor may access personal data during the tests: ☐ appointment as processor (GDPR art. 28) or equivalent controller instructions ☐ synthetic data only
- Agreed limitation of liability (if the contract provides one):
- Vulnerability reporting: timing and recipients of finding communication, and a ban on disclosure to third parties without the owner's consent.

## 9. Confirmation
Owner's signature/confirmation email and date:
