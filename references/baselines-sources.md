# Baseline, standard e fonti ufficiali

Questo file va **ricontrollato a ogni audit**: le pagine cambiano, le edizioni si aggiornano, i link possono rompersi.

Ultima verifica dei link: 29 ottobre 2026 (tutti raggiungibili; `cisa.gov` risponde 403 e `eur-lex.europa.eu` risponde 202 alle richieste automatiche per via di protezioni anti-bot: aprili da browser). Versioni correnti a quella data: **OWASP ASVS 5.0.0** (stabile); **OWASP API Security Top 10 edizione 2023**; **OWASP Top 10 for LLM Applications edizione 2026** (il repository indica la pubblicazione al 4 agosto 2026; la precedente era la 2025). Riverificale a ogni audit.

## Regole d'uso
- Usa le versioni stabili pertinenti alla data dell'audit. Per ogni fonte registra: URL, titolo, versione, data di consultazione, controllo/sezione.
- Se non puoi navigare, dichiaralo: non presentare riferimenti ricordati come aggiornati.
- Le fonti normative ufficiali prevalgono sui riassunti; le divergenze fra fonti vanno rese esplicite.
- Se un portale richiede JavaScript/login o è irraggiungibile, registra il limite. Un risultato indicizzato non equivale alla lettura integrale. Non dichiarare verificata una versione che non hai controllato.
- Distingui sempre **benchmark**, **obbligo legale** e **buona pratica**.

## Baseline di default
- **OWASP ASVS**: motiva il livello atteso (L1/L2/L3) e le esclusioni; L3 si valuta per applicabilità, non si assume. Il Top 10 non è la copertura completa.
- **OWASP WSTG** per le prove manuali; **API Security Top 10** per le API; **Cheat Sheet Series** per i dettagli implementativi.
- **NIST SP 800-115** (assessment e regole di ingaggio), **SSDF SP 800-218** (sviluppo e supply chain), **CSF** (governance, protezione, rilevazione, risposta, ripristino), **Digital Identity Guidelines SP 800-63** (identità).
- **CWE/CAPEC** per debolezze e scenari; **MITRE ATT&CK** quando pertinente al percorso di compromissione.
- **CVSS** (dichiara la versione) ed eventualmente **EPSS** come supporto alla priorità, non sostituti del contesto; advisory dei produttori, CVE, **CISA KEV** per le dipendenze.
- **Italia / PA / NIS2**: aggiungi le indicazioni ACN e AgID pertinenti (misure di sicurezza, linee guida, determinazioni ACN applicabili). Verifica se l'organizzazione rientra davvero nell'ambito NIS2 prima di trattarla come obbligo.
- Da valutare **solo se emergono presupposti concreti**: DORA, PCI DSS, AI Act, CRA, regole sanitarie/lavoro/minori. Non considerarli automaticamente applicabili.
- AI: OWASP GenAI/LLM Top 10 e rischi degli agenti. Mobile: MASVS/MASTG solo se esiste una componente mobile pertinente.
- Privacy: vedi skill `gdpr-sentinel`.

## Baseline opzionali
Per una scala Basso/Medio/Alto, per AgID Misure minime, ACN, NIST 800-53B, Framework Nazionale o una baseline fornita dal cliente: leggi `optional-baselines.md`.

## Fonti ufficiali iniziali

**OWASP e sicurezza applicativa**
- Application Security Verification Standard — https://asvs.owasp.org/
- Web Security Testing Guide — https://owasp.org/projects/web-security-testing-guide
- API Security Top 10 — https://api-security.owasp.org/ (edizione 2023: /editions/2023/en/0x11-t10/)
- Cheat Sheet Series — https://cheatsheetseries.owasp.org/
- GenAI Security Project / LLM Top 10 — https://github.com/GenAI-Security-Project/GenAI-LLM-Top10 (incrociare con le pubblicazioni OWASP correnti)

**NIST, classificazione e vulnerabilità note**
- NIST SP 800-115 — https://csrc.nist.gov/pubs/sp/800/115/final
- NIST Rules of Engagement (glossario) — https://csrc.nist.gov/glossary/term/rules_of_engagement
- NIST SSDF SP 800-218 — https://csrc.nist.gov/pubs/sp/800/218/final
- NIST Cybersecurity Framework — https://www.nist.gov/cyberframework
- NIST Digital Identity Guidelines — https://pages.nist.gov/800-63-4/
- MITRE CWE — https://cwe.mitre.org/ · CAPEC — https://capec.mitre.org/ · ATT&CK — https://attack.mitre.org/
- FIRST CVSS — https://www.first.org/cvss/ (specifica v4.0: /v4.0/specification-document) · EPSS — https://www.first.org/epss/
- CISA KEV — https://www.cisa.gov/known-exploited-vulnerabilities-catalog · mirror dati: https://github.com/cisagov/kev-data (ricontrolla provenienza e data)

**Italia**
- ACN (Agenzia per la Cybersicurezza Nazionale) — https://www.acn.gov.it/ ; NIS: modalità e specifiche di base — https://www.acn.gov.it/portale/nis/modalita-specifiche-base
- AgID — https://www.agid.gov.it/ ; Misure minime di sicurezza ICT per le PA — https://www.agid.gov.it/it/sicurezza/misure-minime-sicurezza-ict

Altre baseline (NIST 800-53B, Framework Nazionale, ISO, CIS): `optional-baselines.md`.

Per le fonti GDPR/ePrivacy/Garante/EDPB vedi `gdpr-sentinel/references/sources.md`.
