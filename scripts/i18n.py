# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Messaggi in inglese per gli script del percorso di consegna (`--lang en` o SENTINEL_LANG=en).

Uso negli script: `import i18n; i18n.install()` prima di argparse. Con la lingua inglese filtra stdout/stderr
sostituendo frasi fisse (tabella PHRASES): non tocca testo libero, titoli dei finding, nomi di file né dati.
Le frasi non in tabella restano in italiano: è una traduzione dei messaggi fissi, non dei contenuti.
I valori canonici dei file macchina (stati, severità) non vengono mai modificati.
"""
import os
import re
import sys

PHRASES = [
    # check_delivery
    ("Controllo di consegna:", "Delivery check:"),
    ("Controlli meccanici: non provano che l'audit sia corretto. Rileggi il report; nei messaggi di chat non scrivere mai valori di segreti.",
     "Mechanical checks: they do not prove the audit is correct. Re-read the report; never write secret values in chat messages."),
    ("esito:", "result:"), ("da verificare", "to verify"), ("falliti", "failed"),
    ("DA VERIFICARE", "TO VERIFY"), ("FALLITO", "FAILED"),
    ("cartella di audit fuori da Git", "audit folder outside Git"), ("cartella di audit", "audit folder"),
    ("è dentro un repository Git", "is inside a Git repository"), ("non esiste", "does not exist"),
    ("né findings/findings.json né gdpr-matrix.csv", "neither findings/findings.json nor gdpr-matrix.csv"),
    ("file attesi", "expected files"),
    ("valori enumerati canonici", "canonical enumerated values"),
    ("validazione dei finding (schema e coerenza)", "finding validation (schema and consistency)"),
    ("validazione dei finding", "finding validation"), ("lettura dei finding", "reading findings"),
    ("smentita dei finding alti", "refutation of high findings"),
    ("nessun finding alto o critico", "no high or critical finding"),
    ("finding alti con esito", "high findings with an outcome"),
    ("mancante su", "missing on"),
    ("«non eseguita» su", "“not performed” on"),
    ("dichiararlo nel report come limite", "state it in the report as a limit"),
    ("revisore dei finding", "findings reviewer"),
    ("rilievi da risolvere o motivare (esegui verify_findings.py)", "issues to fix or justify (run verify_findings.py)"),
    ("matrice GDPR A–N", "GDPR matrix A–N"), ("matrice GDPR", "GDPR matrix"),
    ("errori (esegui check_matrix.py)", "errors (run check_matrix.py)"), ("warning (esegui check_matrix.py)", "warnings (run check_matrix.py)"),
    ("redazione (segreti e dati personali)", "redaction (secrets and personal data)"),
    ("trovati segreti (esegui redact_check.py)", "secrets found (run redact_check.py)"),
    ("valori dei segreti dell'app assenti dall'audit", "app secret values absent from the audit"),
    ("valore di un segreto in", "a secret value from"),
    ("parole vietate («conforme», «sicuro»…)", "forbidden words (“compliant”, “secure”…)"),
    ("copertura con denominatori", "coverage with denominators"),
    ("aree minime nel registro (dipendenze, segreti)", "minimum areas in the log (dependencies, secrets)"),
    ("checklist delle aree (checklist-rapido.csv)", "area checklist (checklist-rapido.csv)"),
    ("meta.json compilato (versione, oggetto, data)", "meta.json filled in (version, subject, date)"),
    ("route senza auth classificate una per una", "unauthenticated routes classified one by one"), ("senza classificazione:", "without classification:"), ("ancora il testo del modello:", "still the template text:"),
    ("cause distinte", "distinct causes"), ("viste da tutti", "seen by all"), ("accordo", "agreement"), ("giri:", "runs:"),
    ("possibile stessa causa (non uniti, da decidere a mano)", "possible same cause (not merged, decide manually)"),
    ("pre-passaggio completato", "pre-pass completed"), ("checklist pre-compilata", "checklist pre-filled"),
    ("le altre aree restano da fare a mano", "the other areas remain manual"),
    ("aree su", "areas out of"), ("non compilate", "not filled in"), ("(anche «non esaminato» va bene, con il motivo)", "(“non esaminato” is fine too, with the reason)"),
    ("Checklist delle aree", "Area checklist"), ("Aree:", "Areas:"), ("esaminate:", "examined:"), ("parziali:", "partial:"),
    ("non esaminate:", "not examined:"), ("non applicabili:", "not applicable:"), ("NON COMPILATA", "NOT FILLED IN"),
    ("nel registro di copertura manca:", "the coverage log is missing:"),
    ("non disponibile in questa skill", "not available in this skill"), ("non disponibile", "not available"),
    ("ha fallito", "failed"),
    ("da rileggere", "to re-read"),
    # validate_findings
    ("campo obbligatorio mancante", "required field missing"), ("stato non valido", "invalid status"),
    ("severita non valida", "invalid severity"), ("ID duplicato", "duplicate ID"),
    ("ma prova.test_eseguito non è true", "but prova.test_eseguito is not true"),
    ("motiva esplicitamente il livello", "justify the level explicitly"),
    ("CVSS senza versione", "CVSS without version"),
    ("CVSS su finding privacy/compliance: non va attribuito alla mera assenza di un documento",
     "CVSS on a privacy/compliance finding: do not assign it for the mere absence of a document"),
    ("non redatto nei testi del finding", "not redacted in the finding text"), ("possibile", "possible"),
    ("ERRORE di lettura", "READ ERROR"), ("ERRORE:", "ERROR:"), ("ERRORE ", "ERROR "),
    ("findings.json deve contenere un array di finding", "findings.json must contain an array of findings"),
    ("nota: modulo jsonschema non installato, uso il controllo minimo (pip install jsonschema per quello completo)",
     "note: jsonschema module not installed, using the minimal check (pip install jsonschema for the full one)"),
    ("errori ·", "errors ·"), ("finding ·", "findings ·"),
    # verify_findings
    ("stato «confermato da codice o configurazione» senza riferimenti a file", "status “confermato da codice o configurazione” with no file references"),
    ("riferimento inesistente", "reference does not exist"), ("oltre la fine di", "past the end of"), ("righe)", "lines)"),
    ("giustificare o declassare", "justify or downgrade"),
    ("finding alto senza mitigazione temporanea", "high finding without a temporary mitigation"),
    ("finding alto senza smentita: farlo confutare da un verificatore diverso dall'autore (brief con --brief-dir)",
     "high finding without refutation: have a verifier other than the author try to refute it (brief with --brief-dir)"),
    ("smentita non eseguita: dichiararlo nel report come limite", "refutation not performed: state it in the report as a limit"),
    ("smentita fatta dall'autore stesso: non è indipendente, usare «non eseguita» oppure un verificatore diverso",
     "refutation done by the author: not independent, use “non eseguita” or a different verifier"),
    ("senza tentativi descritti", "with no attempts described"),
    ("ma il finding è ancora", "but the finding is still"), ("allineare severità e stato", "align severity and status"),
    ("manca il retest", "retest missing"),
    ("l'impatto «reale» afferma un effetto senza test eseguito: riformulare come potenziale o dichiarare il limite",
     "the “real” impact asserts an effect with no test run: rephrase as potential or state the limit"),
    ("possibile duplicato di", "possible duplicate of"),
    ("rilievi del revisore", "reviewer issues"),
    # coverage_summary
    ("File/componenti", "Files/components"), ("Voci inventariate", "Inventoried items"),
    ("Esaminate per intero (si)", "Fully examined (si)"), ("Esaminate in parte (parziale)", "Partly examined (parziale)"),
    ("Da audit precedente", "From previous audit"), ("voci riportate (contenuto invariato)", "items carried over (content unchanged)"),
    ("stantie da rifare", "stale, to redo"),
    ("ATTENZIONE:", "WARNING:"), ("voci non esaminate senza motivo di esclusione", "items not examined without an exclusion reason"),
    ("Endpoint × identità", "Endpoint × identity"), ("Endpoint×metodo censiti", "Endpoint×method inventoried"),
    ("con almeno un test eseguito", "with at least one test run"),
    ("Righe scoperte da una sola fonte (da incrociare)", "Rows discovered from a single source (to cross-check)"),
    ("Controlli (baseline)", "Controls (baseline)"), ("Requisiti censiti", "Requirements inventoried"),
    ("applicabili", "applicable"), ("non applicabili", "not applicable"),
    ("Audit documentale", "Documentary audit"), ("Voci esaminate", "Items examined"),
    ("Ignorate", "Ignored"), ("righe d'esempio del template in", "template example rows in"),
    ("assente", "missing"),
    ("I conteggi riguardano solo ciò che è stato inventariato: non provano l'assenza di asset o vulnerabilità non censiti.",
     "Counts cover only what was inventoried: they do not prove the absence of uninventoried assets or vulnerabilities."),
    ("Riepilogo di copertura (conteggi con denominatore)", "Coverage summary (counts with denominators)"),
    ("(indica nelle note cosa è stato letto e cosa no)", "(note in the log what was read and what was not)"),
    ("Non esaminate o escluse con motivo", "Not examined or excluded with a reason"),
    ("Combinazioni (endpoint×identità×azione) pianificate", "Combinations (endpoint×identity×action) planned"),
    ("eseguite:", "run:"), ("mancanti:", "missing:"),
    # init_audit
    ("è dentro un repository Git. Le evidenze di audit non devono finire in Git.", "is inside a Git repository. Audit evidence must not end up in Git."),
    ("salto (esiste)", "skipping (exists)"), ("Cartella di audit pronta", "Audit folder ready"),
    ("Prossimo passo: compilare 00-regole-di-ingaggio.md e farla confermare dal proprietario.",
     "Next step: fill in 00-regole-di-ingaggio.md and have the owner confirm it."),
    # redact_check
    ("(valore non mostrato)", "(value not shown)"), ("CONTROLLARE", "CHECK"), ("ALTO ", "HIGH "),
    ("NON LETTO", "NOT READ"), ("serve pdftotext o pypdf", "needs pdftotext or pypdf"),
    ("file controllati", "files checked"), ("segreti:", "secrets:"), ("possibili dati personali", "possible personal data"),
]
PHRASES.sort(key=lambda p: -len(p[0]))
_RX = re.compile("|".join(re.escape(a) for a, _ in PHRASES))
_MAP = dict(PHRASES)


def lang():
    return "en" if os.environ.get("SENTINEL_LANG", "").lower().startswith("en") else "it"


def tr(s):
    if lang() != "en":
        return s
    s = _RX.sub(lambda m: _MAP[m.group(0)], s)
    return re.sub(r"(\d+)\*{0,2} su (\d+)", lambda m: m.group(0).replace(" su ", " of "), s)


class _Filter:
    def __init__(self, base):
        self._b = base

    def write(self, s):
        return self._b.write(tr(s))

    def __getattr__(self, k):
        return getattr(self._b, k)


def install():
    """Legge `--lang en|it` da argv (e lo toglie), lo propaga ai sottoprocessi e filtra stdout/stderr."""
    a = sys.argv
    for i, x in enumerate(a):
        if x == "--lang" and i + 1 < len(a):
            os.environ["SENTINEL_LANG"] = a[i + 1]
            del a[i:i + 2]
            break
        if x.startswith("--lang="):
            os.environ["SENTINEL_LANG"] = x.split("=", 1)[1]
            del a[i]
            break
    if lang() == "en":
        sys.stdout = _Filter(sys.stdout)
        sys.stderr = _Filter(sys.stderr)
