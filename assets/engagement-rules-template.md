# Regole di ingaggio — {nome progetto}

> Da compilare e **far confermare per iscritto dal proprietario** prima di qualunque test attivo. Un campo vuoto = quella attività non è autorizzata.

## 1. Mandato
- Proprietario / referente (nome, ruolo, contatto):
- Esecutore:
- Data inizio · data fine · finestre ammesse:
- Modalità: ☐ rapido ☐ standard ☐ completo
- Baseline: ☐ ASVS+NIST+ACN/AgID (default) ☐ opzionale (vedi `references/optional-baselines.md`): 

## 2. Asset autorizzati (esatti)
| Asset (dominio/IP/API/tenant/bucket/repo) | Ambiente | Versione/commit | Note |
|---|---|---|---|
| | | | |

Esclusi esplicitamente (servizi terzi, produzione, blocchi IP, ecc.):

## 3. Attività autorizzate (una per una)
- ☐ Analisi statica / documentale
- ☐ Scansione attiva
- ☐ Pentest applicativo (identità sintetiche: …)
- ☐ Test con effetti di stato (creazione/modifica dati sintetici)
- ☐ Test di disponibilità/carico (richiede profilo approvato: vedi `references/availability-gated.md`)
- Vietate salvo autorizzazione specifica: cancellazioni, acquisti, invio email/SMS, permessi reali, esfiltrazioni, azioni irreversibili, phishing/social engineering, brute force su account reali, registrazione domini.

## 4. Limiti numerici e arresto
Richieste max · concorrenza max · durata · dati creati · storage · chiamate a fornitori · tetto di costo: **(da definire dal proprietario, nessun valore di default)**
Soglie di arresto (errori, latenza, saturazione, backlog, quota, spesa):
Responsabile kill switch (nome, contatto, canale):
Procedura di recupero:

## 5. Strumenti e riservatezza
Tool ammessi · fornitori che ricevono dati tramite i tool · dati che NON devono lasciare il perimetro:

## 6. Evidenze
Destinazione approvata · accessi nominativi · protezione a riposo · conservazione (giorni) · restituzione/cancellazione e verifica:

## 7. Escalation
Contatto operativo durante i test · contatto per incidenti/indizi di compromissione:

## 8. Aspetti legali e riservatezza
- Il firmatario dichiara di avere titolo per autorizzare i test sugli asset del punto 2 (proprietà o delega scritta del proprietario; per servizi di terzi serve anche l'autorizzazione del fornitore, secondo le sue condizioni). Senza autorizzazione, l'accesso a sistemi informatici può costituire reato (in Italia, ad esempio, art. 615-ter c.p.).
- Accordo di riservatezza (NDA) fra le parti: ☐ firmato ☐ non necessario
- Se l'esecutore può accedere a dati personali durante i test: ☐ nomina a responsabile del trattamento (art. 28 GDPR) o istruzioni equivalenti del titolare ☐ accesso solo a dati sintetici
- Limitazione di responsabilità concordata (se prevista dal contratto):
- Segnalazione di vulnerabilità: tempi e destinatari della comunicazione dei finding, e divieto di divulgazione a terzi senza consenso del proprietario.

## 9. Conferma
Firma/e-mail di conferma del proprietario e data:
