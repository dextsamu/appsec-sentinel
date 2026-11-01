# Esempio: collaudo `rapido` su un'applicazione web (anonimizzato)

Caso ricavato da un collaudo reale (sette finding in tutto; qui ne sono riportati cinque): applicazione web Next.js con database PostgreSQL, quattro ruoli, deploy con Docker. Modalità `rapido`, **sola analisi statica** sul codice sorgente, proprietario e sviluppatore coincidenti. Nomi, organizzazioni, indirizzi e identificatori sono stati sostituiti. I finding sono nel formato dello schema e validati da `scripts/validate_findings.py`.

<img src="../../docs/img/caso-reale.svg" alt="Cosa emerge in un collaudo rapido: 2 finding alti, 3 medi, copertura dichiarata" width="60%">

Scheda quadrata pronta per i social: [`docs/img/caso-reale.png`](../../docs/img/caso-reale.png).

## Come si è svolto
1. **Richiesta dell'utente**: «Fai un assessment di sicurezza di questo repository, solo analisi statica.»
2. **Gate di autorizzazione**: la skill ha chiesto conferma di proprietà, tipo di attività (solo statica) e modalità. Risposte: «Sì, tuo, solo analisi statica» e «rapido». Sono state scritte nel file delle regole di ingaggio.
3. **Cartella di audit** creata con `scripts/init_audit.py`, fuori dal repository.
4. **Superficie e segreti**: file `.env*` tracciati, classificati per forma dei valori (segnaposto / vuoto / possibile reale) senza mai stamparli; elenco dei percorsi pubblici del middleware.
5. **Autenticazione e autorizzazione**: lettura del middleware, ricerca euristica delle route senza controlli evidenti, lettura mirata di quelle sospette.
6. **Dipendenze e container**: `npm audit` sul solo lockfile (invia nomi e versioni), Dockerfile, file Compose, CI.
7. **Validazione e consegna**: `validate_findings.py`, `coverage_summary.py`, report con copertura reale e domande aperte.

## Risultato in una tabella
| ID | Severità | Cosa |
|---|---|---|
| APP-001 | media | File di configurazione «example» con valori dall'aspetto reale, tracciato in Git |
| APP-002 | alta | Endpoint di seed demo esente da autenticazione, crea utenti con password fissa |
| APP-003 | media | Route di debug e seed senza controllo di ruolo, mutazioni via GET |
| APP-004 | media | Accettazione preventivo senza controllo di proprietà, password temporanea nella risposta |
| APP-005 | alta | Framework e libreria di autenticazione con advisory noti, inclusi bypass del middleware |

Tutti con stato `confermato da codice o configurazione`: nessun test dinamico era autorizzato, e la skill non lo dichiara mai come `riprodotto`.

## Copertura dichiarata (esempio di denominatori reali)
- Route API: **309** file; letti circa **14**; oltre **280 non letti** → controlli di ruolo e tenant «ignoti».
- Endpoint × identità: 9 censiti, **0** con test eseguito.
- Matrice dei controlli ASVS/NIST/ACN: non compilata in modalità `rapido` (dichiarato).
- Non esaminati: cronologia Git (clone shallow), firewall e hosting, build di produzione.

## Il report PDF
[`report-esempio.pdf`](report-esempio.pdf) è generato con `python3 scripts/build_report_pdf.py examples/collaudo-rapido`. Include copertina, sintesi, finding, audit documentale (8 voci), copertura e piano.

## Cosa mostra l'esempio
- Un finding «alto» può nascere dal confronto fra **elenco dei percorsi pubblici del middleware** e route realmente presenti (APP-002, APP-004).
- L'euristica non è una lettura: va dichiarato quante route sono state lette davvero.
- Un advisory critico non è un finding dimostrato: la raggiungibilità resta da valutare (APP-005).
- I valori dei segreti non compaiono mai: solo posizione, tipo e forma.

## Domande aperte (estratto)
- Le route `internal/*` e `debug/*` sono presenti nella build di produzione? Esistono account demo in produzione?
- I valori del file di configurazione di staging sono quelli in uso?
- Quali advisory del framework sono raggiungibili con la configurazione reale (immagini, hosting)?
