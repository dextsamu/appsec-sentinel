# Strumenti automatici

Gli script accelerano il lavoro ripetitivo; **non decidono**. Ogni output ha uno stato: l'inventario è euristico, gli scanner producono ipotesi, i test dinamici provano solo ciò che hanno eseguito.

## Flusso consigliato
1. `init_audit.py` crea la cartella di audit (riservata, fuori da Git).
2. `inventory_routes.py <repo> --out endpoint-matrix.csv --summary`: elenco di route e metodi, con le route **senza autenticazione evidente** in testa. In Express il controllo è cercato sulla riga della singola route; un'auth applicata a monte con `app.use()` non è visibile e va verificata a mano.
3. Pipeline esistenti dell'utente (npm audit, semgrep, gitleaks, osv-scanner, trivy): importarne i risultati con `import_scanner.py … --out candidati.json [--merge findings.json]`. Sono **ipotesi**: severità mai oltre «media», nessun valore di segreto riportato.
4. Test dinamici, solo dopo la conferma di Fase 0: `dynamic_authz_check.py --config authz-config.json --tests authz-tests.csv --update-matrix endpoint-matrix.csv`. Ammette solo localhost, `*.localhost`, `*.test` salvo `--allow-host` per un host autorizzato per iscritto; solo GET/HEAD/OPTIONS salvo `--allow-state-changing` su dati sintetici; tetto di richieste; nessun corpo salvato; le credenziali si passano con `env:NOME`. Un test non eseguito resta «no» nella matrice.
5. `validate_findings.py`, poi `verify_findings.py --repo <codice>`: controlla riferimenti a file e righe, severità alte con stato debole, duplicati, impatti dichiarati senza test. Le domande del revisore sono in `review-pass.md`.
5b. Per i finding alti: `verify_findings.py … --brief-dir smentite/` e il passaggio di smentita in `refutation-pass.md`. Un finding alto senza esito nel campo `smentita` resta un rilievo.
5c. Prima di consegnare: `check_delivery.py <cartella-audit> --app <repo>`: un solo passo che unisce i controlli meccanici. Zero «falliti»; i «da verificare» si risolvono o si dichiarano.
6. `coverage_summary.py` per i denominatori reali.
7. `redact_check.py <cartella>` e sul PDF finale: segreti (esce con 1) e possibili dati personali. Un esito pulito non garantisce nulla: rileggi sempre il documento.
8. `build_report_pdf.py`: completo, `--sintetico` per la direzione, `--lang en`, `--previous` per il retest, `--nis2` per la mappatura indicativa.
8b. Audit ripetuti: a fine run `coverage_carry.py stamp <audit> --repo <codice>`; al run successivo `coverage_carry.py carry <vecchio> <nuovo> --repo <codice>` riporta le voci con contenuto invariato, segna «stantie» quelle cambiate e elenca i file mai coperti. Riportata non vuol dire sicura: i finding si rivalidano.
9. Per i retest: `compare_audits.py vecchio.json nuovo.json`. «Risolto» vuol dire assente, non verificato.
10. `export_findings.py` per CSV, SARIF e Markdown per le issue. Gli export sono riservati come i file di audit.

**Windows.** Gli esempi usano `python3`. Su Windows usa `python` o `py`; se l'alias del Microsoft Store non parte, installa Python 3 oppure usa l'interprete già disponibile nel tuo ambiente. Gli script usano solo la libreria standard (il PDF richiede `reportlab`).

## Collaudo degli script
`python3 tests/run_checks.py` prova gli script contro `tests/fixtures/vuln-app`, un'app finta con difetti noti elencati in `expected.json`. Se aggiungi o cambi uno script, aggiorna anche il test.
