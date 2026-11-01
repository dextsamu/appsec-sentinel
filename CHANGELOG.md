# Changelog

Formato basato su [Keep a Changelog](https://keepachangelog.com/it-IT/1.1.0/); versioni secondo [SemVer](https://semver.org/lang/it/).

## [Non rilasciato]
### Corretto
- `secret_triage.py`: in un valore lungo e casuale (≥ 20 caratteri, entropia ≥ 4,2) le parole corte come «dev», «tuo» o «xyz» non lo declassano più a segnaposto o password debole: comparivano per caso circa una volta su cento su 40 caratteri, declassando un segreto vero (e facendo fallire a caso il banco dei segreti in CI).

## [1.2.2] - 2026-11-01
### Aggiunto
- Due categorie in `punti-pericolosi.csv`: **route del client** (pagine riservate o protette solo da un guard nel browser, nei file di routing del frontend) e **dati di seed e credenziali** (file YAML/JSON di dati iniziali con password, segreti, domande o risposte di sicurezza). Motivo: nel giro std6 su Juice Shop (13/32) le mancate erano quasi tutte nelle route del frontend e nel file delle domande di sicurezza, che nessuna categoria apriva.
- Criteri per «non difetto» su queste due categorie (`references/commands.md`): «dati di demo» non basta se i dati sono caricati all'avvio; per le route del client serve il controllo lato server. Motivo: nel giro std7 (12/32, entro la variabilità del 13/32 di std6) l'agente le ha chiuse come «dati di demo» e «solo navigazione lato client».

## [1.2.1] - 2026-11-01
### Misurato
- Giro `standard` su Juice Shop con istanza locale, stesso modello (Opus 4.8) e stesso prompt, PC dell'autore: skill 1.2.0 7/32 (9 finding), con il controllo sulle parole 8/32 (13), con `punti-pericolosi.csv` **13/32, 15/32 entro 15 righe (22 finding, 11 riprodotti dinamicamente, 9 alti smentiti senza respinti)**; `chiudi` 15 ok, 0 da verificare. Restano mancate soprattutto le route del frontend e le risposte nel file delle domande di sicurezza.

### Aggiunto
- **`punti-pericolosi.csv`**: il pre-passaggio scrive una riga per ogni categoria di punti pericolosi trovata (nuova categoria «URL dall'utente (SSRF)»: su Juice Shop trova esattamente `profileImageUrlUpload.ts:24`); ogni riga chiude con un finding che cita un file della categoria, con «non difetto» e un `file:riga` letto, o con «non esaminato» (solo nel `rapido`). Nello `standard` e nel `completo` le aree lasciate aperte nella checklist ora fanno **fallire** `chiudi`, e `revisione.md` è letta anche in `report/`. Motivo: il giro successivo (std5, 8/32) ha aggirato il controllo sulle parole scrivendo «annotato» e «superfici note con la verifica mancante» invece di «non promosso».
- **Problemi annotati e non diventati finding**: `chiudi` segnala le aree della checklist il cui motivo dice «non promosso», «da approfondire», «non ridimostrato» o simili; si chiude facendone un finding (anche «ipotesi da validare») o motivando in `revisione.md` sotto «## Risposte». Nello `standard` segnala anche quando la modalità non aggiunge nessun finding al rapido; la procedura ha un passo di **approfondimento** (4b). Motivo: un giro `standard` con la 1.2.0 su Juice Shop (Opus 4.8, PC dell'autore) ha chiuso pulito, con 5 smentite su 5, ma con gli stessi 9 finding del rapido e 7/32 vulnerabilità: recupero password, SSRF, XSS nel client e chatbot erano annotati nella checklist e mai riportati.

## [1.2.0] - 2026-11-01
### Aggiunto (generalizzazione, altri linguaggi, tempi, report)
- **Smentita indipendente**: un «secondo passaggio» nella stessa conversazione non vale più come verificatore; serve una sessione nuova, un altro agente o una persona (`verify_findings.py` lo segnala). Emerso da un giro reale in cui l'agente aveva smentito da solo i propri finding.
- **Base del rapido nello `standard`/`completo`**: a fine rapido la procedura copia i finding in `findings/rapido.json`; `chiudi` fallisce se manca e segnala i finding spariti senza una smentita che li respinga. Motivo: anche con la procedura fissa un giro `standard` su Juice Shop aveva 10 finding (16/32 vulnerabilità nei file citati) contro 26–28 del `rapido` (22/32): le prove dinamiche restringevano l'esame.
- `verify_findings.py`: i finding confermati o riprodotti devono citare almeno una riga (`file:riga`); gli artefatti dell'audit si citano come `audit:<percorso>` e non vengono cercati nel repository (il giro aveva tolto i numeri di riga per far sparire i rilievi sugli artefatti). Procedura: niente prove distruttive, token solo in variabili d'ambiente.
- **Procedure fisse per `standard` e `completo`** (`references/commands.md`): ordine dei passi, la checklist del `rapido` come base di ogni modalità, prove dinamiche solo dopo, smentita con un sottoagente nuovo. `chiudi` controlla i deliverable della modalità letta da `meta.json` (sintesi, threat model, matrice dei controlli; per `completo` anche inventario, rapporto tecnico, piano e matrice di copertura) e, se il mandato è dinamico, che almeno un test sia registrato nella matrice endpoint. Motivo: due giri reali (31/10/2026) avevano scelto la procedura da soli; il giro `standard` su Juice Shop con istanza locale ha riprodotto 9 finding su 11 ma ne ha trovati meno del `rapido` (8/32 contro 18–20/32) e non aveva il threat model.
- `dynamic_authz_check.py --update-matrix` abbina `/api/orders/1` a `/api/orders/:id` (anche `{id}`, `<id>`, `[id]`) e conserva gli esiti di più identità sulla stessa route.
- `verify_findings.py`: i riferimenti `percorso@commit` o «(storia Git)» non sono segnalati come inesistenti; in `revisione.md` la sezione `## Risposte` non viene più sovrascritta.
- `coverage_summary.py`: «si (L3 valutato)» conta come applicabile.
- **Smentita nel `doppio`**: nuovo `scripts/apply_refutations.py`, che applica gli esiti scritti da un verificatore indipendente in `smentite/esiti.json` (resiste; declassato con severità/stato più bassi e confidenza adeguata; respinto spostato in `findings/respinti.json`), con controlli che rifiutano esiti incoerenti senza scrivere nulla. Nel `doppio` la smentita si fa sull'unione con un terzo sottoagente che vede solo brief e codice: nei 12 giri reali nessun giro poteva farla (un sottoagente non ne avvia un altro). Prova: sul banco Django, con 2 finding falsi aggiunti all'unione, il verificatore li ha respinti entrambi e nessuno vero; su Juice Shop 16 resistono, 4 declassati (codice attivo solo con certe configurazioni), 0 respinti.
- `validate_findings`: «secret = chiave pubblica» non è più scambiato per una password in chiaro (parola seguita da altro testo).
- **Banco indipendente su OWASP Juice Shop** (`tests/bench-juice/juice_bench.py`): la verità non è scritta da noi ma ricavata dai marcatori che Juice Shop mette sulle righe vulnerabili delle sue sfide (32 vulnerabilità con file e riga, commit fissato). `prepare` toglie marcatori, soluzioni, suggerimenti, test e nomi delle sfide (i numeri di riga restano); `score` conta una vulnerabilità trovata se un finding cita lo stesso file e una riga entro 3. Misura la generalizzazione, che i banchi scritti da noi non possono misurare.
- **Banchi PHP/Laravel e Python/Django** (`tests/bench-php`, 13 difetti e 5 esche; `tests/bench-django`, 10 difetti e 5 esche), con lo stesso `score_bench.py`; nei test: preparazione, nessun commento rivelatore, route senza autenticazione attese, punteggio.
- `inventory_routes.py`: **Laravel** legge i gruppi `Route::middleware(...)->prefix(...)->group(...)` e applica middleware e prefisso alle route interne; **Django** legge l'autenticazione sulla view (decoratori, mixin, `permission_classes`, `DEFAULT_PERMISSION_CLASSES` di DRF solo per le view DRF) e non più sul file `urls.py`, e risolve i prefissi di `include()`. Prima, sul banco Django, tutte le 8 route risultavano senza autenticazione (vere: 2) e il campione R03 era vuoto.
- `run_scanners.py`: `composer audit` per i `composer.lock`; comando preparato per yarn, pnpm, poetry, Bundler e Go.
- **Tempi**: `init_audit` registra l'inizio in `registro-tool/tempi.json`; `check_delivery` stampa e registra la durata fino alla chiusura, separando il pre-passaggio dal resto; `merge_audits` riporta la durata di ogni giro.
- **Report PDF per il cliente** anche per `doppio` e per gdpr-sentinel: sezioni «Gap privacy» (da `gaps.csv`) e «Due giri indipendenti» (da `unione-giri.json`: cause distinte, viste da entrambi, viste da un solo giro).

### Aggiunto (dopo 12 giri reali di sottoagenti, 31/10/2026: risultati in docs/BENCHMARK.md)
- `prepass` scrive `registro-tool/punti-pericolosi.txt` e pre-compila R11: HTML senza escape anche nel client, esecuzione di codice, deserializzazione, parser XML, funzioni AI, recupero password. R04 chiede del recupero con domande di sicurezza; R11 dei punti client e della prompt injection. Su Juice Shop: da 15 a 18–20 vulnerabilità su 32 per giro.
- `juice_bench.py score` stampa anche la misura «vicino» (stesso file, entro 15 righe).
- `merge_audits` stampa anche la quota di finding con un corrispondente in un altro giro (stima alta, utile quando i giri dividono le cause in modo diverso).
- `check_delivery`: le parole vietate non si cercano nelle uscite degli script (copiano estratti del repository).

### Corretto
- `score_bench.py` sostituisce tutti i segnaposto `__NOME__` dei modelli con valori casuali (prima solo `__SESSION_SECRET__`).

## [1.1.0] - 2026-10-30
### Aggiunto (variabilità e falsi positivi, 31/10/2026)
- **Variabilità fra giri.** Due giri `rapido` reali sullo stesso repo avevano in comune 2 finding su 10, entrambi prodotti da script; il resto dipendeva dalle aree guardate (in comune 2 aree su 14). Ora: `assets/rapido-checklist.csv` con 14 aree (R01–R14) che coprono tutti i 12 finding dei due giri, copiata da `init_audit.py`; `scripts/prepass.py` esegue gli strumenti in ordine fisso (output identico fra due esecuzioni) e pre-compila le aree automatiche, compresa R02 con l'elenco delle route di servizio (internal, debug, seed, demo…); `check_delivery` fallisce se un'area è vuota e segnala esiti senza riferimenti o motivo; `coverage_summary` riporta lo stato della checklist; `scripts/merge_audits.py` unisce più giri per causa e misura l'accordo (sui due giri reali: 10 cause distinte, 2 in comune, accordo 20%).
- **Falsi positivi sui segreti nella storia.** `scripts/secret_triage.py`: punteggio su due assi (valore: formato del fornitore, entropia, segnaposto, password debole; file: credenziali note, configurazione reale, esempio/documentazione/test/seed) più host locale o remoto e ripetizione del valore; impronta corta per i duplicati, valore mai riportato; dipendenze vendorizzate escluse. Misure in `docs/BENCHMARK.md` (banco sintetico, leaky-repo, NodeGoat, il gestionale B). Banco sintetico con verità nota in `tests/benchmark/secrets_bench.py`, eseguito anche nei test.

### Aggiunto (condiviso con gdpr-sentinel)
- `merge_audits.py` unisce anche cartelle di gdpr-sentinel (`gaps.csv`), scrivendo un `gaps.csv` unito con la provenienza; `check_delivery` passa `--gaps` a `check_matrix`.

### Aggiunto (primo giro reale sul banco: 16/16 difetti in entrambi i giri)
- `verify_findings.py --repo` segnala i finding sui segreti che citano righe con soli segnaposto (anche i `.env` citati senza riga); `check_delivery --app` gli passa il repository. Intercetta i tre falsi allarmi reali (U2, A, B), nessuno sui segreti veri.
- Banco corretto dopo il primo giro: le esche si confrontano solo con titolo e osservato; il seed eseguito dal README nel deploy è un difetto vero (B16), non un'esca.

### Aggiunto (banco pubblico e ottimizzazione)
- `tests/bench-app/`: banco di prova pubblico con 15 difetti noti e 6 esche (fra cui il `.env` con soli segnaposto che aveva ingannato un giro reale) e `score_bench.py` (richiamo, difetti alti, falsi allarmi, accordo fra giri). Misura la skill senza codice privato.
- Comando `doppio`/`double`: due giri `rapido` indipendenti con sottoagenti e la loro unione.
- `SKILL.md` più leggero (−16% di parole caricate a ogni uso): il dettaglio dei comandi è in `references/commands.md`.

### Corretto
- `merge_audits.py` e `score_bench.py` toglievano tutti i punti iniziali dai percorsi (`.github/…` diventava `github/…`, `.env.staging` diventava `env.staging`): ora tolgono solo il prefisso `./`.

### Aggiunto (dopo i giri U1 e U2 sul gestionale B: 5/5 difetti noti trovati da entrambi, accordo 60%)
- `prepass` scrive `registro-tool/route-senza-auth.csv` e `check_delivery` segnala le route senza auth non classificate; R01 chiede se gli header interni del middleware (tenant, ruolo, flag admin) sono ripuliti quando arrivano dal client.
- La smentita dei finding sui segreti chiede se il valore è un segnaposto (un falso positivo «alta» era passato).
- «Nessuna rete verso il sito» non vieta `npm audit`: detto in SKILL, `prepass` e R07; `prepass --no-network` avvisa (due giri avevano saltato le dipendenze).
- `check_delivery` segnala `meta.json` con il testo del modello.

### Aggiunto (dopo i giri G3 e G4: accordo 64%, prima 43% e 20%)
- R03 chiede di verificare nella matrice quali ruoli hanno il permesso usato dal controllo; R11 chiede di cercare i redirect aperti anche nelle pagine client (callbackUrl, next, returnTo). `merge_audits` spiega perché una coppia molto simile non è stata unita (es. un finding che ne raggruppa due).

### Aggiunto (dopo i giri G1 e G2)
- `prepass`: campione prioritario fisso per R03 (`registro-tool/campione-r03.txt`), così ogni giro legge per prime le stesse route con identificativo; domande esplicite in R03 (mass assignment sui propri privilegi), R04 (secondo fattore a ogni login, login alternativi, sessioni degli utenti disattivati) e R08 (riga esatta di ogni mount). Motivo: G1 e G2 (accordo 43%, prima 20%) differivano per profondità del campione, non più per copertura.

### Corretto
- `merge_audits.py`: la prima versione univa a catena finding diversi che citavano lo stesso file (15 unioni sbagliate su 24 nei tre giri reali). Ora pesa le citazioni `file:riga` identiche e il testo completo, non mette mai due finding dello stesso giro nello stesso gruppo e non unisce a catena; sui tre giri reali: 0 unioni sbagliate, 0 mancate. Test di regressione con un caso a catena.
- `redact_check.py`: «pacchetto@versione» (es. `prisma@7.10.1`, negli output di npm audit) non è più segnalato come email; esclusi anche i sottodomini di `example.*`.
- Secondo giro reale: l'analisi delle dipendenze e dei segreti nella storia Git è stata saltata («node_modules assente», «gitleaks non disponibile»), ma `npm audit --package-lock-only` non ha bisogno di `node_modules`. Aggiunto `scripts/run_scanners.py` (`deps` e `history`): niente installazioni, ripiego dichiarato (`sca-stato.json` con comando preparato), clone superficiale segnalato, valori dei segreti mai riportati; e un controllo di `check_delivery` che segna «da verificare» un registro di copertura senza le aree dipendenze e segreti, per ridurre la variabilità fra giri.
- Trovato in un audit reale su un'app di prova: senza il modulo `jsonschema` la validazione dei finding usava un controllo minimo che non vedeva enum e tipi annidati sbagliati (`prova.tipo`, `prova.test_eseguito`, `smentita.esito`, `intervento.priorita`, `smentita.tentativi`), e `check_delivery` dava comunque «ok». Ora il controllo minimo verifica enum e tipi annidati come lo schema, e `check_delivery` segna «da verificare» se lo schema completo non è stato eseguito.

### Aggiunto
- Copertura tecnica: `scripts/import_openapi.py` (OpenAPI/Swagger 2.0 e 3.x, JSON e YAML → matrice endpoint; con `--repo` confronto spec↔codice), `scripts/iac_check.py` (14 regole su Dockerfile, compose, Kubernetes, Terraform e GitHub Actions, uscita SARIF), e in `import_scanner.py` i formati `--semgrep`, `--trivy` e `--zap`. Comandi `openapi` e `iac`. Tutto resta «ipotesi da validare»; di ZAP non si importano `evidence` e `attack`, che possono contenere payload o dati reali. Limiti: regole a pattern (non parsing completo di YAML/HCL), confronto spec↔codice dipendente dall'inventario euristico.
- `tests/benchmark/` e `docs/BENCHMARK.md`: misura dell'inventario delle route su Juice Shop e NodeGoat contro un elenco curato di endpoint noti. Ha mostrato che l'inventario segnalava quasi tutto come «senza auth evidente» (Juice Shop 238 su 239, tutti i 5 endpoint autenticati noti; NodeGoat 11 su 11): ora riconosce l'auth dichiarata a monte (`app.use`, `app.METHOD(percorso, auth)`), famiglie di nomi di middleware (`isAuthorized`, `isLoggedIn`…), elenca i montaggi `app.use` ed esclude cartelle di test. Limite dichiarato: le correzioni sono state fatte su queste stesse app, quindi i numeri «dopo» non sono indipendenti.
- `tests/scenarios/`: kit per collaudare il comportamento dell'agente (non solo gli script): `score_scenarios.py` con 5 controlli di sicurezza e 6 di qualità, quattro giri (statico, istruzione ostile nel codice, inglese, segreto in chat), app finta con istruzione ostile creata da `prepare`. Provato su audit sintetici buoni e cattivi; sugli audit di Codex e Antigravity ha dato esiti coerenti con quanto avevamo visto a mano. Limite: controlli meccanici su un'app finta.
- `scripts/canonicalize.py` (comando `normalizza`/`canonicalize`): riporta ai valori canonici italiani stati, severità, confidenza ed esiti scritti in inglese, senza toccare il testo libero; `chiudi` lo segnala. Alias inglesi anche per gli argomenti di `area` (`secrets`, `dependencies`). Limite dichiarato: i messaggi stampati dagli script e i nomi dei campi dei file macchina restano in italiano.
- Skill utilizzabile in inglese: alias inglesi di tutti i comandi (`quick`, `refute`, `close`…), sezione «Lingua / Language» (risposte, finding e report nella lingua dell'utente; valori canonici dei file macchina invariati), descrizione bilingue per l'attivazione da richieste in inglese, `docs/COMMAND-CARD.md`. Il PDF con `--lang en` mostra ora anche stati e confidenza in inglese. Limite dichiarato: istruzioni, reference e template restano scritti in italiano e l'agente li traduce al volo; i messaggi degli script restano in italiano.
- `scripts/i18n.py` e `--lang en`: messaggi fissi in inglese per `check_delivery`, `validate_findings`, `coverage_summary`, `verify_findings`, `init_audit`, `redact_check` (stessi codici di uscita, nessun cambio ai valori canonici). Modelli in inglese: `assets/engagement-rules-template.en.md`, `assets/finding-template.en.md`. Limiti: traduzione di frasi fisse, non del testo libero; gli altri script restano in italiano.
- Sito in inglese (`site/index.en.html`) con selettore IT/EN nel menu; la pagina dichiara che istruzioni, comandi e report delle skill restano in italiano.
- `README.en.md`: guida breve in inglese (la skill resta in italiano, dichiarato).
- Esempio inventato `examples/findings.example.json` con il campo `smentita`; struttura del repository verificata con `npx skills add <percorso> --list`.
- Collaudo end-to-end di `dynamic_authz_check.py` su un'istanza locale reale (`tests/lab/lab_app.py`, solo 127.0.0.1): trova i 2 difetti di autorizzazione noti (BOLA, BFLA) e nessun falso positivo sui 4 comportamenti corretti. Limite dichiarato: è un laboratorio scritto da noi, con un solo tipo di difetto per classe; non è un benchmark su app pubbliche (Juice Shop, DVWA non provate).
- `inventory_routes.py` riconosce anche Laravel, Spring, ASP.NET, Rails e Go (fixture `tests/fixtures/multi-fw`, 6 nuovi test). Limite dichiarato: l'auth è cercata vicino alla singola route; middleware di gruppo e filtri globali non sono visibili.
- `scripts/check_delivery.py` e comando `chiudi`: controllo di consegna in un solo passo (schema e revisore, smentite dei finding alti, matrice GDPR, redazione compresi i valori dei segreti dell'app con `--app`, parole vietate, copertura). Provato sugli audit prodotti da Codex e Antigravity.
- `docs/ALTRI-AGENTI.md`: dove installare la skill su altri agenti (Antigravity, Codex), esiti della prova su Windows (un giro, modalità rapido, app finta) e controlli da fare.
- Smentita dei finding alti: campo `smentita` nello schema, brief per il verificatore (`verify_findings.py --brief-dir`), controllo che un finding alto o critico abbia l'esito, riga «Smentita» nel PDF, `references/refutation-pass.md`.
- Copertura cumulativa tra audit: `scripts/coverage_carry.py` (`stamp` e `carry`) riporta le voci con contenuto invariato, segna «stantie» quelle cambiate e elenca i file mai coperti; `coverage_summary.py` ne mostra i conteggi.
- Sito di presentazione delle due skill in `site/` (pagina statica, tema chiaro e scuro, mobile) e workflow `pages.yml` a pubblicazione manuale.
- `docs/SCHEDA-COMANDI.md`: scheda dei comandi in una pagina, con il flusso in sei righe, richiamata dall'inizio del README e dalla sezione Comandi.
- Strumenti automatici: `inventory_routes.py`, `dynamic_authz_check.py` (solo locale o host autorizzato), `import_scanner.py`, `verify_findings.py`, `redact_check.py`, `compare_audits.py`, `export_findings.py` (CSV, SARIF, Markdown).
- PDF: opzioni `--sintetico`, `--lang en`, `--previous` (confronto con audit precedente), `--nis2` (mappatura indicativa art. 21).
- `references/automation.md`, `references/review-pass.md`, app di prova con difetti noti in `tests/` e `tests/run_checks.py` eseguito in CI.
- Report PDF: sezione «Matrici di copertura» con le tabelle complete (inventario, endpoint, controlli ASVS/NIST/ACN), non solo i conteggi.
- Report PDF con grafica rinnovata, coerente con quella dei repository: copertina a gradiente con scudo, indice con pagine, intestazione e «Pagina X di Y», ciambella delle severità, riquadri di copertura, etichette colorate e schede finding. Tema teal per la sicurezza, ambra per la privacy.
- Rimandi espliciti alla skill gemella `gdpr-sentinel`: riquadro in testa al README, sezione «Con gdpr-sentinel» con schema, regole di consegna in `SKILL.md`.
- Comandi `documentale` (audit documentale: documenti ↔ codice, documenti attesi, matrice) e `pdf`; reference `documentary-audit.md`, template `documentary-matrix.csv` e `meta-template.json`, script `build_report_pdf.py` (report PDF aziendale, richiede `reportlab`), esempio anonimizzato con PDF. Il PDF supporta anche tabella delle domande per destinatario e piano da `meta.json` (report solo privacy).
- Comandi rapidi (`rapido`, `standard`, `completo`, `area`, `retest`, `piano`, `report`, `stato`, `privacy`) definiti in `SKILL.md` e descritti nel README.
### Modificato
- Dopo le prove su Codex e Antigravity: nessun valore di segreto in nessun output (chat compresa); `verify_findings.py` nella chiusura; la smentita vale solo se fatta da un verificatore diverso (altrimenti `non eseguita`); smentita GDPR nella forma `esito | verificatore | tentativi`; CVSS da sola lettura statica solo dichiarando il limite; nota per Windows sul comando `python`; euristica sull'impatto «reale» meno severa.
- Dopo il primo collaudo su un caso reale: le righe d'esempio dei template iniziano con `ESEMPIO` e `coverage_summary.py` le ignora; `esaminato` ammette `parziale`.
- Istruzioni: confronto tra percorsi pubblici del middleware e route, route di debug/seed/demo, risposte con più dati del necessario, limiti delle euristiche (dichiarare quante route sono state lette), raggiungibilità degli advisory, porte pubblicate, file `.env` «example» con valori reali.
- Esempio anonimizzato di collaudo (`examples/collaudo-rapido/`) e guida `docs/ESEMPI-DI-UTILIZZO.md`.
- Template dei finding: valori ammessi per `prova.tipo`, `stato` e `privacy`.

## [1.0.0] - 2026-10-29
### Aggiunto
- Assessment di application/cloud security con gate di autorizzazione, tre modalità (`rapido`, `standard`, `completo`), reference, template di finding e regole di ingaggio, schema JSON dei finding, matrici di copertura e script (`init_audit.py`, `validate_findings.py`, `coverage_summary.py`).
- Profilo dei controlli minimi per classe di rischio (`references/minimum-controls-profile.md` e `assets/minimum-controls-profile.csv`): 14 temi con soglie Basso/Medio/Alto, fonti AgID/ACN/NIST e provenienza di ogni soglia.
- Finding di esempio inventato in `examples/`, validato automaticamente.
- Controlli automatici su GitHub Actions e rilascio automatico del pacchetto `.skill` alla creazione di un tag `v*`.
- Modelli per issue e pull request, codice di condotta, `CITATION.cff`, immagine di anteprima.
- Licenza Apache-2.0, `NOTICE`, `THIRD_PARTY.md`, `SECURITY.md`, intestazioni SPDX negli script.
- Profilo legale nelle regole di ingaggio (titolo ad autorizzare, NDA, nomina art. 28 GDPR).
