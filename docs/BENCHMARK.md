# Benchmark su app vulnerabili pubbliche

Cosa misura e cosa no, con i numeri veri. Il codice è in `tests/benchmark/` (`run_benchmark.py` più un elenco curato per app).

## Cosa è stato misurato
Solo l'**inventario delle route** (`inventory_routes.py`): quanti endpoint noti trova e se segnala correttamente quelli senza autenticazione evidente. Non misura la qualità di un audit completo, né la ricerca di vulnerabilità.

Gli elenchi di endpoint noti sono **curati da noi** (non sono dataset ufficiali) e piccoli: sono un termometro, non una certificazione.

## Risultati (commit di Juice Shop 717f5ef, NodeGoat all'ultimo commit del 30/10/2026)
| App | Versione dello script | Route in inventario | Segnalate «senza auth» | Scoperta noti | Richiamo senza-auth | Falsi allarmi su autenticati |
|---|---|---|---|---|---|---|
| Juice Shop | prima (1.1.0 di stamattina) | 239 | 238 | 14/15 | 9/10 | **5/5** |
| Juice Shop | dopo | 125 | 88 | 15/15 | 10/10 | 0/5 |
| NodeGoat | prima | 21 | 21 | 17/17 | 6/6 | **11/11** |
| NodeGoat | dopo | 21 | 9 | 17/17 | 6/6 | 0/11 |

## Cosa ha mostrato il benchmark
Prima del benchmark l'inventario segnalava **quasi tutto** come «senza auth evidente»: per tre cause, che ora sono corrette.
1. Il controllo di accesso dichiarato **a monte** (`app.use('/api/basket', security.isAuthorized())`) non era visto: ora una route sotto un prefisso con auth è «autenticato a monte».
2. Mancavano i nomi comuni dei middleware (`isAuthorized`, `isLoggedIn`, `ensureAuthenticated`, `requireUser`…): ora sono riconosciuti per famiglie di nomi.
3. `app.use('/ftp', ...)` non era elencato come route, e i file di test e gli snippet didattici facevano rumore: ora i montaggi `app.use` sono elencati e le cartelle `test`, `tests`, `spec`, `e2e`, `cypress`, `codefixes` sono escluse.

## Limiti da leggere prima dei numeri
- **Non sono test indipendenti.** Le correzioni sono state fatte guardando proprio questi risultati: i numeri «dopo» misurano un codice adattato a queste due app. Un terzo test su un'app mai vista è il solo che dica quanto regge.
- **Il rumore resta alto.** Su Juice Shop 88 route su 125 sono segnalate «senza auth evidente»: sono candidati da verificare, non finding. La precisione sull'elenco completo non è misurabile senza una verità completa.
- **L'auth è cercata sulla riga della route o su un prefisso.** Middleware globali, router montati altrove (`app.use('/admin', adminRouter)`: le route dentro il router restano con «prefisso di montaggio non risolto») e controlli dentro il gestore non si vedono.
- **Non si vede l'autorizzazione per oggetto.** `/rest/basket/:id` risulta autenticata, ma l'accesso al carrello di un altro utente (BOLA) si trova solo con il test dinamico.
- **Il richiamo sulle vulnerabilità non è misurato.** Qui si misura il riconoscimento dell'autenticazione, non la scoperta di difetti.

## Test dinamico: non eseguito
Il passaggio `dynamic_authz_check.py` contro un'istanza di Juice Shop in esecuzione non è stato fatto: l'installazione del frontend è fallita qui (`npm install` di npm: «Cannot read properties of null (reading 'edgesOut')»). Il test dinamico è provato solo sull'app di laboratorio `tests/lab/lab_app.py` (2 differenze volute trovate, 0 falsi positivi su 4). Non va quindi dichiarato come misurato su un'app pubblica. Per un'affermazione onesta serve inoltre una terza app mai usata per tarare l'inventario.

## Due giri reali dell'agente su uno stesso repo di produzione (31/10/2026)
Stessa modalità `rapido`, solo analisi statica, su un repo reale di proprietà dell'autore (Next.js, 432 route). Non sono un confronto fra strumenti: servono a vedere cosa cambia da un giro all'altro.
- **Giro 1** (skill con il validatore minimo): 7 finding, nessuno alto. `check_delivery` dava 9 ok, ma lo schema completo trovava 21 errori in `findings.json` (enum e tipi annidati). Difetto corretto: ora anche il controllo minimo li rifiuta e il gate dice «da verificare» se lo schema completo non gira.
- **Giro 2** (skill corretta): 5 finding, nessuno alto; valori canonici, `test_eseguito` booleano, smentita «non eseguita» dichiarata su tutti, schema completo passato. Ha usato `inventario` (432 route, 18 senza auth evidente, tutte pubbliche per scelta), `openapi` (33 operazioni documentate) e `iac` (13 indizi); l'analisi delle dipendenze è dichiarata non eseguita (nessuno scanner offline), con il comando preparato.
- **Cosa mostrano insieme:** fra i due giri i finding coincidono solo in minima parte (azioni GitHub non fissate e socket Docker nel compose residuo). Un giro `rapido` non è riproducibile né esaustivo: un secondo giro ha trovato problemi che il primo non aveva visto, e viceversa. Il report non va letto come «cosa c'è» ma come «cosa è emerso in quel giro». Per questo la copertura e i limiti dichiarati contano più dell'elenco.
- **Limiti:** due giri, un solo repo, nessuna verità nota da confrontare; i finding non sono stati verificati dinamicamente.

## Segreti nella storia Git: falsi positivi e richiamo (31/10/2026)
`run_scanners.py history` senza gitleaks usa `secret_triage.py`. Misure prima e dopo la classificazione («in cima» = severità media, da guardare per primi):

| Banco | Prima | Dopo | Note |
|---|---|---|---|
| Sintetico (`tests/benchmark/secrets_bench.py`, verità nota, valori casuali a ogni esecuzione) | 6/7 veri in cima, 4/14 esche in cima | 11/11 veri in cima, 0/21 esche in cima (stabile su 8 esecuzioni) | Scritto da noi: le esche sono quelle che conosciamo |
| [leaky-repo](https://github.com/Plazmaz/leaky-repo) (benchmark pubblico, 42 file con segreti) | 21/42 file trovati, 12 in evidenza | 40/42 trovati, tutti in cima o «da guardare» | gitleaks con la configurazione del benchmark: 40/44. Usato anche per tarare: il «dopo» non è indipendente |
| NodeGoat (499 commit, mai usato per tarare) | — | 4 in cima, tutti veri (2 chiavi private, chiave ZAP in 2 file); 11 da guardare (hash bcrypt, credenziali Mongo verso host remoto); 3.961 file di `node_modules` esclusi | Unica misura su dati mai visti; verifica a mano con valori mascherati |
| Gestionale B (dell'autore, clone superficiale) | 49 voci «media» | 6 in cima, verificate a mano: stesso segreto casuale ripetuto in script e documenti, un segreto di firma in un file di composizione | Usato anche per tarare |

Cosa ha insegnato, compresi gli errori fatti per strada:
- Un dizionario unico confondeva segnaposto (`your-secret-here`) e password deboli ma reali (`hunter2` in un file di configurazione): ora sono due cose diverse e la seconda dipende dal file.
- La regola «stesso valore in molti file = valore di sviluppo» era sbagliata per i valori casuali: un segreto vero copiato in script e documenti è il caso peggiore. Ora la ripetizione abbassa solo i valori deboli.
- Una versione intermedia ha messo in cima 30 voci sul gestionale B che sembravano segreti copiati: erano frammenti di shell (`SEGRETO=$(grep …)`) ripetuti in 11 script. Scoperto solo con la verifica a mano; ora c'è un'esca apposta nel banco sintetico.
- Su NodeGoat le chiavi di test delle librerie in `node_modules` committati finivano in cima: ora le cartelle di dipendenze sono escluse e contate.
- Limiti: euristico; passphrase con spazi non rilevate; formati non coperti (es. il file `config` IRC e `salesforce.js` di leaky-repo); con gitleaks installato la classificazione usa solo entropia, regola e percorso (il valore è redatto).

## Variabilità fra giri (31/10/2026)
I due giri reali sul repository A, uniti con `merge_audits.py` (abbinamento per contenuto): 12 finding → **10 cause distinte, 2 viste da entrambi i giri, accordo 20%**. Le due in comune sono quelle prodotte da `iac_check` (stesse righe); le altre dipendevano dalle aree guardate: giro 1 su R01, R07, R10, R12; giro 2 su R05, R08 (in comune R09 e R14 su 14 aree).
Risposta: `checklist-rapido.csv` con 14 aree che coprono tutti i 12 finding, `prepass.py` deterministico (output identico fra due esecuzioni sul gestionale B), `check_delivery` che fallisce con aree vuote, `merge_audits.py` per unire più giri.

**Primo giro con la checklist (G1, 31/10/2026).** Stesso repo, skill con `prepass` e 14 aree. Tutte le 14 aree compilate (11 esaminate, 3 parziali); 9 finding, di cui uno alto nuovo (permessi admin di Better Auth al ruolo RESPONSABILE) con smentita indipendente «resiste»; `check_delivery` 9 ok.
Unione con i due giri precedenti, verificata contro le cause etichettate a mano: **13 cause distinte; G1 ne riporta 9 (69%), i vecchi giri 7 (54%) e 5 (38%)**. Delle 10 cause dei vecchi giri G1 ne riporta 6; le altre 4 le ha **viste e giudicate** nella checklist (manuali pubblici per progetto, specifica OpenAPI come limite documentale, log del nome file, iscrizione al calendario classificata pubblica con token). Su quest'ultima G1 e il vecchio giro 1 sono in disaccordo: da verificare a mano.
Conclusione provvisoria: con la checklist la variabilità di **copertura** sparisce (nessuna area dimenticata); resta una variabilità di **giudizio** sui finding minori, ora scritta nella checklist e quindi controllabile. 
**Due giri entrambi con la checklist (G1 e G2, stesso commit, stessa versione della skill).** Unione verificata contro le cause etichettate a mano: **14 cause distinte, 6 viste da entrambi, accordo 43%** (prima della checklist: 20%). L'unione è esatta su questa coppia (6 coppie vere su 6, nessuna sbagliata), e G2 non era stato usato per tarare.
Le differenze rimaste non sono più di copertura (14 aree su 14 in entrambi) ma di tre tipi:
- **profondità del campione** — i due finding alti visti solo da G2 (modifica dei propri flag di privilegio con `PATCH /api/users/{id}`; secondo fattore mai richiesto al login) stanno in aree che G1 aveva coperto, ma con un campione diverso (2 route lette su 101 contro 10) o fermandosi prima (G1 aveva scritto «flusso del secondo fattore per-login non ricostruito»);
- **giudizio sui minori** — stessi fatti sulle azioni CI non fissate, G2 li ha giudicati sotto «informativa»;
- **un disaccordo di fatto** — sul mount del socket di fail2ban i due giri si contraddicono: va verificato a mano.
Risposta alla prima causa: `prepass` scrive un campione prioritario fisso per R03 (`registro-tool/campione-r03.txt`: prima le route non admin che modificano utenti, ruoli, permessi, password), e R03/R04/R08 contengono le domande che hanno separato i due giri (mass assignment sui propri privilegi, secondo fattore a ogni login, percorsi di login alternativi, sessioni degli utenti disattivati, riga esatta di ogni mount). Su il repository A `PATCH /api/users/{id}` risulta prima nel campione; il criterio è generico ma è stato controllato proprio su quel caso.

**Due giri con campione fisso e domande esplicite (G3 e G4, sottoagenti indipendenti, stesso commit).** Entrambi hanno trovato i tre finding alti (permessi admin di Better Auth al RESPONSABILE, `PATCH /api/users/{id}`, secondo fattore non richiesto al login), ciascuno con smentita indipendente «resiste»; entrambi hanno letto per intero il campione prioritario (25 route su 177). Unione verificata contro le cause etichettate a mano: **14 cause, 9 viste da entrambi, accordo 64%** (G1/G2: 43%; giri iniziali: 20%); unione esatta (9 coppie su 9, nessuna sbagliata) su giri mai usati per tarare. Contando come concordanza il residuo Coolify, che G3 ha incluso dentro un altro finding, l'accordo effettivo è 10 su 14 (71%).
Differenze rimaste: un giudizio (CI: stessi fatti, G4 «rischio basso, nessun finding»), una profondità (reset password e inviti: G4 si è fermato a «richiede UPDATE_USER», G3 ha verificato che quel permesso lo hanno anche RESPONSABILE e VOLONTARIO), una ricerca troppo stretta (G3 ha cercato redirect aperti solo nelle API; quello trovato da G4 è nella pagina di login) e un finding minore visto da uno solo (enumerazione tramite passkey). Correzioni: R03 chiede di verificare nella matrice quali ruoli hanno il permesso usato dal controllo; R11 chiede di guardare i redirect anche nelle pagine client.

| Coppia di giri | Strumenti | Accordo |
|---|---|---|
| Giri iniziali | solo script | 20% |
| G1 / G2 | checklist di 14 aree + prepass | 43% |
| G3 / G4 | + campione prioritario fisso e domande esplicite | 64% (71% contando un raggruppamento) |

**Secondo repository: gestionale B (U1 e U2, sottoagenti indipendenti, versione della skill di G3/G4).** Qui una parte dei difetti era già nota da un test dinamico su istanza locale e dalla scansione dei segreti (due route di servizio senza controlli adeguati, una route di debug, due segreti in file versionati): **entrambi i giri li hanno trovati tutti e 5**, senza saperne nulla.
Unione: 16 gruppi automatici, 8 in comune (accordo meccanico 50%); a mano, il segreto condiviso del cron è la stessa causa in entrambi (l'unione l'ha segnata «possibile», 0,40) → **15 cause, 9 in comune: 60%**; contando la route di debug che U2 ha raggruppato con le route di seed, 10 su 15.
Problemi emersi e corretti:
- **Dipendenze non analizzate da entrambi.** Il prompt diceva «nessuna richiesta di rete verso il sito reale» e i due giri hanno lanciato `prepass --no-network`, saltando `npm audit` (che contatta solo il registro npm). Ora SKILL, `prepass` e R07 dicono esplicitamente che non è un motivo valido, e `prepass --no-network` avvisa.
- **Un falso positivo «alta» passato dalla smentita.** U2 ha segnalato `.env.staging` versionato con «valori in forma di segreto»: verificato a mano senza stampare i valori, sono tutti segnaposto (`CHANGE…`, `COPY…`, `GENERATE…`); U1 l'aveva giudicato correttamente. Il brief di smentita ora, per i finding sui segreti, chiede esplicitamente se il valore è un segnaposto.
- **Una route pubblica non classificata.** U2 ha trovato `/api/quotes/[id]` pubblica con dati personali; U1, che aveva la stessa route nell'inventario, non l'ha citata. Ora `prepass` scrive `registro-tool/route-senza-auth.csv` da classificare riga per riga e `check_delivery` segnala le righe vuote. Solo U1 ha trovato gli header di tenant e SuperAdmin non ripuliti dal middleware: R01 ora lo chiede.
- `meta.json` lasciato con il testo del modello in entrambi i giri: ora `check_delivery` lo segnala.

| Repository | Coppia | Accordo (a mano) | Difetti noti trovati |
|---|---|---|---|
| Repository A | G3 / G4 | 64% (71% con un raggruppamento) | — (nessuna verità nota) |
| Gestionale B | U1 / U2 | 60% (67% con un raggruppamento) | 5/5 in entrambi |

**Banco pubblico (`tests/bench-app`).** Per non dipendere da codice privato: un'app finta con 15 difetti delle classi trovate nei giri reali e 6 esche, punteggio automatico. 

| Agente · versione skill | Giro | Difetti (su 16) | Alti (su 6) | Falsi allarmi (su 5) | Data |
|---|---|---|---|---|---|
| Claude Code (web) · `doppio`, versione del 31/10 | A | 16 | 6 | 1 (`.env.staging` con soli segnaposto) | 31/10/2026 |
| Claude Code (web) · `doppio`, versione del 31/10 | B | 16 | 6 | 0 | 31/10/2026 |

Accordo sui difetti noti fra A e B: 16 su 16; unione automatica: 20 cause, 18 in comune (90%).
**Come leggere questo 16/16, onestamente.** Il banco è stato costruito con le stesse classi di difetti su cui sono state scritte le domande della checklist: misura che la skill applica bene ciò che chiede, non che generalizza a difetti di tipo nuovo. Il primo giro ha anche corretto il banco: tre «falsi allarmi» erano errori dello script di punteggio (un'esca che combaciava con qualunque citazione del file; una parola cercata nella descrizione della prova invece che nell'affermazione) e un'«esca» era un difetto vero piantato per sbaglio (il README fa eseguire il seed con ADMIN a password nota nella procedura di deploy). Il banco è stato corretto di conseguenza (ora 16 difetti e 5 esche).
**Il falso allarme ricorrente** (`.env` con soli segnaposto riportato come segreto) ha colpito 2 giri reali su 4 (U2 e A) anche dopo la domanda aggiunta alla smentita, perché la smentita riguarda solo i finding alti. Ora `verify_findings.py --repo` (e `check_delivery --app`) segnala meccanicamente i finding sui segreti che citano righe con soli segnaposto: intercetta i tre casi reali (U2, A, B) e nessun segreto vero di il gestionale B.

**gdpr-sentinel sul banco privacy (`gdpr-sentinel/tests/bench-app`).** Portale soci finto con informativa e 15 difetti noti (dopo la correzione del banco), 5 esche. Due giri `doppio` indipendenti: **15/15 difetti e 6/6 prioritari in entrambi, 0 falsi allarmi**, consegna senza errori, unione 23 cause e 16 in comune (70%). Come per appsec, il banco usa le classi di difetti su cui la skill fa domande: misura l'applicazione, non la generalizzazione. Il giro ha corretto il banco: tre «falsi allarmi» erano difetti veri piantati senza volerlo.

Limiti: due repository, due giri per configurazione; l'accordo dice quanto i giri si somigliano, non quanto sono completi (nessuno conosce l'elenco vero dei difetti del repository A).

**Correzione di `merge_audits.py` emersa da questo test.** La prima versione univa a catena per un file in comune: 15 coppie sbagliate su 24 (es. l'advisory di better-auth, l'header X-Forwarded-For e i permessi di RESPONSABILE in un unico gruppo). Ora: citazioni `file:riga` identiche, insieme dei file, testo completo e CWE; mai due finding dello stesso giro nello stesso gruppo; niente catene. Sui tre giri reali: 13 gruppi, 10 coppie vere su 10 unite, 0 sbagliate. Tarato su questi stessi giri: non è una misura indipendente.

## Generalizzazione e altri linguaggi: giri reali (31/10/2026)
Giri eseguiti da sottoagenti con contesto nuovo, uno per cartella, con la sola skill e l'app (le verità restano fuori dalla cartella data all'agente). Limiti: stessa macchina delle verità (gli agenti avevano l'istruzione di non leggere altro); nessuna smentita indipendente dei finding alti, perché un sottoagente non può avviarne un altro.

| Banco | Giri | Difetti noti trovati | Falsi allarmi sulle esche | Accordo fra i giri | Durata per giro |
|---|---|---|---|---|---|
| Laravel (`bench-php`) | 2 | 13/13 e 13/13 | 0/5 | 13/13 difetti noti | 4–5 min |
| Django (`bench-django`) | 2 | 11/11 e 11/11 | 0/5 | 88% delle cause | 6–7 min |
| Juice Shop, skill prima delle correzioni | 2 | 15/32 e 15/32 (vicino: 17 e 17) | — | 75% | 11–12 min |
| Juice Shop, skill dopo le correzioni | 2 | 18/32 e 20/32 (vicino: 21 e 22) | — | 69% | 10 min |

- **Laravel e Django** confermano che metodo e pre-passaggio funzionano fuori da JavaScript, dopo la correzione dell'inventario (gruppi di Laravel; in Django l'autenticazione era cercata nel file delle route invece che sulla view). Sono però banchi scritti da noi: misurano l'applicazione, non la generalizzazione. Il primo giro Django ha trovato un difetto vero piantato senza volerlo (ricerca senza filtro per sezione), ora D11.
- **Juice Shop** è la misura di generalizzazione: verità scritta da altri. Primo paio di giri: nessuno aveva aperto il frontend (XSS lato client), il chatbot (prompt injection) e il recupero password con domande di sicurezza. Correzioni: `registro-tool/punti-pericolosi.txt` nel pre-passaggio (HTML senza escape anche nel client, esecuzione di codice, deserializzazione, XML, AI, recupero password) e domande in R04/R11. Secondo paio: 18 e 20 vulnerabilità su 32 (unione 20/32, prima 16/32). Restano fuori soprattutto le pagine «nascoste» del frontend (4), le risposte deboli alle domande di sicurezza nei dati (5) e un'immagine Docker. La misura «vicino» (stesso file, entro 15 righe) esiste perché un finding corretto spesso cita l'inizio della funzione e non la riga marcata.
- **gdpr-sentinel sul gestionale B** (repository reale, nessuna verità nota): due coppie di giri `doppio`, prima e dopo l'aggiunta delle `domande_minime`: 39 cause per coppia, accordo 46% e 44%; finding con un corrispondente nell'altro giro 67% e 66%. Le domande non hanno alzato l'accordo: i giri divergono soprattutto per come dividono le cause (un giro fa due gap di ciò che l'altro ne fa uno) e per l'ampiezza del repository (oltre 300 route). Unendo i quattro giri le cause distinte sono 52: un giro solo ne vede circa la metà, quindi per la privacy su un'app grande `doppio` è necessario, non facoltativo. Terza coppia, dopo la regola «un gap = una causa» nella procedura: **accordo 63%**, finding con un corrispondente 83%, 43 cause (37 e 33 gap per giro). La divergenza veniva dunque soprattutto dalla granularità, non dalla copertura. Smentita indipendente sui gap ad alta priorità di un'unione: 9 resistono, 2 declassati, 0 respinti.

## Modalità standard e completo (31/10/2026)
- **`standard` su Juice Shop con test dinamici** su un'istanza locale (release 20.3.0, dati sintetici, solo 127.0.0.1): 11 finding, **9 riprodotti dinamicamente** (SQL injection nel login e nella ricerca, token admin falsificato con la chiave nel codice, BOLA sul carrello, null byte su /ftp, redirect aperto, CORS…), circa 26 richieste, nessun falso. Però 8/32 vulnerabilità contro 18–20 del `rapido`: il giro ha speso il tempo sulle prove senza fare prima l'esame ampio, e mancava il threat model. Da qui la procedura fissa (prima tutto il `rapido`, poi le prove) e il controllo dei deliverable in `chiudi`.
- **Secondo giro `standard`, con la procedura fissa**: threat model presente, 6 su 10 riprodotti, 18 richieste, `chiudi` senza falliti; ma ancora 10 finding (16/32 vulnerabilità nei file citati, contro 22/32 del `rapido`) e riferimenti senza numero di riga. Correzioni: copia obbligatoria dei finding a fine rapido (`findings/rapido.json`) controllata da `chiudi`, righe obbligatorie e riferimenti `audit:` nel revisore. Un terzo giro di verifica è stato interrotto al primo passo da un controllo di sicurezza dell'ambiente: queste correzioni sono provate dai test, non ancora da un giro reale.
- **`completo` sul banco Django** (solo statico): 15 finding, tutti i deliverable, 62 righe di controlli ASVS/profilo, circa 10 minuti. Ha segnalato i punti poco chiari, ora corretti: procedura e definizione di «finito», applicabilità «si (…)», riferimenti solo nella storia Git, risposte in `revisione.md` sovrascritte.

## Modalità standard su un PC, stesso modello e stesso prompt (01/11/2026)
Giri `standard` su Juice Shop con istanza locale (127.0.0.1, dati sintetici), lanciati dall'autore con Claude Code sul proprio PC, **Opus 4.8**, stesso prompt in ogni giro; cambia solo la versione della skill.

| Skill | Vulnerabilità con file e riga | Vicino (15 righe) | Finding | Riprodotti | Gravi smentiti | `chiudi` |
|---|---|---|---|---|---|---|
| versione precedente alla 1.2.0 | 7/32 | 9/32 | 12 | 9 | — | — |
| 1.2.0 | 7/32 | 8/32 | 9 | 6 | 5, tutti resistono | 13 ok |
| 1.2.0 + controllo sui problemi annotati | 8/32 | 10/32 | 13 | 8 | 7, tutti resistono | 1 fallito |
| 1.2.1 (`punti-pericolosi.csv`) | **13/32** | **15/32** | 22 | 11 | 9, tutti resistono | 15 ok |
| 1.2.2 (route del client, dati di seed) | 12/32 | 13/32 | 18 | 8 | 6, tutti resistono | 15 ok |

Cosa mostra: con lo stesso modello il salto viene da `punti-pericolosi.csv`, una riga da chiudere per categoria di punti pericolosi, che ha portato nei finding XSS nel client, SSRF, XXE, chatbot e domande di sicurezza, prima annotati nella checklist e mai riportati. Un controllo sulle parole del motivo («non promosso») non bastava: il giro successivo ha scritto «annotato» e «superfici note». Fra 1.2.1 e 1.2.2 la differenza (13 contro 12) sta nella variabilità di un giro solo: le due categorie nuove sono state aperte e chiuse come «non difetto» con motivi deboli («dati di demo», «solo navigazione»), da cui i criteri aggiunti in `references/commands.md`. Per misurare un effetto di questa grandezza servono almeno due giri per versione. Con Opus 5.5 in cloud il `rapido` aveva dato 18–20/32: il modello conta quanto la procedura.

## Come ripeterlo
```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop /tmp/juice-shop
git clone --depth 1 https://github.com/OWASP/NodeGoat /tmp/NodeGoat
python3 tests/benchmark/run_benchmark.py /tmp/juice-shop
python3 tests/benchmark/run_benchmark.py /tmp/NodeGoat --truth tests/benchmark/nodegoat.json

# banchi con difetti noti (dalla radice del repository della skill)
python3 tests/bench-juice/juice_bench.py prepare ~/prova-juice           # clona Juice Shop al commit fissato
python3 tests/bench-juice/juice_bench.py score ~/prova-juice/juice-truth.bin ~/prova-juice/audit-A ~/prova-juice/audit-B
python3 tests/bench-php/score_bench.py prepare ~/prova-php                 # idem tests/bench-django
python3 tests/bench-php/score_bench.py score ~/prova-php/audit-A ~/prova-php/audit-B
```
