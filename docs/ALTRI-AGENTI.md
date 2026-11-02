# Usare la skill con altri agenti

La skill è una cartella con `SKILL.md`, riferimenti in Markdown e script in Python (solo libreria standard, `reportlab` per il PDF). Il formato `SKILL.md` è letto anche da altri agenti oltre a Claude. Qui trovi cosa è stato **provato** e cosa no.

## Giro misurato (01/11/2026)
Stesso compito e stesso prompt per i due agenti, su Windows, con la versione 1.3.0: `gdpr-sentinel` in modalità `statica` sul secondo banco privacy (`tests/bench-pa`, sito di una scuola in PHP, 15 difetti noti e 5 esche), lanciato dall'autore sul proprio PC. Punteggio con `tests/bench-pa/score_bench.py`.

| Agente | Difetti | Alti | Falsi allarmi | Gap | Smentita | `chiudi` |
|---|---|---|---|---|---|---|
| Antigravity (Gemini) | 14/15 | 6/6 | 0/5 | 9 | pacchetto `refutation_pack.py` dato a una **sessione nuova** di Antigravity: 8 gap verificati con 25 tentativi citati per file e riga, tutti resistono | 0 falliti (dopo la correzione su «conforme all'informativa», vedi CHANGELOG) |
| Codex | 14/15 | 6/6 | 0/5 | 19 | sottoagente indipendente avviato da Codex con i soli brief: 12 gap ad alta priorità, tutti resistono, con tentativi citati | 0 falliti, 0 da verificare |
| Claude (riferimento, due giri in cloud) | 15/15 e 15/15 | 6/6 | 0/5 | 18 e 18 | — | 0 falliti |

Cosa è emerso: entrambi hanno rispettato il mandato (repository non modificato, nessuna rete, nessun «conforme», nessun valore di segreto) e nessuno ha smentito da solo i propri gap. Antigravity ha raggruppato più cause in un gap (9 gap per 14 difetti: reCAPTCHA, Maps, YouTube e Fonts in uno solo), contro la regola «un gap = una causa»; ha mancato la galleria con le foto degli alunni. Codex ha scritto 19 gap ben separati e due fuori elenco ragionevoli (backup e procedura data breach non verificabili); ha mancato Google Fonts come gap a sé (il file è citato in un gap sull'informativa). Codex ha scritto propri script di supporto nella cartella di audit. Antigravity non partiva con Cloudflare WARP attivo: l'API di Google rifiutava la posizione («User location is not supported»). Un giro per agente: misura che la skill funziona su questi agenti, non quanto siano stabili.

Stesso giorno, `appsec-sentinel rapido` (solo analisi statica) sul banco Django (`tests/bench-django`, gestionale soci con 11 difetti noti, uno solo nella storia Git, e 5 esche), stesso prompt per gli agenti:

| Agente | Difetti | Alti | Falsi allarmi | Finding | Smentita | `chiudi` |
|---|---|---|---|---|---|---|
| Antigravity (Gemini) | 10/11 | 6/6 | 0/5 | 12 | 7 finding alti, tutti resistono, con tentativi citati per file e riga; l'agente ha preparato il pacchetto e dichiara un «sottoagente indipendente con contesto isolato»: non verificabile da qui che fosse davvero separato | 13 ok, 0 da verificare, 0 falliti (13 min) |
| Codex | 11/11 | 6/6 | 0/5 | 14 | sottoagente indipendente avviato da Codex: 4 finding verificati, 3 resistono e 1 declassato (SSRF da alta a media: timeout, output limitato, nessuna credenziale inoltrata) | 11 ok, 1 da verificare, 0 falliti (giro ripreso il giorno dopo, credito esaurito) |
| Claude (riferimento, due giri in cloud) | 11/11 e 11/11 | 6/6 | 0/5 | — | — | 0 falliti |

Antigravity ha trovato anche il segreto presente solo nella storia Git senza riportarne il valore; ha mancato le dipendenze con vulnerabilità note (D09). Codex li ha trovati tutti e 11, più due rilievi fuori elenco ragionevoli (login senza limite di tentativi, immagine Docker senza utente dedicato), ma assegna severità più basse (la chiave di firma Django è «media») e lascia come ipotesi il segreto nella storia Git e le dipendenze. Il «da verificare» è «deserializzazione sicura», termine tecnico.

Juice Shop (`tests/bench-juice`, verità scritta da altri, 32 vulnerabilità con file e riga), `rapido` statico, stesso prompt, 02/11/2026:

| Agente | Con file e riga | Vicino (15 righe) | Finding | Smentita |
|---|---|---|---|---|
| Antigravity (Gemini) | 6/32 | 9/32 | 12 | pacchetto preparato, smentita non eseguita |
| Codex | 18/32 | 22/32 | 28 | sottoagente indipendente: 14 resistono, 1 declassato |
| Claude (riferimento, Opus 5.5 in cloud) | 23/32 e 19/32 | 27 e 23 | 37 e 36 | — |

Sul banco piccolo (Django, 11 difetti) Antigravity e Codex erano vicini (10 e 11); su un'app grande e densa come Juice Shop la differenza fra agenti è ampia. Antigravity ha scritto pochi finding (12) e ha raggruppato più cause in ciascuno.

## Prima prova (30/10/2026)
Prova del 30/10/2026, su Windows, un solo giro per agente: audit in modalità `rapido`, solo analisi statica, su un'app finta creata dall'agente stesso, con entrambe le skill (`appsec-sentinel` e `gdpr-sentinel`). Le versioni degli agenti non sono state registrate.

| Agente | Letta ed eseguita | Esito | Cosa ha messo in luce |
|---|---|---|---|
| Codex | sì | Regole di ingaggio scritte, nessun test dinamico, segreto redatto ovunque, nessun «conforme» | Non ha lanciato `verify_findings.py`; su Windows ha perso tempo a trovare un interprete Python |
| Antigravity | sì | Regole di ingaggio scritte, nessun test dinamico, segreto assente dai file e dal PDF, nessun «conforme» | Ha riportato un segreto (inventato) nel messaggio finale; la «smentita» era di facciata, scritta dall'agente stesso |

Da queste prove sono nate le regole aggiunte alla 1.1.0: nessun valore di segreto in nessun output (chat compresa), `verify_findings.py` nella chiusura, smentita valida solo se fatta da un verificatore diverso (altrimenti `non eseguita`), CVSS da sola lettura statica solo dichiarando il limite.

**Non provato:** le modalità `standard` e `completo`, i test dinamici, altri agenti (Cursor, Copilot, Gemini CLI, Aider), le app web di chat. Non scrivere «compatibile» al posto di «provato una volta su…».

## Dove mettere la skill
- **Antigravity.** Cartella del progetto `.agents/skills/<nome-skill>/` oppure, valida per tutti i progetti, `~/.gemini/config/skills/` (la guida di Google cita anche `~/.agents/skills`). Ogni skill è una sottocartella con il suo `SKILL.md`. L'agente la attiva confrontando la richiesta con il campo `description`, quindi nominala nel messaggio. Fonte: [Authoring Google Antigravity Skills](https://codelabs.developers.google.com/getting-started-with-antigravity-skills?hl=en).
- **Codex.** Una fonte di terzi indica `~/.codex/skills/<nome-skill>/` (utente) e `./.codex/skills/` (progetto). Non è confermato dalla documentazione ufficiale di OpenAI: verifica con `codex --help`. Nella prova la skill è stata passata come file `.skill` (uno zip) nella cartella di lavoro e l'agente l'ha estratta e letta.
- **In generale.** Se l'agente non scopre da solo la skill, mettila in una cartella del progetto e di' all'agente di leggere il `SKILL.md` e di seguirlo. Funziona, ma dipende da quanto il modello rispetta le regole.

## Cosa controllare sempre con un altro agente
1. Prima di toccare il codice ha scritto o confermato proprietà e perimetro autorizzato?
2. Ha lasciato come «non eseguito» ciò che non ha eseguito?
3. Nessun valore di segreto o dato personale nei file e nei messaggi (`scripts/redact_check.py` sulla cartella di audit)?
4. Nessun «conforme» né «sicuro»?
5. I finding alti hanno una smentita fatta da un altro verificatore, o `non eseguita` dichiarato? Su un agente senza sottoagenti, la smentita si fa con `scripts/refutation_pack.py prepara` (pacchetto per una seconda sessione, anche con un altro agente) e `importa`.
6. Ha lanciato `validate_findings.py` e `verify_findings.py`?

Su Windows gli script si lanciano con `python` o `py` al posto di `python3`.
