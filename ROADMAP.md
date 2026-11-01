# Roadmap di appsec-sentinel

Cosa è fatto, cosa viene dopo e perché. Le priorità vengono dalle misure in [docs/BENCHMARK.md](docs/BENCHMARK.md), non da una lista di desideri: ogni voce dice quale numero dovrebbe cambiare. Nessuna data promessa; l'ordine è l'ordine di lavoro.

## Fatto

**1.0 – 1.1 (29–30/10/2026).** Metodo con gate di autorizzazione, stati onesti (esaminato, provato, ignoto), finding strutturati e validati, copertura con denominatori reali, report PDF, profilo di controlli minimi, comandi in italiano e inglese.

**1.2.0 (01/11/2026), prima versione pubblica**, misurato su banchi con difetti noti e su repository reali:
- ripetibilità del `rapido`: checklist di 14 aree, pre-passaggio deterministico, campione prioritario; accordo fra due giri dal 20% al 60–71%;
- `doppio`: due giri indipendenti, unione per causa, smentita sull'unione con un terzo verificatore (`apply_refutations.py`);
- banchi: Node/Next.js (16/16 in due giri), Laravel (13/13), Django (11/11), OWASP Juice Shop con verità scritta da altri (18–20/32 per giro);
- elenco dei punti pericolosi nel pre-passaggio (anche nel client, AI, recupero password);
- procedure fisse per `standard` e `completo`, deliverable controllati da `chiudi`, base del `rapido` obbligatoria;
- tempi per giro e per passo.

## Prossimo

1. **Confermare lo `standard` con un giro reale.** Le ultime correzioni (base del `rapido`, righe obbligatorie, riferimenti `audit:`) sono provate solo dai test. Obiettivo: un giro `standard` su Juice Shop locale con almeno i finding di un `rapido` (22/32 nei file citati) e i critici riprodotti dinamicamente. Pronto da lanciare: `_prove/avvia-standard.ps1` nella cartella di lavoro dell'autore.
2. **Rilascio 1.3.0** con le correzioni confermate dal punto 1, note dal CHANGELOG e pacchetti `.skill` allegati.
3. **Smentita anche senza sottoagenti.** Oggi un agente singolo può solo scrivere «non eseguita». Proposta: un comando che prepara un pacchetto per una seconda sessione (brief e codice, niente motivazioni) e reimporta `esiti.json`. Obiettivo: zero finding alti consegnati senza smentita quando l'utente ha una seconda sessione.
4. **Juice Shop: i casi ancora mancati.** Le pagine «nascoste» del frontend (route senza link nel client) e i dati di esempio deboli (domande e risposte di sicurezza, account di seed). Obiettivo: oltre 24/32 per giro senza aumentare i falsi allarmi sui banchi.
5. **Report PDF completo per `standard` e `completo`**, con sintesi del threat model e dei test dinamici registrati.
6. **Giro misurato su Codex e Antigravity.** Le skill sono state provate una sola volta su ciascuno (Windows, `rapido`, app finta). Obiettivo: un `rapido` sul banco Django e uno su Juice Shop con ciascun agente, con punteggio e note su cosa cambia (sottoagenti, permessi, comandi), così il README può dire che funzionano e non solo che sono state provate.

## Dopo

- **Altri stack con banco proprio**: Spring (Java), Go, Rails, ASP.NET. L'inventario delle route li riconosce, ma non è misurato.
- **Prove dinamiche oltre l'autorizzazione**: un aiuto per le prove a richiesta singola (injection, redirect, upload) con gli stessi limiti di `dynamic_authz_check.py` (solo host autorizzati, tetto di richieste, niente corpi salvati).
- **Catalogo ASVS consultabile senza rete** per citare i requisiti con il numero giusto quando il mandato vieta la navigazione.
- **Esecuzione in CI**: un'azione che lancia pre-passaggio e `chiudi` su ogni pull request e pubblica solo l'esito, mai i dettagli.
- **Messaggi degli script in inglese** (oggi sono tradotti i valori e il PDF, non i messaggi a terminale).

## Non in programma

- Scansioni attive su sistemi non autorizzati per iscritto, test di carico senza mandato specifico, «certificazioni» o percentuali di sicurezza.
- Invio di codice o finding a servizi esterni.

## Come proporre una voce

Apri una issue con il caso concreto (repository o banco, cosa è stato mancato o sbagliato, come si misura). Una voce entra in «Prossimo» quando ha un numero che deve cambiare.
