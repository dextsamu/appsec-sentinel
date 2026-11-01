# Usare la skill con altri agenti

La skill è una cartella con `SKILL.md`, riferimenti in Markdown e script in Python (solo libreria standard, `reportlab` per il PDF). Il formato `SKILL.md` è letto anche da altri agenti oltre a Claude. Qui trovi cosa è stato **provato** e cosa no.

## Stato delle prove
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
5. I finding alti hanno una smentita fatta da un altro verificatore, o `non eseguita` dichiarato?
6. Ha lanciato `validate_findings.py` e `verify_findings.py`?

Su Windows gli script si lanciano con `python` o `py` al posto di `python3`.
