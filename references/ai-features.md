# Funzionalità AI e automazioni (solo se presenti)

Riferimenti: OWASP GenAI Security Project / LLM Top 10 e rischi degli agenti. Verifica l'edizione corrente: se pagine diverse indicano edizioni diverse, registra la discrepanza e usa un riferimento versionato verificato.

Inventaria modelli, provider, prompt, memory, RAG, embedding, vector store, tool, MCP, agenti, azioni automatizzate. Valuta:
- **Prompt injection** diretta e indiretta da documenti, siti, email, ticket, risultati di ricerca, output di tool.
- **Separazione** fra istruzioni e dati; contesto riservato, credenziali e informazioni che il modello non deve vedere.
- **Isolamento dei tenant** nel recupero documenti, memoria, cache, embedding, output.
- **Tool con privilegi eccessivi**: SSRF, esecuzione di codice, letture/scritture, invii, acquisti, azioni concatenate. I controlli devono essere indipendenti dal modello, con conferme per azioni sensibili.
- Allowlist, sandbox, limiti di risorse e di spesa, identità dell'agente, audit, kill switch, gestione di loop, retry, deleghe.
- **Output non fidato** che raggiunge HTML, query, comandi o decisioni operative; poisoning dei dati e integrità delle fonti.
- Dati personali nei prompt, nei log, nel training/fine-tuning; retention, subfornitori, localizzazione, trasferimenti; adeguatezza dei ruoli privacy reali (vedi skill `gdpr-sentinel`, controllo M).

Per i test usa segreti fittizi, documenti sintetici ed endpoint di prova. Non dimostrare esfiltrazioni verso servizi esterni con dati veri. I test di costo/loop vanno sotto le condizioni di `availability-gated.md`.
