# Inventario, superficie d'attacco e threat model

## Indice
1. Inventario completo
2. Superfici da incrociare
3. Matrice endpoint
4. Threat model e percorsi di attacco

## 1. Inventario completo
Registra commit, branch, modifiche locali, timestamp, ambienti, versioni e asset esaminati. Verifica, quando possibile, che il codice analizzato corrisponda alla build distribuita (hash dell'immagine, versione riportata dal runtime, bundle pubblicato).

Inventaria ogni file e directory del perimetro: file nascosti, configurazioni, CI/CD, IaC, migrazioni, script, task, template, documentazione operativa, artefatti pubblicati. Per ogni area indica **una** di queste modalità: revisione semantica / controllo automatico / analisi dei metadati / esclusione motivata. Non affermare di aver letto dipendenze o file generati che hai solo enumerato. Registra tutto in `coverage-matrix.csv`.

## 2. Superfici da incrociare
Ricostruisci da più fonti e confronta; ciò che compare in una fonte e manca nelle altre è un indizio.
- Route da codice, router, OpenAPI, gateway, reverse proxy, JavaScript client, osservazione del runtime; endpoint legacy, debug, health, metriche, documentazione esposta.
- Tutti i metodi HTTP, form, API REST/GraphQL/gRPC, Server Actions/RPC, webhook, WebSocket, SSE, callback OAuth, job, cron, worker.
- Domini e sottodomini autorizzati, DNS, CDN, WAF, origin, load balancer, server, database, cache, object storage, code, backup, osservabilità.
- Ruoli, tenant, account tecnici, pannelli admin/supporto, impersonificazione, autenticazioni interne, integrazioni.
- Dati raccolti, prodotti, importati, derivati, esportati; log, tracce, analytics, pagamenti, email/SMS, geolocalizzazione, AI.
- Ambienti dev/preview/staging raggiungibili dall'esterno e differenze rispetto alla produzione.

## 3. Matrice endpoint
Produci `endpoint-matrix.csv`: endpoint × metodo × identità × ruolo × tenant × oggetto × azione × controllo atteso → test eseguito / esito / finding. Le righe senza test sono parte del risultato: sono il denominatore onesto della copertura dinamica.

## 4. Threat model e percorsi di attacco
- Disegna flussi dei dati e confini di fiducia (un diagramma Mermaid va bene). Identifica asset, impatti, attori: anonimo, utente autenticato, utente di altro tenant, operatore interno, amministratore, integrazione compromessa, dipendenza, agente AI.
- Usa STRIDE per le minacce di sicurezza e LINDDUN per la prospettiva privacy.
- Cerca **percorsi concatenati**: es. accesso a un oggetto altrui → token di integrazione → esportazione; upload → elaboratore vulnerabile → credenziali del worker. Separa i passaggi dimostrati da quelli ipotetici. Non rendere reale un'intera compromissione quando una prova locale minima ne dimostra l'impatto.
- Individua controlli compensativi, single point of failure, punti in cui un errore comporta accesso permissivo (fail-open).
- Valuta sia attacchi dall'esterno sia abusi da utenti e operatori legittimi.
