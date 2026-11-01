# Disponibilità, DoS applicativo e costi — fase con condizioni bloccanti

Questa fase è **gated**: senza tutte le condizioni sotto non si genera carico. Il motivo è semplice: un test di resilienza mal governato è, di fatto, un attacco al proprietario.

## Condizioni per procedere (tutte)
1. Ambiente isolato.
2. Autorizzazione esplicita **a queste tecniche** (non basta quella ai test generici).
3. Risorse e dipendenze note.
4. Condizioni del provider rispettate (policy di test del cloud/hosting).
5. Dati sintetici.
6. Osservabilità attiva.
7. Budget numerici approvati.
8. Kill switch verificato.

Se ne manca una: completa l'analisi statica e **prepara il piano eseguibile** ("preparato, non eseguito"); non avviare il carico. I test di una web app non autorizzano DDoS volumetrico contro hosting/CDN/reti.

## Profilo da far approvare
Endpoint; dimensioni massime degli input; distribuzione delle identità; richieste totali; RPS massimi; connessioni; concorrenza; durata; storage; tetto di costo. Definisci **soglie numeriche di arresto**: errori, latenza, saturazione, connessioni, backlog, quota del provider, spesa. Non riempire i campi con valori arbitrari presentati come sicuri: se il proprietario non li fornisce, restano `da definire` e il test non parte.

## Esecuzione
Incremento graduale con arresto automatico. Il collasso non è un obiettivo. Quando emerge un comportamento pericoloso: prova minima e interruzione di quello scenario.

## Cosa coprire (in modo proporzionato)
- Endpoint costosi: login/hash password, ricerca, ordinamento, report/export, PDF, immagini, importazioni, upload, decompressione, parser, regex, JSON annidato, aggregazioni DB.
- Paginazione illimitata, input ad alta cardinalità, query complesse, GraphQL depth/alias/batch, cache miss forzati, invalidazioni.
- Pool di connessioni, transazioni/lock lunghi, timeout, worker, file descriptor, socket, WebSocket/SSE; slow client solo nella sandbox prevista.
- Code senza limiti, retry storm, fan-out, webhook duplicati, circuit breaker, backpressure, propagazione dei guasti.
- Rate limit e quote per IP, identità, account, token, tenant, endpoint, costo dell'operazione; atomicità distribuita, proxy fidati, chiavi falsificabili, fallback se il limitatore non è disponibile.
- Lockout, recovery e verifiche che un attaccante può usare per bloccare altri utenti o saturare email/SMS.
- Autoscaling, limiti cloud/serverless, egress/storage, chiamate a pagamento (incluse AI): budget e allarmi contro il *denial of wallet*.
- Ridondanza, dipendenze critiche, degrado controllato, continuità dei controlli di sicurezza, recupero dopo il carico.

## Cosa misurare e riportare
Throughput, p50/p95/p99, error rate, CPU, memoria, I/O, DB, code, connessioni, cache, scaling, costo. Riporta baseline, profilo eseguito, massimo effettivamente raggiunto, arresti, recupero osservato.

## Esclusioni
Traffico illimitato, botnet, amplificazione/riflessione, test distribuiti su reti terze. Un test L7 locale non dimostra protezione da DDoS volumetrico: valuta separatamente architettura, copertura contrattuale, configurazioni e processi del provider, segnalando ciò che non è verificabile.
