# Input, output, browser, API, file, integrazioni, logica di business e pentest

Riferimenti: ASVS (validazione, encoding, API, file, logica), WSTG, API Security Top 10, OWASP Cheat Sheet Series.

## Indice
1. Input, output, browser, protocolli
2. API e canali asincroni
3. File
4. Webhook e integrazioni
5. Business logic e concorrenza
6. Pentest applicativo e validazione dinamica

## 1. Input, output, browser, protocolli
Segui i dati da ogni sorgente ai sink, inclusi dati già salvati e integrazioni "affidabili".
- SQL/NoSQL injection, command/code injection, template injection, LDAP/XPath/XML/XXE, deserializzazione, prototype pollution, parsing ambiguo, canonicalizzazione.
- XSS riflesso, persistente, DOM; HTML, SVG, Markdown, rich text, template email, documenti; escaping corretto **per contesto**, sanitizzazione, dati inseriti negli script.
- SSRF e fetch server-side: protocolli, redirect, DNS, reti interne, servizi metadata, credenziali implicite. Usa mock o endpoint controllati, senza interrogare indiscriminatamente metadati o reti di produzione.
- Path traversal, file inclusion, accesso a file locali, link simbolici, race sui percorsi.
- CSRF e validazione dell'origine secondo i flussi reali; CORS con credenziali e riflessione delle origini; clickjacking, postMessage, opener, XS-Leaks pertinenti.
- Open redirect, Host header e proxy header trust, IP del client, confusione di metodi e content type, parameter pollution, gestione incoerente degli errori.
- Cache poisoning/deception, request smuggling/desincronizzazione: **solo in ambiente isolato**, perché possono coinvolgere richieste di altri utenti.
- HTTPS, TLS, certificati, HSTS, CSP, frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy, mixed content, valutando compatibilità e rischio effettivo.
- Dati in URL, cronologia, referrer, browser storage, IndexedDB, service worker, cache offline, dispositivi condivisi.

Un header mancante o un pattern sospetto è un **indizio da contestualizzare**, non una severità critica automatica.

## 2. API e canali asincroni
Validazione lato server, schema, campi extra, filtri, paginazione, limiti di risposta, errori, API versionate, endpoint batch e debug. GraphQL: autorizzazione per resolver, alias, batching, profondità, costo. WebSocket: autenticazione iniziale, autorizzazione dei messaggi, rinnovo/revoca, origin, quote.

## 3. File
Autenticazione e permessi, tipo reale/MIME/estensione, nomi, percorsi, dimensioni, quantità, antivirus ove motivato, archiviazione e download. Contenuti attivi, SVG/HTML, archivi, immagini/documenti, metadati EXIF, file pubblici accidentali, URL firmati e scadenze. Per archivi malevoli/decompressione usa fixture piccole e limitate in sandbox: niente bombe capaci di saturare sistemi condivisi.

## 4. Webhook e integrazioni
Firma sul **corpo corretto**, timestamp, replay, rotazione, idempotenza, retry, ordinamento eventi, riconciliazione. Non fidarti del callback del browser per confermare pagamenti o attivare servizi. Verifica scope OAuth e revoca anche presso i fornitori.

## 5. Business logic e concorrenza
Ricostruisci le invarianti di prezzi, sconti, valuta, quantità, saldi, crediti, abbonamenti, trial, quote, prenotazioni, referral, inviti, approvazioni, trasferimenti. Cerca valori negativi, arrotondamenti, stato client fidato, salti di fase, doppio utilizzo, incoerenze fra sistemi. Concorrenza: race condition, TOCTOU, retry e richieste parallele su operazioni sensibili; transazioni, vincoli, lock, chiavi di idempotenza. Usa sandbox dei pagamenti e fixture sintetiche, senza movimentare denaro né inviare comunicazioni reali.

## 6. Pentest applicativo e validazione dinamica
- Deriva i casi di test dal threat model, dalla matrice autorizzativa e dai requisiti ASVS/WSTG. Per ciascuno: prerequisiti, identità, dati sintetici, input, esito atteso/osservato, cleanup concordato.
- Combina analisi del codice e verifica da browser/proxy/API. Copri sessioni nuove, anonime, autenticate, scadute, revocate, ruoli e tenant diversi, e i percorsi non raggiungibili dalla UI.
- Tool (ZAP/Burp, SAST/SCA/segreti/container/IaC, controlli TLS, test runner) **solo se disponibili e autorizzati**, con configurazioni coerenti col perimetro; niente template di exploitation indiscriminati, fuzzing pesante o funzioni distruttive. Verifica falsi positivi e negativi con lettura manuale e prove mirate.
- Uno scan automatico non è un pentest. Un comando scritto non è un test eseguito. Se un tool manca o fallisce, registra il limite e usa alternative compatibili; non inventare output.
- Per ogni test registra: ambiente/versione, timestamp, durata, parametri redatti, identità sintetiche, richiesta/risposta o traccia equivalente, risultato, copertura. Non pubblicare payload o procedure contro sistemi fuori mandato.
