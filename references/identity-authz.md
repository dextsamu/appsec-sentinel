# Identità, autenticazione, sessioni, segreti, autorizzazione e isolamento

Riferimenti principali: ASVS (capitoli autenticazione, sessioni, controllo accessi), WSTG (identity/authn/authz testing), NIST SP 800-63, API Security Top 10 (BOLA/BFLA/BOPLA). Verifica le versioni correnti (vedi `baselines-sources.md`).

## Indice
1. Identità e sessioni
2. Segreti
3. Autorizzazione e isolamento
4. Come testare l'autorizzazione

## 1. Identità, autenticazione, sessioni
Esamina e, dove autorizzato, prova:
- Registrazione, verifica email/telefono, login, logout, inviti, recupero account, reset password, cambio identità, collegamento account, trasferimento di proprietà.
- Enumerazione utenti (differenze di risposta e di timing), difese contro tentativi ripetuti, blocchi abusabili come DoS, account dormienti, credenziali di default.
- Hash delle password: algoritmo, parametri, salt, upgrade. Confrontali con le indicazioni ufficiali **correnti**; non prescrivere algoritmi o soglie da ricordi non verificati.
- MFA e passkey: requisiti per admin/staff, enrollment, recovery, backup code, fattori deboli, bypass tramite percorsi alternativi.
- OAuth/OIDC/SSO/SAML: issuer, audience, firme, algoritmi, scadenze, state/nonce, PKCE, redirect URI, metadata, gestione chiavi; account linking e isolamento tra organizzazioni.
- Cookie e token: Secure, HttpOnly, SameSite, scope Domain/Path, prefissi, trasporto, fixation, furto, revoca, rotazione; token di accesso e refresh, riuso e concorrenza.
- Invalidazione dopo logout, cambio password/MFA, disabilitazione, cambio ruolo, uscita da un tenant; sessioni parallele; autenticazione recente per azioni sensibili.
- Una libreria di autenticazione presente non prova la corretta configurazione.

## 2. Segreti
- API key, service account, webhook secret, credenziali DB: privilegi, scadenza, inventario, separazione per ambiente, distribuzione, rotazione, revoca.
- Cerca esposizioni in repository e cronologia (se autorizzata), bundle client, source map, log, URL, messaggi d'errore, cache, immagini container, artefatti CI, documentazione.
- Leggi il minimo necessario e **redigi i valori**: registra posizione, tipo e stato, mai il segreto (`engagement-rules.md` §5).

## 3. Autorizzazione e isolamento dei dati
Verifica ogni confine di accesso **lato server**, nei job e nei canali asincroni. Copri BOLA/IDOR, BFLA, autorizzazione a livello di proprietà/campo, mass assignment, escalation orizzontale e verticale.
- Controlla ownership, tenant scoping, membership, permessi ereditati e revocati. Non fidarti di ID, email, ruoli o tenant passati dal client.
- Cerca percorsi che bypassano middleware o UI; verifica il comportamento quando il sistema di autorizzazione fallisce (deve negare).
- Estendi l'isolamento a: cache, CDN, log consultabili, report, file, link condivisi, URL firmati, indici di ricerca, code, notifiche, WebSocket, supporto, backup, basi vettoriali.
- Database con RLS: policy, ruoli che le bypassano, query raw, propagazione del contesto con pooling e riuso delle connessioni.
- Endpoint interni, amministrativi, cron, webhook: una route non documentata non è privata.
- **Confronta l'elenco dei percorsi pubblici (middleware, proxy, configurazione del framework) con le route realmente presenti.** Una route pubblica per eccezione senza controlli propri, o una route che nella documentazione è «pubblica» ma il middleware non la espone, sono i difetti più frequenti trovati nei collaudi. Il middleware non è l'unico presidio: cerca controlli di sessione e ruolo anche nel gestore, e verifica che le versioni del framework non abbiano bypass noti del middleware.
- **Route di debug, seed, demo, migrazione, «fix» una tantum**: cercale per nome (`debug`, `seed`, `demo`, `fix`, `internal`, `test`), controlla se sono nella build di produzione, se richiedono ruolo, se mutano dati con GET, se contengono credenziali o email fisse. Una password fissa nel codice per account demo è una credenziale predefinita.
- **Risposte che restituiscono più del necessario**: password temporanee o token nel corpo della risposta, record con relazioni complete (contatti, organizzazione) invece dei soli campi usati.
- **Le euristiche non sono letture.** Una ricerca (grep) di «route senza chiamata di autenticazione» dà falsi positivi (endpoint disattivati) e falsi negativi (controlli in funzioni con altro nome). Dichiara sempre quante route hai letto davvero rispetto al totale; le altre restano «ignoto» per ruolo e tenant.
- Impersonificazione e accessi di assistenza: motivazione, durata, audit, limiti.

## 4. Come testare l'autorizzazione
Identità sintetiche minime: anonimo, utente A, utente B stesso tenant, utente di altro tenant, amministratore (adatta ai ruoli reali). Per ogni operazione pertinente prova: lettura, elenco, ricerca, creazione, modifica, cancellazione **simulata**, download, esportazione. Annota ogni combinazione in `endpoint-matrix.csv`; le combinazioni non provate restano visibili come non testate.
