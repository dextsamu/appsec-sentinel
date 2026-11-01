# Database, crittografia, cloud, supply chain, operatività e ripristino

Riferimenti: ASVS (configurazione, crittografia, comunicazioni), NIST SSDF SP 800-218, NIST CSF, Cheat Sheet Series; per PA/NIS2 anche indicazioni ACN/AgID.

## Indice
1. Database e dati
2. Crittografia
3. Cloud e hosting
4. Server e container
5. DNS e ciclo di vita
6. Email e confini organizzativi
7. CI/CD e repository
8. Dipendenze e SBOM
9. Operatività, incident response, ripristino

## 1. Database e dati
Query parametrizzate, privilegi, separazione degli ambienti, accessibilità di rete, cifratura e chiavi, migrazioni, backup, repliche, credenziali, connessioni, indici, vincoli, dati di test. Verifica export e dump accidentalmente pubblici e l'assenza di dati di produzione nelle preview.

## 2. Crittografia
- File `.env*` e simili: un file chiamato «example» o «template» può contenere valori reali. Classifica i valori **per forma** (segnaposto / vuoto / lunghezza ed entropia da segreto) senza mai stamparli, e leggi i commenti del file: se dichiara di contenere valori reali, è un finding.
Inventaria algoritmi, protocolli, generazione casuale, chiavi, certificati, nonce/IV, firme, verifiche di integrità. Valuta librerie affidabili, cifratura autenticata ove pertinente, unicità e corretto uso dei nonce, separazione delle chiavi per scopo/ambiente, KMS/HSM quando motivati, rotazione, revoca, recupero, accesso ai dati in chiaro. Distingui cifratura, hashing, encoding, pseudonimizzazione. Niente crittografia personalizzata; la sola dicitura «encrypted» non basta.

## 3. Cloud e hosting
Confronta IaC, configurazione dichiarata e stato reale disponibile. Verifica IAM, ruoli e trust policy, account root/admin, MFA, segregazione, accessi remoti, firewall/security group, reti private, egress, object storage, CDN/WAF, log, secret manager, metadati cloud. **Evidenzia ciò che non vedi dalla sola IaC** (stato reale, console, modifiche manuali).

## 4. Server e container
- Porte pubblicate dai file Compose/orchestrazione: database e cache non devono ascoltare su tutte le interfacce; verifica il binding (`127.0.0.1:porta:porta`) e il firewall dell'host (se non verificabile, dichiaralo).
OS/runtime supportati, patch, servizi e porte, utente non privilegiato, filesystem e mount, capability, immagini e provenienza, isolamento, orchestrazione, network policy, pannelli e socket amministrativi. Non cambiare configurazioni reali durante la verifica.

## 5. DNS e ciclo di vita
Record obsoleti e takeover potenziali, verifica dell'origin, certificati, proprietà dei domini, ambienti dimenticati, dismissione. Non registrare domini o acquisire risorse per dimostrare un takeover senza autorizzazione specifica.

## 6. Email e confini organizzativi
Se l'app invia posta o usa l'email per l'identità: SPF/DKIM/DMARC e allineamento, gestione dei bounce, abusi degli invii, protezione del dominio. Servizi amministrativi e accesso degli operatori, onboarding/offboarding, accessi di emergenza, separazione dei compiti. Controlli fisici e formazione: solo con evidenze documentali, non presumerli dal repository.

## 7. CI/CD e repository
Protezioni dei branch, review, accessi, token e permessi dei workflow; fork/PR non fidate, script di build, runner, secret injection, artefatti, approvazioni di deploy, separazione degli ambienti. Esposizioni in log, cache, immagini.

## 8. Dipendenze e SBOM
Crea una SBOM con componenti diretti/transitivi, runtime, immagini, servizi rilevanti. Controlla lockfile, registri, script di installazione, dipendenze Git/URL, typosquatting, dependency confusion, componenti abbandonati/EOL, integrità/provenienza delle build.
Per ciascun advisory verifica: versione effettiva, configurazione, **raggiungibilità** del codice vulnerabile, condizioni di sfruttamento. La presenza del pacchetto non è sfruttamento dimostrato. CVSS ed EPSS supportano la priorità; CISA KEV segnala sfruttamento noto. Non basta il comando di audit del package manager. Niente aggiornamenti massivi né fix automatici durante l'assessment.
- **Esecuzione**: `scripts/run_scanners.py deps <repo> --out <audit>/registro-tool` lancia `npm audit --package-lock-only --ignore-scripts` (non serve `node_modules`; invia a npm solo nomi e versioni dei pacchetti, `--no-network` lo impedisce) e registra l'esito in `sca-stato.json`; per la storia Git `run_scanners.py history`. Se non parte, riporta il motivo reale e il comando preparato come limite.
- **Raggiungibilità degli advisory**: un `npm audit` (o equivalente) sul solo lockfile è ammesso se invia soltanto nomi e versioni; il risultato è un elenco, non una valutazione. Per ogni advisory di gravità alta o critica sui componenti centrali (framework, autenticazione, parser) verifica se la funzione colpita è usata (ottimizzazione immagini, cache, server actions, middleware, piattaforma di hosting) e registra «raggiungibile / non raggiungibile / non valutato». Gli advisory sul middleware o sull'autenticazione contano di più quando l'applicazione affida lì i controlli di accesso.
- Versioni beta di librerie di autenticazione e runtime a fine supporto vanno riportate come rischio di manutenzione, con la data di fine supporto verificata alla fonte.

## 9. Operatività, incident response, ripristino
- Ownership, inventario, processo di patch, vulnerability management, canale di segnalazione, logging, alert, sincronizzazione oraria, integrità e accesso ai log. Cerca segreti e dati personali eccessivi nella telemetria e verifica che i log necessari esistano davvero.
- Capacità effettiva di rilevare e ricostruire: accessi anomali, cambi di privilegi, esportazioni massive, tentativi cross-tenant, abusi di token. Verifica consegna e presa in carico degli alert con eventi sintetici concordati: una dashboard non prova che qualcuno gestisca un incidente.
- Backup cifrati e separati, credenziali indipendenti, protezione da cancellazioni/ransomware ove motivata, **restore testato**, RPO/RTO reali. «Backup riuscito» non prova che il ripristino funzioni. Restore solo su ambiente autorizzato e isolato.
- Runbook per compromissione account, fuga di chiavi, accesso cross-tenant, ransomware, indisponibilità, supply chain: responsabilità, revoca/rotazione, evidenze, comunicazione, continuità. Testa con tabletop o simulazioni concordate, senza notifiche reali.
