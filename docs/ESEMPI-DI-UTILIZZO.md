# Esempi di utilizzo di appsec-sentinel

Frasi pronte da incollare. Sostituisci i segnaposto tra `<...>`. La skill farà sempre prima il **gate di autorizzazione**: ti chiederà di confermare proprietà, ambienti, tipo di attività e modalità.

## 1. Primo controllo veloce di un repository (analisi statica)
> Usa appsec-sentinel in modalità rapido sul repository `<nome>`. Solo analisi statica: niente richieste a server, nessun test attivo. Il progetto è mio. Segnala segreti, controlli di accesso e dipendenze con advisory, e dimmi quanto hai realmente letto.

Risultato atteso: finding con stato «confermato da codice o configurazione», matrice di copertura con denominatori, domande aperte. Esempio in `examples/collaudo-rapido/`.

## 2. Controllo di una sola area
> Con appsec-sentinel esamina solo autenticazione e autorizzazione di `<repository>`: confronta i percorsi pubblici del middleware con le route e cerca endpoint di debug o seed.

## 3. Assessment standard con test dinamici su istanza locale
> Usa appsec-sentinel in modalità standard su `<repository>`. Ho un'istanza locale su `http://localhost:<porta>` con dati finti e account sintetici (`<utente-A>`, `<utente-B>`, `<admin>`). Autorizzo test applicativi su quell'indirizzo, massimo `<N>` richieste al minuto, nessuna invio di email reali. Non toccare altro.

La skill prepara il piano di test, esegue solo ciò che rientra nel mandato e marca il resto «preparato, non eseguito».

## 4. Retest dopo una correzione
> Ho corretto il finding APP-002 nel branch `<branch>`. Ripeti il caso originale, prova percorsi alternativi e un altro ruolo, e dimmi se resta qualcosa.

## 5. Dai risultati al piano
> Prendi i finding in `<cartella-audit>/findings/findings.json` e prepara un piano di intervento in ordine di priorità, con mitigazione temporanea e test di retest, più le domande per chi gestisce l'infrastruttura.

## 6. Con la parte privacy
> Dopo l'assessment, usa gdpr-sentinel sullo stesso repository e collega i finding di sicurezza all'articolo 32.

## 7. Audit documentale con report PDF
> Usa appsec-sentinel con il comando `documentale` su `<repository>`: inventaria tutti i documenti, confrontali con il codice (sicurezza dichiarata, elenchi, versioni, processi), segnala quelli mancanti, obsoleti o sovrapposti e genera il PDF aziendale per il titolare.

Risultato atteso: matrice documentale, finding per le incoerenze che nascondono un difetto, PDF con sintesi, copertura e piano. Esempio: `examples/collaudo-rapido/report-esempio.pdf`.

## Dove lanciarla
- **Claude (web/desktop)**: carica la skill, poi collega il repository dal connettore GitHub oppure allega i file. Adatta ad analisi statica.
- **Claude Code in locale**: apri la cartella del progetto e usa le stesse frasi; qui puoi anche avviare un'istanza locale con dati finti per i test dinamici.
- **Cartella di audit**: tienila fuori dal repository (usa `scripts/init_audit.py <cartella>`); contiene evidenze e non va mai pubblicata.

## Cosa non chiedere
- Test su server o domini che non sono tuoi o per i quali non hai autorizzazione scritta.
- Brute force o password spraying su account reali, invio di email o SMS reali, test di carico su produzione.
- «Dimmi se sono conforme»: la skill produce finding e copertura, non certificazioni.
