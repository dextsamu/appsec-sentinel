# Baseline opzionali e classificazione del rigore

La baseline di default è **ASVS + NIST + ACN/AgID** (vedi `baselines-sources.md`). Usa questo file quando l'utente vuole un secondo metro di confronto o una scala di rigore, oppure quando il contesto lo suggerisce (PA, soggetti NIS2, enti con requisiti propri). Una baseline opzionale non diventa mai un obbligo giuridico per il solo fatto di essere usata: distingui sempre benchmark, obbligo legale e buona pratica.

## 1. Classificazione generica Basso / Medio / Alto
Serve a motivare *quanto rigore chiedere* ai controlli. Classifica separatamente dati, applicazione e infrastruttura, considerando riservatezza, integrità e disponibilità, e scrivi la motivazione. Vale la classe più alta fra le tre proprietà; per dataset misti vale il dato più sensibile.

| Classe | Impatto se la proprietà viene compromessa | Esempi tipici |
|---|---|---|
| **Basso** | Effetto limitato: disagio, correzione semplice, nessun danno rilevante a persone | sito vetrina, contenuti già pubblici |
| **Medio** | Effetto serio: danno apprezzabile a persone o all'organizzazione, interruzione di servizi, obblighi di notifica | anagrafiche di soci o utenti, gestionali, servizi con login |
| **Alto** | Effetto grave: danno significativo o difficilmente reversibile, categorie particolari di dati, servizi essenziali | dati sanitari o su minori, sistemi critici di una PA o di un soggetto NIS2 |

Regole d'uso: la classe è una **proposta motivata** da far confermare al titolare; non è una classificazione ufficiale. Più è alta, più l'audit amplia ASVS (livello atteso), la copertura della matrice endpoint e la verifica di backup, log e incident response.

## 2. Baseline opzionali
| Riferimento | Quando usarlo | Note |
|---|---|---|
| **AgID, Misure minime di sicurezza ICT per le PA** (circolare 2/2017; livelli minimo, standard, alto) | Pubbliche amministrazioni e fornitori della PA | Italiana e pensata per la PA. È del 2017: verifica se è ancora in vigore e se è integrata da misure più recenti (ACN). La pagina AgID può essere in manutenzione: usa il PDF della circolare. |
| **ACN, misure di sicurezza di base NIS2** (determinazione ACN 379907/2025 e allegati) | Soggetti che rientrano nell'ambito NIS2 | Ha valore normativo per i soggetti coinvolti. Verifica prima se l'organizzazione è davvero NIS2 e quali specifiche di base si applicano. |
| **NIST SP 800-53 Rev. 5 con le baseline di SP 800-53B** (Low / Moderate / High) e **FIPS 199** | Serve una scala a tre livelli con controlli già associati, o il cliente adotta framework NIST | Catalogo molto ampio: usa solo il sottoinsieme pertinente alla baseline scelta e dichiaralo. |
| **Framework Nazionale per la Cybersecurity e la Data Protection** (CINI, basato su NIST CSF) | Piccole e medie organizzazioni italiane, contestualizzazione per priorità | Il sito ufficiale può essere in manutenzione: controlla la versione corrente e usa le pagine del laboratorio CINI. |
| **ISO/IEC 27001 e 27002** | Il cliente ha o vuole una certificazione | Norme a pagamento: non riportarne il testo, referenzia solo i numeri dei controlli. |
| **CIS Critical Security Controls** (gruppi di implementazione IG1-IG3) | Serve una prioritizzazione pratica per dimensione | Verifica le condizioni di licenza sul sito prima di riusarne il testo. |

## 3. Come applicarle
- Ricava una matrice dei controlli pertinenti e registrala in `controls-matrix.csv` (fonte, versione, sezione, requisito, applicabilità, evidenza, stato, gap).
- Separa requisiti obbligatori, raccomandazioni e buone pratiche della baseline scelta.
- Per prodotti o processi specifici di un ente (strumenti, account, procedure interne), valuta l'**obiettivo del controllo** e l'equivalente tecnico; segnala ciò che non si applica all'organizzazione.
- Confronta periodicità e SLA reali con quelli della baseline: non basta che una policy esista.
- Dichiara nel report che la baseline è un metro di confronto, non una certificazione né una prova di conformità GDPR.

## 3 bis. Profilo dei controlli minimi
Per sapere che cosa aspettarsi su ogni tema (patch, MFA, log, backup…) per classe di rischio, usa `minimum-controls-profile.md` e il CSV collegato: ogni soglia riporta fonte e provenienza (da fonte, proposta, da definire).

## 4. Baseline fornita dall'utente
Se il cliente ha una baseline propria, chiedi il documento, registra versione e data, e applicala con le stesse regole. Non assumere che un documento non letto sia soddisfatto.

## Fonti
- AgID, Misure minime di sicurezza ICT per le PA (pagina) — https://www.agid.gov.it/it/sicurezza/misure-minime-sicurezza-ict
- AgID, Circolare 2/2017 (PDF) — https://www.agid.gov.it/sites/agid/files/2024-05/CircolareAgID_170418_n_2_2017_Mis_minime_sicurezza_ICT_PA-GU-103-050517-2.pdf
- ACN, NIS: modalità e specifiche di base — https://www.acn.gov.it/portale/nis/modalita-specifiche-base
- NIST SP 800-53 Rev. 5 — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- NIST SP 800-53B (baseline) — https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final
- NIST FIPS 199 — https://csrc.nist.gov/pubs/fips/199/final
- Framework Nazionale per la Cybersecurity e la Data Protection — https://www.cybersecurityframework.it/ (al 29/10/2026 in manutenzione); laboratorio CINI — https://www.consorzio-cini.it/index.php/it/labcs-home
- CIS Critical Security Controls v8 — https://www.cisecurity.org/controls/v8
