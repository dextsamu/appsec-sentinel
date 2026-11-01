<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Samuele Cucurnia e Pietro Previtali -->
# Profilo dei controlli minimi per classe di rischio

Tabella di riferimento per decidere **quanto rigore** aspettarsi su un tema (patch, MFA, backup, log…) in base alla classe di rischio dell'asset. È il corrispettivo pubblico e tracciabile di una "tabella dei controlli minimi per classe": ogni riga dice da quale fonte viene e cosa, invece, è una nostra proposta.

Dati completi: `assets/minimum-controls-profile.csv` (una riga per tema, con soglie Basso/Medio/Alto, cosa verificare, fonti per AgID, ACN e NIST, provenienza). Questo file spiega il metodo e i limiti.

## 1. Come usarla
1. Classifica l'asset su Basso/Medio/Alto con la scala di `optional-baselines.md` (sezione 1), registrando la motivazione.
2. Per ogni tema pertinente apri la riga del CSV e confronta lo stato **reale** con la soglia della classe.
3. Scrivi in `controls-matrix.csv` fonte, soglia attesa, evidenza, stato e gap.
4. Se la riga è marcata **proposta** o **da definire**, non presentare lo scostamento come violazione di una norma: è un'osservazione rispetto a un valore concordato col titolare. Chiedi al titolare di confermare o correggere il valore e annotalo.
5. Dichiara nel report che il profilo è un metro di confronto, non una certificazione.

## 2. Provenienza: cosa significa ogni etichetta
| Etichetta | Significato |
|---|---|
| **da fonte** | Il requisito e la sua distribuzione per livello sono presenti in almeno una delle fonti lette (AgID con livelli Minimo/Standard/Alto; NIST con baseline Low/Moderate/High). |
| **requisito da fonte; valore = proposta** | La fonte richiede il controllo ma non fissa un numero (es. giorni per le patch). Il valore numerico è nostro. |
| **proposta** | Corrispondenza o soglia scelta da noi come punto di partenza ragionevole. Da confermare. |
| **da definire** | Fonti non lette o non abbastanza precise: decide il titolare con consulenza. |

Nessun valore è copiato da documenti di terzi non pubblici o non citati. Le fonti usate sono solo quelle elencate qui sotto.

## 3. Corrispondenza tra scale (nostra mappatura)
| Classe skill | AgID | NIST (SP 800-53B) | ACN NIS2 |
|---|---|---|---|
| Basso | Minimo | Low | — |
| Medio | Standard | Moderate | — |
| Alto | Alto | High | — |

L'ACN non distingue tre livelli di rigore: distingue soggetti **importanti** (allegato 1) ed **essenziali** (allegato 2), con misure in buona parte coincidenti e alcune aggiuntive per gli essenziali. Nel CSV la colonna ACN indica la sottocategoria e dove si applica (I, E). La mappatura Basso/Medio/Alto ↔ livelli AgID/NIST è **approssimativa**: gli schemi non sono costruiti per corrispondersi uno a uno.

## 4. Metodo di estrazione e data
- **AgID**: PDF della circolare 2/2017 (Gazzetta Ufficiale n. 103 del 5-5-2017), testo estratto con `pdftotext -layout`. I livelli sono ricavati dalla posizione delle «X» nelle colonne Minimo/Standard/Alto. L'impaginazione spezza gli identificativi (es. «10 2 1»): gli ID ABSC nel CSV sono **ricostruiti** e dove l'incertezza è maggiore sono marcati «numerazione da verificare».
- **ACN**: allegati 1 (soggetti importanti) e 2 (soggetti essenziali) della determinazione 379907/2025, versione scaricata il 29/10/2026. Letto il testo delle sottocategorie PR.AA-03, PR.AA-05, PR.PS-01, PR.PS-02, PR.PS-04, PR.PS-06, PR.DS-02, PR.DS-11, ID.RA-08, ID.AM-02. Le sottocategorie GV.SC e quelle sulla risposta agli incidenti sono state solo individuate per identificativo e non rilette nel testo.
- **NIST**: cataloghi OSCAL delle baseline SP 800-53B (Low, Moderate, High) su SP 800-53 Rev. 5, versione 5.2.0, con appartenenza di controlli e miglioramenti verificata con uno script.
- Ricerca di periodicità numeriche nei testi ACN: trovate solo «almeno ogni due anni» e «almeno con cadenza annuale». Le fonti lette **non fissano** giorni per le patch né mesi di conservazione dei log.

## 5. Limiti dichiarati
- Il profilo non sostituisce l'analisi del rischio specifica né l'esame della norma applicabile al soggetto.
- Le soglie numeriche marcate «proposta» (giorni per patch, frequenze di scansione) sono nostre; servono per confrontare e non per dichiarare conformità.
- Le fonti cambiano: ricontrolla versione e stato di vigore prima di citarle in un report.
- Dove i testi ufficiali sono ambigui, vale il testo ufficiale, non questa sintesi.

## 6. Come estenderla
Aggiungi una riga al CSV per ogni tema nuovo con: fonte e sezione, livelli, cosa verificare, provenienza. Se non hai la fonte, scrivi «da definire». Non inserire valori senza indicare da dove vengono.

## Fonti
- AgID, Circolare 2/2017 (PDF) — https://www.agid.gov.it/sites/agid/files/2024-05/CircolareAgID_170418_n_2_2017_Mis_minime_sicurezza_ICT_PA-GU-103-050517-2.pdf
- ACN, NIS: modalità e specifiche di base — https://www.acn.gov.it/portale/nis/modalita-specifiche-base
- NIST SP 800-53B (baseline) — https://csrc.nist.gov/pubs/sp/800/53/b/upd1/final
- NIST SP 800-53 Rev. 5 — https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final
- OWASP ASVS — https://owasp.org/www-project-application-security-verification-standard/
