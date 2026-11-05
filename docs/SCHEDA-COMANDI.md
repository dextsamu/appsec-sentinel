# Scheda comandi · appsec-sentinel

Scrivi il comando dopo `/appsec-sentinel` (o come prima parola della richiesta). **Nessun comando salta il gate di autorizzazione:** prima dei test attivi serve perimetro e conferma scritta.

## Il flusso in sei righe
1. `rapido <repo>` (o `standard`, `completo`): intake, regole di ingaggio, modalità.
2. `inventario <repo>`: matrice endpoint con le route senza auth evidente in testa.
3. `scanner <file…>` e, se autorizzato, `dinamico <config> <test>`: ipotesi dagli scanner e prove di accesso.
4. `revisione` e `smentita`: falsi positivi, e un verificatore che prova a confutare i finding alti.
5. `chiudi` poi `pdf`: controllo di consegna (segreti, smentite, parole vietate), quindi il report.
6. `confronta <vecchio> <nuovo>` dopo le correzioni: risolti, nuovi, cambiati.

## Avvio
| Comando | Che cosa fa |
|---|---|
| `rapido <repo>` | Triage mirato (ore), analisi statica |
| `standard <repo> [url]` | Threat model, analisi statica, verifiche dinamiche autorizzate, controlli ASVS pertinenti |
| `completo <repo> [url]` | Inventario file per file, ASVS esteso |
| `area <authz\|segreti\|dipendenze\|infra\|input\|ai> <repo>` | Solo l'area indicata, con la copertura dichiarata |

## Analisi
| Comando | Che cosa fa | Limite |
|---|---|---|
| `inventario <repo>` | Bozza di `endpoint-matrix.csv` | Euristico: ogni riga da verificare |
| `scanner <file…>` | Importa npm audit, SARIF, gitleaks, osv come candidati | Solo «ipotesi da validare», mai oltre «media» |
| `dinamico <config> <test>` | Prova gli accessi per identità | Solo localhost o host autorizzato; solo letture di default |
| `documentale <repo>` | Confronta i documenti con il codice | Stati: coerente, incoerente, obsoleto, duplicato, mancante |
| `privacy <repo>` | Passa a `gdpr-sentinel` | Serve la skill gemella |

## Verifica e consegna
| Comando | Che cosa fa |
|---|---|
| `revisione [cartella]` | Riferimenti inesistenti, severità senza prova, duplicati, domande del revisore |
| `report [cartella]` | Valida finding e copertura, produce sintesi e rapporto tecnico |
| `chiudi [cartella]` | Controllo di consegna in un solo passo; zero «falliti» prima di consegnare |
| `smentita [cartella]` | Un verificatore diverso dall'autore prova a confutare ogni finding alto o critico |
| `redazione [cartella]` | Cerca segreti e dati personali nei file e nel PDF; non stampa mai i valori |
| `pdf [cartella]` | Report PDF aziendale. Opzioni: `--sintetico`, `--lang en`, `--previous`, `--nis2` |
| `esporta [cartella]` | CSV, SARIF, Markdown per le issue |

## Dopo le correzioni
| Comando | Che cosa fa |
|---|---|
| `retest <ID> [branch]` | Ripete il caso originale, prova percorsi alternativi e altri ruoli |
| `confronta <vecchio> <nuovo>` | Risolti, nuovi, cambiati. «Risolto» non è «verificato» |
| `riprendi <vecchio> <nuovo>` | Audit ripetuto: riporta la copertura invariata, segna le voci cambiate e i buchi |
| `piano [cartella]` | Piano di intervento dai finding esistenti |
| `stato [cartella]` | Copertura e finding aperti, senza nuove attività |

## Da ricordare
- Stati dei finding: riprodotto dinamicamente · confermato da codice o configurazione · ipotesi da validare · non verificabile.
- Un test non eseguito resta «no» nella matrice: mai «provato» senza output.
- I file di audit e i report sono riservati: fuori da Git e dai repository pubblici.

Dettagli: [README](../README.it.md) · [automazioni](../references/automation.md) · [revisione](../references/review-pass.md) · [smentita](../references/refutation-pass.md)
