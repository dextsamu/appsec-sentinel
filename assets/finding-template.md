# {ID} — {Titolo concreto del finding}

| Campo | Valore |
|---|---|
| ID | APP-001 |
| Categoria | es. Autorizzazione / BOLA |
| Asset · ambiente · versione | es. api.example.it · staging · commit abc1234 |
| **Stato** | riprodotto dinamicamente · confermato da codice o configurazione · ipotesi da validare · non verificabile |
| Severità | critica · alta · media · bassa · informativa — *motivazione sotto* |
| CWE | es. CWE-639 |
| CVSS | versione + vettore + punteggio (solo se i dati bastano; **mai** per la mera assenza di un documento) |
| Riferimenti | ASVS v?.?.? 4.2.1 · WSTG-ATHZ-04 · NIST … |
| Confidenza | alta · media · bassa |

## Attore, prerequisiti, ingresso
Chi può sfruttarlo, con quali privilegi/condizioni, da quale punto d'ingresso; quale confine di fiducia viene violato.

## Prova minima
File:righe, configurazione o richiesta/risposta **redatta** (nessun segreto, nessun dato personale reale). Spiega perché la prova sostiene la conclusione.

## Atteso / osservato
- Atteso:
- Osservato:
- Controllo negativo (se utile):

## Riproduzione
Passi eseguibili **solo nell'ambiente autorizzato**, con identità sintetiche.

## Impatto
- Reale (dimostrato):
- Potenziale:
- Condizioni che limitano lo sfruttamento:

## Motivazione della severità
Perché questa severità, in questo contesto.

## Intervento consigliato
- Correzione:
- Mitigazione temporanea:
- Dipendenze:
- Responsabile proposto · priorità:
- Test di regressione / retest:

## Limiti dell'analisi
Cosa non è stato verificato e perché.

---
*Se il finding riguarda privacy/compliance:* norma e articolo, fatto osservato, applicabilità, rischio per gli interessati, questione da sottoporre a titolare/DPO/legale.

## Valori ammessi nel JSON (validati da `scripts/validate_findings.py`)
- `prova.tipo`: `codice`, `configurazione`, `richiesta-risposta`, `log-tool`, `documento`, `nessuna`.
- `stato`: `riprodotto dinamicamente`, `confermato da codice o configurazione`, `ipotesi da validare`, `non verificabile`.
- `privacy` (solo per finding privacy/compliance): `norma_articolo`, `applicabilita`, `rischio_interessati`, `da_sottoporre_a` (`titolare`, `DPO`, `legale`, `fornitore`). Altri campi non sono ammessi: metti le note in `limiti`.
