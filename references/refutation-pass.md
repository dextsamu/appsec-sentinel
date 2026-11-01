# Smentita dei finding alti

Un finding scritto da chi l'ha trovato tende a sembrare solido a chi l'ha scritto. Prima del report, ogni finding **alto o critico** passa da un verificatore diverso dall'autore, il cui unico compito è **dimostrare che è sbagliato**: non cercare conferme.

## Chi può farlo
- un secondo agente con lo stesso perimetro e gli stessi divieti, che non ha visto il ragionamento dell'autore;
- una sessione nuova (altra conversazione o altro agente) che riparte dal solo brief: un secondo passaggio nella **stessa** conversazione non conta, perché il ragionamento dell'autore è ancora lì;
- una persona del team.
Nessuna di queste figure amplia il mandato: non si fanno test nuovi se non erano già autorizzati. Se non c'è nessun verificatore indipendente, registra `esito: non eseguita` e dichiaralo nel report come limite.

## Procedura
1. `verify_findings.py findings/findings.json --repo <codice> --brief-dir smentite/` crea un brief per ogni finding alto o critico. Il brief contiene l'affermazione, l'attore dichiarato e i riferimenti, **non** la motivazione dell'autore.
2. Il verificatore prova le ipotesi di smentita: codice non raggiungibile in produzione (test, esempio, build di sviluppo); controllo a monte (middleware, proxy, WAF, rete, flag); attore che non ha quell'ingresso o quei privilegi; impatto che richiede condizioni non verificate; severità gonfiata; stato dichiarato superiore a quello raggiunto.
3. Esito, da copiare nel campo `smentita` del finding:
   - `resiste`: nessuna smentita valida; elenca i tentativi fatti;
   - `declassato`: riduci severità o stato e aggiorna la motivazione;
   - `respinto`: falso positivo; il finding esce dal report (conserva la nota nel registro);
   - `non eseguita`: nessun verificatore indipendente.
4. Rilancia `validate_findings.py` e `verify_findings.py`: un finding alto senza smentita resta un rilievo.

## Chi non può farlo
Lo stesso agente che ha scritto il finding, nella stessa conversazione, non è un verificatore indipendente. In quel caso scrivi `non eseguita` e dichiaralo: è meglio di una smentita di facciata.

## Limiti
La smentita riduce i falsi positivi, non garantisce che un finding «resista» perché è vero: dipende da cosa il verificatore ha davvero controllato. Riportalo nei limiti del finding.
