# Passaggio di revisione dei finding

Serve a trovare falsi positivi e affermazioni non provate **prima** di consegnare. Va fatto da una prospettiva diversa da quella di chi ha scritto il finding: un secondo passaggio separato, o un secondo agente con lo stesso perimetro e gli stessi divieti, senza nuove autorizzazioni.

1. Esegui `verify_findings.py findings/findings.json --repo <codice> --md revisione.md`.
2. Per ogni finding rispondi alle domande che lo script stampa: raggiungibilità e ambiente; mitigazioni a monte che il codice letto non mostra (proxy, WAF, rete); se la prova dimostra la conclusione o solo la presenza di un pattern; se lo stato è quello davvero raggiunto; se severità e impatto dipendono da condizioni non verificate.
3. Per ogni rilievo: correggi il finding, declassalo, cambia stato, oppure documenta perché resta com'è.
4. Cerca anche ciò che manca: aree non inventariate, ruoli o tenant non provati, endpoint senza test. Riportali nella copertura come «ignoto» con il motivo.
5. Rilancia `validate_findings.py` e conserva `revisione.md` nella cartella di audit.

Per i finding alti o critici segui anche `refutation-pass.md`: a confutarli deve essere un verificatore diverso dall'autore.

Un finding che non supera la revisione non va nel report come «confermato».
