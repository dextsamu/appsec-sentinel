# Esempi

`findings.example.json` è un record minimo di riferimento per la forma del JSON (`assets/finding.schema.json`): le verifiche automatiche del repository lo validano a ogni modifica. Per un esempio vero, vedi `collaudo-rapido/`.

Per validarlo a mano:

```bash
pip install jsonschema
python3 scripts/validate_findings.py examples/findings.example.json
```

## `collaudo-rapido/`
Esempio **anonimizzato, ricavato da un caso reale**: cinque finding validati, copertura con denominatori e svolgimento del collaudo. Vedi il suo [README](collaudo-rapido/README.md). La cartella è una cartella di audit completa (finding, matrici, `meta.json`) e il PDF d'esempio è generato da `scripts/build_report_pdf.py`.
