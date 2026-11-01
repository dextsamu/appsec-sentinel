#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Esporta findings.json in CSV, SARIF 2.1.0 o Markdown pronto per le issue.

Uso:
    python3 export_findings.py findings/findings.json --csv out.csv
    python3 export_findings.py findings/findings.json --sarif out.sarif
    python3 export_findings.py findings/findings.json --md-dir issue/        (un file .md per finding)

Esporta solo i campi già redatti dei finding: se i file di audit sono riservati, lo sono anche gli export.
Non caricare lo SARIF su servizi esterni (es. code scanning di un repository pubblico) senza autorizzazione.
"""
import argparse
import csv
import json
import re
from pathlib import Path

LEVEL = {"critica": "error", "alta": "error", "media": "warning", "bassa": "note", "informativa": "note"}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", type=Path)
    ap.add_argument("--csv", type=Path)
    ap.add_argument("--sarif", type=Path)
    ap.add_argument("--md-dir", type=Path)
    a = ap.parse_args()
    fs = json.loads(a.findings.read_text(encoding="utf-8"))
    if a.csv:
        with a.csv.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["id", "severita", "stato", "titolo", "categoria", "asset", "cwe", "file", "correzione", "retest"])
            for f in fs:
                w.writerow([f["id"], f["severita"], f["stato"], f["titolo"], f["categoria"], f["asset"], " ".join(f.get("cwe", [])),
                            "; ".join(f["prova"].get("riferimenti_file", [])), f["intervento"]["correzione"], f["retest"]])
        print(f"CSV: {a.csv}")
    if a.sarif:
        rules, results = [], []
        for f in fs:
            rules.append({"id": f["id"], "name": re.sub(r"\W+", "", f["titolo"].title())[:60], "shortDescription": {"text": f["titolo"]},
                          "properties": {"stato": f["stato"], "confidenza": f["confidenza"], "tags": f.get("cwe", [])}})
            locs = []
            for ref in f["prova"].get("riferimenti_file", []):
                path, _, line = ref.partition(":")
                reg = {"region": {"startLine": int(line)}} if line.isdigit() else {}
                locs.append({"physicalLocation": {"artifactLocation": {"uri": path}, **reg}})
            results.append({"ruleId": f["id"], "level": LEVEL.get(f["severita"], "note"),
                            "message": {"text": f"{f['titolo']} [{f['stato']}] {f['osservato']}"[:900]}, "locations": locs or [{"physicalLocation": {"artifactLocation": {"uri": f["asset"]}}}]})
        doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
               "runs": [{"tool": {"driver": {"name": "appsec-sentinel", "informationUri": "https://github.com/dextsamu/appsec-sentinel", "rules": rules}}, "results": results}]}
        a.sarif.write_text(json.dumps(doc, ensure_ascii=False, indent=1), encoding="utf-8")
        print(f"SARIF: {a.sarif}")
    if a.md_dir:
        a.md_dir.mkdir(parents=True, exist_ok=True)
        for f in fs:
            imp = f["impatto"]
            body = (f"# {f['id']} · {f['titolo']}\n\n**Severità:** {f['severita']} · **Stato:** {f['stato']} · **Confidenza:** {f['confidenza']}\n\n"
                    f"## Prova\n{f['prova']['descrizione']}\n\nFile: {', '.join(f['prova'].get('riferimenti_file', [])) or 'n/d'}\n\n"
                    f"## Atteso / osservato\n- Atteso: {f['atteso']}\n- Osservato: {f['osservato']}\n\n"
                    f"## Impatto\n- Reale: {imp['reale']}\n- Potenziale: {imp['potenziale']}\n\n"
                    f"## Correzione\n{f['intervento']['correzione']}\n\n**Subito:** {f['intervento'].get('mitigazione_temporanea', '')}\n\n"
                    f"## Retest\n{f['retest']}\n\n## Limiti\n{f['limiti']}\n")
            (a.md_dir / f"{f['id']}.md").write_text(body, encoding="utf-8")
        print(f"Markdown: {len(fs)} file in {a.md_dir}")


if __name__ == "__main__":
    main()
