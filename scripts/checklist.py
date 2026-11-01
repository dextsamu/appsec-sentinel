# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Lettura e verifica di checklist-rapido.csv (aree che ogni giro deve coprire o dichiarare non coperte).

Esiti ammessi: «esaminato» (con riferimenti), «parziale» (con riferimenti e motivo di ciò che manca),
«non esaminato» (con motivo), «non applicabile» (con motivo). Un'area vuota è un'area dimenticata.
"""
import csv
from pathlib import Path

ESITI = ("esaminato", "parziale", "non esaminato", "non applicabile")


def load(audit):
    p = Path(audit) / "checklist-rapido.csv"
    if not p.exists():
        return None
    with p.open(encoding="utf-8") as fh:
        return [r for r in csv.DictReader(fh) if (r.get("id") or "").strip()]


def problems(rows):
    """Restituisce (vuote, incoerenti): id delle aree non compilate e delle aree con esito senza giustificazione."""
    vuote, incoerenti = [], []
    for r in rows:
        e = (r.get("esito") or "").strip().lower()
        mot, ref = (r.get("motivo") or "").strip(), (r.get("riferimenti") or "").strip()
        if not e:
            vuote.append(r["id"])
        elif e not in ESITI:
            incoerenti.append(f"{r['id']} (esito «{e}» non ammesso)")
        elif e == "esaminato" and not ref:
            incoerenti.append(f"{r['id']} (esaminato senza riferimenti)")
        elif e == "parziale" and not (ref and mot):
            incoerenti.append(f"{r['id']} (parziale senza riferimenti o senza cosa manca)")
        elif e in ("non esaminato", "non applicabile") and not mot:
            incoerenti.append(f"{r['id']} ({e} senza motivo)")
    return vuote, incoerenti


def write(audit, rows):
    p = Path(audit) / "checklist-rapido.csv"
    fields = ["id", "area", "domanda", "come", "evidenza_minima", "esito", "motivo", "riferimenti"]
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows({k: r.get(k, "") for k in fields} for r in rows)
