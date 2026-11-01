#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Confronta due findings.json (audit precedente e retest): risolti, nuovi, invariati, cambiati.

Uso:
    python3 compare_audits.py precedente/findings.json nuovo/findings.json [--md confronto.md] [--json confronto.json]

Un finding è «risolto» solo se nel nuovo audit non c'è più E non c'è un finding con titolo molto simile
(il confronto usa l'ID; se l'ID cambia, la somiglianza del titolo solo a parità di asset o di file citati). «Risolto» non significa «verificato»: serve il retest indicato
nel finding. Segnala anche i cambi di stato (es. da «ipotesi da validare» a «riprodotto dinamicamente») e di severità.
"""
import argparse
import difflib
import json
from pathlib import Path

ORDER = {"critica": 0, "alta": 1, "media": 2, "bassa": 3, "informativa": 4}


def compare(old, new):
    res = {"risolti": [], "nuovi": [], "invariati": [], "cambiati": []}
    new_by_id = {f["id"]: f for f in new}
    matched = set()
    for o in old:
        n = new_by_id.get(o["id"])
        if not n:
            def same_thing(f):
                refs = {r for r in o["prova"].get("riferimenti_file", []) if ":" in r} & set(f["prova"].get("riferimenti_file", []))
                return o["asset"] == f["asset"] or (refs and o["categoria"] == f["categoria"])
            cands = [f for f in new if f["id"] not in matched and same_thing(f)]
            best = max(cands, key=lambda f: difflib.SequenceMatcher(None, o["titolo"].lower(), f["titolo"].lower()).ratio(), default=None)
            if best and difflib.SequenceMatcher(None, o["titolo"].lower(), best["titolo"].lower()).ratio() > 0.8:
                n = best
        if not n:
            res["risolti"].append(o); continue
        matched.add(n["id"])
        ch = []
        if o["severita"] != n["severita"]:
            ch.append(f"severità {o['severita']} → {n['severita']}")
        if o["stato"] != n["stato"]:
            ch.append(f"stato «{o['stato']}» → «{n['stato']}»")
        (res["cambiati"] if ch else res["invariati"]).append({"id": o["id"], "nuovo_id": n["id"], "titolo": n["titolo"], "severita": n["severita"], "cambi": ch})
    res["nuovi"] = [f for f in new if f["id"] not in matched and f["id"] not in {o["id"] for o in old}]
    return res


def to_md(r):
    L = ["# Confronto tra audit", "",
         f"- Risolti (non più presenti): **{len(r['risolti'])}**", f"- Nuovi: **{len(r['nuovi'])}**",
         f"- Cambiati: **{len(r['cambiati'])}**", f"- Invariati: **{len(r['invariati'])}**", ""]
    for key, label in (("risolti", "Risolti: da confermare con il retest del finding"), ("nuovi", "Nuovi"), ("cambiati", "Cambiati"), ("invariati", "Ancora aperti")):
        if r[key]:
            L.append(f"## {label}")
            for f in r[key]:
                extra = f" ({'; '.join(f['cambi'])})" if f.get("cambi") else ""
                L.append(f"- **{f['id']}** [{f.get('severita', '')}] {f['titolo']}{extra}")
            L.append("")
    L.append("_«Risolto» significa assente nel nuovo audit, non verificato: esegui il retest indicato in ogni finding._")
    return "\n".join(L)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("old", type=Path)
    ap.add_argument("new", type=Path)
    ap.add_argument("--md", type=Path)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    r = compare(json.loads(a.old.read_text(encoding="utf-8")), json.loads(a.new.read_text(encoding="utf-8")))
    md = to_md(r)
    print(md)
    if a.md:
        a.md.write_text(md, encoding="utf-8")
    if a.json:
        a.json.write_text(json.dumps(r, ensure_ascii=False, indent=1), encoding="utf-8")


if __name__ == "__main__":
    main()
