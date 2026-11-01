#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Riporta nei finding gli esiti della smentita scritti da un verificatore indipendente.

Uso:
    python3 apply_refutations.py <cartella-audit> [--esiti <cartella-audit>/smentite/esiti.json]

Perché: il verificatore lavora solo sui brief (smentite/smentita-<ID>.md) e non deve toccare findings.json, che è il
lavoro dell'autore. Scrive i suoi esiti in smentite/esiti.json; questo script li applica in modo meccanico:
  [{"id": "APP-002", "esito": "resiste|declassato|respinto", "verificatore": "...", "tentativi": ["...", ...],
    "severita": "media",            # solo per «declassato», se cambia la severità
    "stato": "ipotesi da validare",  # solo per «declassato», se cambia lo stato
    "motivo": "..."}]               # obbligatorio per «declassato» e «respinto»
- resiste: scrive il campo `smentita`;
- declassato: scrive `smentita`, aggiorna severità e/o stato e aggiunge il motivo a `motivazione_severita`;
- respinto: toglie il finding da findings.json e lo conserva in findings/respinti.json con l'esito (non si cancella nulla).
Cartelle di gdpr-sentinel (gaps.csv, senza findings.json): stessi esiti; «declassato» abbassa `priorita` (alta, media,
bassa) e/o `stato`; la colonna `smentita` diventa «esito | verificatore | tentativi»; i respinti vanno in gaps-respinti.csv.
Un esito per un ID inesistente, un esito non ammesso o un «declassato» che non abbassa niente è un errore: lo script
non scrive nulla finché gli esiti non sono tutti validi.
"""
import argparse
import csv
import json
import sys
from datetime import date
from pathlib import Path

SEV = ["critica", "alta", "media", "bassa", "informativa"]
STATI = ["riprodotto dinamicamente", "confermato da codice o configurazione", "ipotesi da validare", "non verificabile"]
PRIO = ["alta", "media", "bassa"]
GSTATI = ["riscontrato", "confermato da codice/config", "ipotesi", "non verificabile"]


def apply_gaps(audit: Path, es: list) -> int:
    gp = audit / "gaps.csv"
    rows = list(csv.DictReader(gp.open(encoding="utf-8")))
    fields = list(rows[0].keys()) if rows else []
    by = {r["id"]: r for r in rows}
    errs = []
    for e in es:
        r = by.get(e.get("id"))
        if r is None:
            errs.append(f"{e.get('id')}: nessun gap con questo ID"); continue
        if e.get("esito") not in ("resiste", "declassato", "respinto"):
            errs.append(f"{e['id']}: esito non ammesso «{e.get('esito')}»"); continue
        if not e.get("verificatore") or not e.get("tentativi"):
            errs.append(f"{e['id']}: mancano verificatore o tentativi")
        if e["esito"] in ("declassato", "respinto") and not e.get("motivo"):
            errs.append(f"{e['id']}: «{e['esito']}» senza motivo")
        if e["esito"] == "declassato":
            pr, st = e.get("priorita"), e.get("stato")
            cur_p, cur_s = (r.get("priorita") or "").strip().lower(), (r.get("stato") or "").strip()
            if pr and pr not in PRIO or st and st not in GSTATI:
                errs.append(f"{e['id']}: priorità o stato non ammessi")
            elif not ((pr and cur_p in PRIO and PRIO.index(pr) > PRIO.index(cur_p)) or (st and cur_s in GSTATI and GSTATI.index(st) > GSTATI.index(cur_s))):
                errs.append(f"{e['id']}: «declassato» deve abbassare priorità o stato")
    if errs:
        print("Nessuna modifica: correggi gli esiti.\n  " + "\n  ".join(errs))
        return 1
    n, respinti = {"resiste": 0, "declassato": 0, "respinto": 0}, []
    for e in es:
        r = by[e["id"]]
        n[e["esito"]] += 1
        tent = "; ".join(e["tentativi"]) + (f"; motivo: {e['motivo']}" if e.get("motivo") else "")
        r["smentita"] = f"{e['esito']} | {e['verificatore']} | {tent}".replace("\n", " ")
        if e["esito"] == "declassato":
            r["priorita"] = e.get("priorita") or r["priorita"]
            r["stato"] = e.get("stato") or r["stato"]
        elif e["esito"] == "respinto":
            respinti.append(r)
    if respinti:
        rp = audit / "gaps-respinti.csv"
        new = not rp.exists()
        with rp.open("a", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields)
            if new:
                w.writeheader()
            w.writerows(respinti)
        rows = [r for r in rows if r not in respinti]
    with gp.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader(); w.writerows(rows)
    print(f"smentite applicate ai gap: {n['resiste']} resistono, {n['declassato']} declassati, {n['respinto']} respinti"
          + (" (in gaps-respinti.csv)" if respinti else ""))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit", type=Path)
    ap.add_argument("--esiti", type=Path)
    a = ap.parse_args()
    fj = a.audit / "findings" / "findings.json"
    ej = a.esiti or a.audit / "smentite" / "esiti.json"
    if not ej.exists():
        sys.exit(f"manca {ej}")
    if not fj.exists() and (a.audit / "gaps.csv").exists():
        return apply_gaps(a.audit, json.loads(ej.read_text(encoding="utf-8")))
    if not fj.exists():
        sys.exit(f"manca {fj} (né gaps.csv)")
    fs = json.loads(fj.read_text(encoding="utf-8"))
    es = json.loads(ej.read_text(encoding="utf-8"))
    by = {f["id"]: f for f in fs}
    errs = []
    for e in es:
        f = by.get(e.get("id"))
        if f is None:
            errs.append(f"{e.get('id')}: nessun finding con questo ID"); continue
        if e.get("esito") not in ("resiste", "declassato", "respinto"):
            errs.append(f"{e['id']}: esito non ammesso «{e.get('esito')}»"); continue
        if not e.get("verificatore") or not e.get("tentativi"):
            errs.append(f"{e['id']}: mancano verificatore o tentativi")
        if e["esito"] in ("declassato", "respinto") and not e.get("motivo"):
            errs.append(f"{e['id']}: «{e['esito']}» senza motivo")
        if e["esito"] == "declassato":
            sv, st = e.get("severita"), e.get("stato")
            if sv and sv not in SEV or st and st not in STATI:
                errs.append(f"{e['id']}: severità o stato non ammessi")
            elif not ((sv and SEV.index(sv) > SEV.index(f["severita"])) or (st and STATI.index(st) > STATI.index(f["stato"]))):
                errs.append(f"{e['id']}: «declassato» deve abbassare severità o stato")
    if errs:
        print("Nessuna modifica: correggi gli esiti.\n  " + "\n  ".join(errs))
        return 1
    respinti, n = [], {"resiste": 0, "declassato": 0, "respinto": 0}
    for e in es:
        f = by[e["id"]]
        f["smentita"] = {"esito": e["esito"], "verificatore": e["verificatore"], "tentativi": e["tentativi"], "data": date.today().isoformat()}
        n[e["esito"]] += 1
        if e["esito"] == "declassato":
            old = f"{f['severita']} / {f['stato']}"
            f["severita"] = e.get("severita") or f["severita"]
            f["stato"] = e.get("stato") or f["stato"]
            f["motivazione_severita"] = (f.get("motivazione_severita") or "").rstrip() + f" Declassato dalla smentita (prima: {old}): {e['motivo']}"
            if f["stato"] in ("ipotesi da validare", "non verificabile") and f.get("confidenza") == "alta":
                f["confidenza"] = "media"   # lo schema non ammette confidenza alta su un'ipotesi
                f["motivazione_severita"] += " Confidenza portata da alta a media."
        elif e["esito"] == "respinto":
            f["smentita"]["tentativi"] = e["tentativi"] + [f"respinto: {e['motivo']}"]
            respinti.append(f)
    if respinti:
        rp = a.audit / "findings" / "respinti.json"
        old = json.loads(rp.read_text(encoding="utf-8")) if rp.exists() else []
        rp.write_text(json.dumps(old + respinti, indent=2, ensure_ascii=False), encoding="utf-8")
        fs = [f for f in fs if f not in respinti]
    fj.write_text(json.dumps(fs, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"smentite applicate: {n['resiste']} resistono, {n['declassato']} declassati, {n['respinto']} respinti"
          + (" (in findings/respinti.json)" if respinti else ""))
    senza = [f["id"] for f in fs if f.get("severita") in ("critica", "alta") and (f.get("smentita") or {}).get("esito") in (None, "non eseguita")]
    if senza:
        print(f"finding alti ancora senza smentita: {', '.join(senza)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
