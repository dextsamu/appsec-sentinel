#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Misura l'inventario delle route su un'app vulnerabile pubblica, contro un elenco curato di endpoint noti.

Uso:
    git clone --depth 1 https://github.com/juice-shop/juice-shop /tmp/juice-shop
    python3 tests/benchmark/run_benchmark.py /tmp/juice-shop [--truth tests/benchmark/juice-shop.json] [--script scripts/inventory_routes.py]

Misure:
  scoperta        quanti endpoint dell'elenco compaiono nell'inventario (con il metodo giusto)
  richiamo        quanti degli endpoint noti senza autenticazione sono segnalati «NESSUNA AUTH EVIDENTE»
  falsi allarmi   quanti degli endpoint noti autenticati sono segnalati senza auth (da correggere)
  rumore          quante route l'inventario segnala in tutto: la precisione sull'elenco completo NON è misurabile
                  senza una verità completa, e il numero va letto come «candidati da verificare»
Limite: l'elenco è curato da noi (non ufficiale) e piccolo: è un termometro, non una certificazione.
"""
import argparse
import csv
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def norm(s):
    return [("*" if x.startswith(":") else x) for x in s.strip("/").split("/") if x]


def find(rows, ep, meth):
    return [r for r in rows if norm(r["endpoint"]) == norm(ep) and r["metodo"] in (meth, "ANY")]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", type=Path)
    ap.add_argument("--truth", type=Path, default=HERE / "juice-shop.json")
    ap.add_argument("--script", type=Path, default=ROOT / "scripts" / "inventory_routes.py")
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    truth = json.loads(a.truth.read_text(encoding="utf-8"))
    out = Path(tempfile.mkdtemp()) / "inv.csv"
    r = subprocess.run([sys.executable, str(a.script), str(a.repo), "--out", str(out)], capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout + r.stderr)
        return 1
    rows = list(csv.DictReader(out.open(encoding="utf-8")))
    flagged = [x for x in rows if x["identita"] == "NESSUNA AUTH EVIDENTE"]
    disc = rec = 0
    miss, wrong = [], []
    for ep, m in truth["senza_auth"]:
        f = find(rows, ep, m)
        disc += bool(f)
        if f and any(x["identita"] == "NESSUNA AUTH EVIDENTE" for x in f):
            rec += 1
        else:
            miss.append(f"{m} {ep}" + (" (non trovata)" if not f else " (non segnalata)"))
    fa = 0
    for ep, m in truth["con_auth"]:
        f = find(rows, ep, m)
        disc += bool(f)
        if f and all(x["identita"] == "NESSUNA AUTH EVIDENTE" for x in f):
            fa += 1
            wrong.append(f"{m} {ep}")
    n_u, n_a = len(truth["senza_auth"]), len(truth["con_auth"])
    res = {"app": truth["app"], "route_in_inventario": len(rows), "segnalate_senza_auth": len(flagged),
           "scoperta": f"{disc}/{n_u + n_a}", "richiamo_senza_auth": f"{rec}/{n_u}", "falsi_allarmi_su_autenticati": f"{fa}/{n_a}",
           "mancano": miss, "falsi_allarmi": wrong}
    print(f"{truth['app']} · inventario con {a.script.name}")
    print(f"  route in inventario: {len(rows)}; segnalate «senza auth evidente»: {len(flagged)}")
    print(f"  scoperta degli endpoint noti: {disc}/{n_u + n_a}")
    print(f"  richiamo sui senza-auth noti: {rec}/{n_u}" + (f"; mancano: {', '.join(miss)}" if miss else ""))
    print(f"  falsi allarmi sugli autenticati noti: {fa}/{n_a}" + (f": {', '.join(wrong)}" if wrong else ""))
    print("  " + truth["nota_sulla_verita"])
    if a.json:
        a.json.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
