#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Riporta ai valori canonici (italiani) i valori in inglese scritti in un audit, in modo che gli script li verifichino.

Uso:
    python3 canonicalize.py <cartella-audit> [--dry-run]
English: converts English enum values (e.g. "dynamically reproduced", "high") in an audit folder to the canonical
Italian values the scripts check. The free text is never touched.

Cosa tocca (solo valori enumerati, mai testo libero, mai i nomi dei campi):
  findings/findings.json  stato, severita, confidenza, prova.tipo, intervento.priorita, smentita.esito,
                          privacy.da_sottoporre_a
  gdpr-matrix.csv         stato e, nella colonna smentita, l'esito iniziale («holds | verifier | attempts»)
È idempotente: i valori già canonici non cambiano. Con --dry-run elenca soltanto. Esce con 0; stampa quante
sostituzioni ha fatto o farebbe e i valori inglesi che non riconosce (da correggere a mano).
"""
import argparse
import csv
import json
import sys
from pathlib import Path

STATO = {"dynamically reproduced": "riprodotto dinamicamente", "confirmed from code or configuration": "confermato da codice o configurazione",
         "confirmed from code": "confermato da codice o configurazione", "hypothesis to validate": "ipotesi da validare", "hypothesis": "ipotesi da validare",
         "not verifiable": "non verificabile", "unverifiable": "non verificabile"}
SEV = {"critical": "critica", "high": "alta", "medium": "media", "low": "bassa", "informational": "informativa", "info": "informativa"}
CONF = {"high": "alta", "medium": "media", "low": "bassa"}
TIPO = {"code": "codice", "configuration": "configurazione", "config": "configurazione", "request-response": "richiesta-risposta",
        "tool-log": "log-tool", "document": "documento", "none": "nessuna"}
PRIO = {"immediate": "immediata", "high": "alta", "medium": "media", "low": "bassa"}
ESITO = {"holds": "resiste", "withstands": "resiste", "downgraded": "declassato", "rejected": "respinto", "not performed": "non eseguita", "not done": "non eseguita"}
DEST = {"controller": "titolare", "dpo": "DPO", "legal": "legale", "counsel": "legale", "supplier": "fornitore", "vendor": "fornitore"}
GDPR_STATO = {"found": "riscontrato", "confirmed from code/config": "confermato da codice/config", "confirmed from code or configuration": "confermato da codice/config",
              "hypothesis": "ipotesi", "not verifiable": "non verificabile", "unverifiable": "non verificabile"}
CANON = {"stato": set(STATO.values()), "severita": set(SEV.values()), "confidenza": set(CONF.values())}


def conv(val, table, canon, log, where):
    """Restituisce il valore canonico; registra le sostituzioni e i valori non riconosciuti."""
    if not isinstance(val, str):
        return val
    k = val.strip().lower()
    if val in canon or k in {c.lower() for c in canon}:
        return val
    if k in table:
        log["fatte"].append(f"{where}: «{val}» -> «{table[k]}»")
        return table[k]
    log["ignote"].append(f"{where}: «{val}»")
    return val


def do_findings(path: Path, dry, log):
    data = json.loads(path.read_text(encoding="utf-8"))
    for f in data:
        i = f.get("id", "?")
        f["stato"] = conv(f.get("stato"), STATO, set(STATO.values()), log, f"{i}.stato")
        f["severita"] = conv(f.get("severita"), SEV, set(SEV.values()), log, f"{i}.severita")
        if "confidenza" in f:
            f["confidenza"] = conv(f["confidenza"], CONF, set(CONF.values()), log, f"{i}.confidenza")
        if isinstance(f.get("prova"), dict) and "tipo" in f["prova"]:
            f["prova"]["tipo"] = conv(f["prova"]["tipo"], TIPO, set(TIPO.values()), log, f"{i}.prova.tipo")
        if isinstance(f.get("intervento"), dict) and "priorita" in f["intervento"]:
            f["intervento"]["priorita"] = conv(f["intervento"]["priorita"], PRIO, set(PRIO.values()), log, f"{i}.intervento.priorita")
        if isinstance(f.get("smentita"), dict) and "esito" in f["smentita"]:
            f["smentita"]["esito"] = conv(f["smentita"]["esito"], ESITO, set(ESITO.values()), log, f"{i}.smentita.esito")
        if isinstance(f.get("privacy"), dict) and isinstance(f["privacy"].get("da_sottoporre_a"), list):
            f["privacy"]["da_sottoporre_a"] = [conv(x, DEST, {"titolare", "DPO", "legale", "fornitore"}, log, f"{i}.privacy.da_sottoporre_a") for x in f["privacy"]["da_sottoporre_a"]]
    if log["fatte"] and not dry:
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def do_matrix(path: Path, dry, log):
    with path.open(newline="", encoding="utf-8") as fh:
        rd = csv.DictReader(fh)
        fields, rows = rd.fieldnames or [], list(rd)
    before = len(log["fatte"])
    for r in rows:
        c = r.get("controllo", "?")
        r["stato"] = conv(r.get("stato", ""), GDPR_STATO, set(GDPR_STATO.values()), log, f"{c}.stato")
        sm = (r.get("smentita") or "")
        if sm.strip():
            head, sep, rest = sm.partition("|")
            new = conv(head.strip(), ESITO, set(ESITO.values()), log, f"{c}.smentita")
            if new != head.strip():
                r["smentita"] = new + (" |" + rest if sep else "")
    if len(log["fatte"]) > before and not dry:
        with path.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
            w.writeheader(); w.writerows(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit", type=Path)
    ap.add_argument("--dry-run", action="store_true", help="elenca senza scrivere / list only")
    a = ap.parse_args()
    log = {"fatte": [], "ignote": []}
    fj, gm = a.audit / "findings" / "findings.json", a.audit / "gdpr-matrix.csv"
    if not fj.exists() and not gm.exists():
        print("ERRORE: né findings/findings.json né gdpr-matrix.csv nella cartella", file=sys.stderr)
        return 1
    if fj.exists():
        do_findings(fj, a.dry_run, log)
    if gm.exists():
        do_matrix(gm, a.dry_run, log)
    verb = "farebbe" if a.dry_run else "fatte"
    print(f"sostituzioni {verb}: {len(log['fatte'])}")
    for l in log["fatte"]:
        print("  " + l)
    if log["ignote"]:
        print(f"valori non canonici e non riconosciuti: {len(log['ignote'])} (correggi a mano; ammessi nei file schema/guide)")
        for l in log["ignote"][:20]:
            print("  ? " + l)
    return 0


if __name__ == "__main__":
    sys.exit(main())
