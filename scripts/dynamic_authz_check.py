#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Verifica dinamica di accesso e autorizzazione su un'istanza LOCALE o esplicitamente autorizzata.

Uso:
    python3 dynamic_authz_check.py --config authz-config.json --tests authz-tests.csv [--out risultati.csv]
                                   [--update-matrix endpoint-matrix.csv] [--allow-host staging.example.test]
                                   [--allow-state-changing]
    python3 dynamic_authz_check.py --skeleton endpoint-matrix.csv > authz-tests.csv   (bozza dei test)

authz-config.json:
    {"base_url": "http://127.0.0.1:3000", "timeout": 5, "max_requests": 200, "delay_ms": 100,
     "identities": {"anonimo": {}, "utente_a": {"headers": {"Authorization": "env:TOKEN_A"}},
                    "utente_b": {"cookies": {"session": "env:COOKIE_B"}}}}
I valori "env:NOME" sono letti dall'ambiente: nessuna credenziale finisce in file o report.

authz-tests.csv: endpoint,metodo,identita,atteso,finding_id   (atteso: elenco di status accettati, es. "401|403|404")

Garanzie di sicurezza (non aggirabili da configurazione):
  - host ammessi di default: localhost, 127.0.0.1, ::1, *.localhost, *.test. Altri host solo con --allow-host
    esplicito e dopo conferma scritta nelle regole di ingaggio;
  - solo metodi sicuri (GET, HEAD, OPTIONS) salvo --allow-state-changing (usare solo su dati sintetici);
  - tetto di richieste, pausa tra richieste, nessun redirect seguito, nessun corpo di risposta salvato
    (solo status e lunghezza), nessun brute force: una richiesta per test.
Un test eseguito scrive l'esito reale; un test non eseguito resta "no". Mai dichiarare «provato» senza questo output.
"""
import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SAFE = {"GET", "HEAD", "OPTIONS"}
LOCAL_SUFFIX = (".localhost", ".test")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def host_allowed(host, extra):
    h = (host or "").lower()
    return h in ("localhost", "127.0.0.1", "::1", "[::1]") or h.endswith(LOCAL_SUFFIX) or h in extra


def resolve(v):
    if isinstance(v, str) and v.startswith("env:"):
        val = os.environ.get(v[4:])
        if val is None:
            sys.exit(f"variabile d'ambiente mancante: {v[4:]}")
        return val
    return v


def skeleton(matrix: Path):
    rows = list(csv.DictReader(matrix.open(encoding="utf-8")))
    w = csv.writer(sys.stdout)
    w.writerow(["endpoint", "metodo", "identita", "atteso", "finding_id"])
    for r in rows:
        ep, m = r["endpoint"], r["metodo"].upper()
        if "{" in ep or m not in SAFE or not r.get("identita", "").upper().startswith("NESSUNA"):
            continue
        w.writerow([ep, m, "anonimo", "401|403|404", r.get("finding_id", "")])
    print("# Bozza: solo GET senza auth evidente e senza parametri. Aggiungi i test per ruoli e tenant a mano.", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", type=Path)
    ap.add_argument("--tests", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--update-matrix", type=Path)
    ap.add_argument("--allow-host", action="append", default=[])
    ap.add_argument("--allow-state-changing", action="store_true")
    ap.add_argument("--skeleton", type=Path)
    a = ap.parse_args()
    if a.skeleton:
        return skeleton(a.skeleton)
    if not (a.config and a.tests):
        ap.error("servono --config e --tests (oppure --skeleton)")
    cfg = json.loads(a.config.read_text(encoding="utf-8"))
    base = cfg["base_url"].rstrip("/")
    host = urllib.parse.urlparse(base).hostname
    if not host_allowed(host, [h.lower() for h in a.allow_host]):
        sys.exit(f"RIFIUTATO: l'host «{host}» non è locale né ammesso con --allow-host. Nessuna richiesta inviata.")
    ident = cfg.get("identities", {})
    tests = list(csv.DictReader(a.tests.open(encoding="utf-8")))
    cap = int(cfg.get("max_requests", 200))
    if len(tests) > cap:
        sys.exit(f"RIFIUTATO: {len(tests)} test superano il tetto di {cap} richieste (max_requests).")
    opener = urllib.request.build_opener(NoRedirect)
    results = []
    for t in tests:
        m = t["metodo"].upper()
        if m not in SAFE and not a.allow_state_changing:
            results.append({**t, "eseguito": "no", "status": "", "esito": "SALTATO: metodo con effetti di stato, serve --allow-state-changing"})
            continue
        i = ident.get(t["identita"])
        if i is None:
            results.append({**t, "eseguito": "no", "status": "", "esito": f"SALTATO: identità «{t['identita']}» non definita"})
            continue
        headers = {k: str(resolve(v)) for k, v in i.get("headers", {}).items()}
        if i.get("cookies"):
            headers["Cookie"] = "; ".join(f"{k}={resolve(v)}" for k, v in i["cookies"].items())
        req = urllib.request.Request(base + t["endpoint"], method=m, headers={"User-Agent": "appsec-sentinel/1.0", **headers})
        status, length = "", ""
        try:
            with opener.open(req, timeout=float(cfg.get("timeout", 5))) as r:
                status, length = r.status, len(r.read(65536))
        except urllib.error.HTTPError as e:
            status, length = e.code, len(e.read(65536))
        except Exception as e:
            results.append({**t, "eseguito": "no", "status": "", "esito": f"ERRORE di rete: {type(e).__name__}"})
            continue
        ok_set = {s.strip() for s in t["atteso"].replace(",", "|").split("|") if s.strip()}
        verdict = "conforme all'atteso" if str(status) in ok_set else f"DIFFORME: atteso {t['atteso']}, ottenuto {status}"
        results.append({**t, "eseguito": "si", "status": status, "lunghezza": length, "esito": verdict})
        time.sleep(float(cfg.get("delay_ms", 100)) / 1000)
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    fields = ["endpoint", "metodo", "identita", "atteso", "finding_id", "eseguito", "status", "lunghezza", "esito"]
    out = a.out or a.tests.with_name("authz-risultati.csv")
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(results)
    done = sum(r["eseguito"] == "si" for r in results)
    diff = [r for r in results if str(r["esito"]).startswith("DIFFORME")]
    print(f"{stamp}  richieste eseguite: {done}/{len(results)}  difformi dall'atteso: {len(diff)}  -> {out}")
    for r in diff:
        print(f"  DIFFORME {r['metodo']} {r['endpoint']} come {r['identita']}: ottenuto {r['status']} (atteso {r['atteso']})")
    if a.update_matrix:
        rows = list(csv.DictReader(a.update_matrix.open(encoding="utf-8")))
        names = list(rows[0].keys()) if rows else []
        by = {(r["endpoint"], r["metodo"].upper()): r for r in rows}
        def seg(ep):
            return [x for x in urllib.parse.urlsplit(ep).path.strip("/").split("/") if x]
        def is_param(x):
            return x.startswith(":") or (x[:1] in "{<[" and x[-1:] in "}>]")
        def match(ep, meth):   # stessa route anche se il test usa un valore (/basket/6) e la matrice il parametro (/basket/:id)
            if (ep, meth) in by:
                return by[(ep, meth)]
            t = seg(ep)
            for (mep, mm), row in by.items():
                m = seg(mep)
                if mm in (meth, "ANY") and len(m) == len(t) and all(x == y or is_param(y) for x, y in zip(t, m)):
                    return row
            return None
        for r in results:
            row = match(r["endpoint"], r["metodo"].upper())
            if row and r["eseguito"] == "si":
                row["test_eseguito"] = "si"
                prev = row.get("esito") or ""
                cur = f"{r['identita']} {r['endpoint']}: {r['status']} ({r['esito']}) · {stamp[:10]}"
                row["esito"] = cur if not prev or prev.startswith("ESEMPIO") else f"{prev}; {cur}"   # più identità sulla stessa route
        with a.update_matrix.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=names); w.writeheader(); w.writerows(rows)
        print(f"matrice aggiornata: {a.update_matrix}")
    sys.exit(2 if diff else 0)


if __name__ == "__main__":
    main()
