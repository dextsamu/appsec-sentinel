#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Banco di prova pubblico per l'agente: un'app finta con 16 difetti noti e 5 esche, e il punteggio di un audit.

Uso:
    python3 tests/bench-app/score_bench.py prepare <cartella>             # crea <cartella>/bench-app (repository Git)
    python3 tests/bench-app/score_bench.py score <audit> [<audit> …]      # richiamo, difetti alti, falsi allarmi

`prepare` copia l'app senza la verità e senza commenti che indichino i difetti, genera a caso i valori dei segreti
e crea una storia Git di due commit (un segreto aggiunto e poi rimosso). L'agente va lanciato dentro
<cartella>/bench-app, con l'audit FUORI da quella cartella.

`score` legge findings/findings.json di ogni audit:
  - un difetto è trovato se un finding cita uno dei suoi file e il testo contiene una delle sue parole chiave;
  - un'esca è un falso allarme se un finding la cita con severità media o superiore;
  - con più audit: tabella difetto × giro e accordo.
Limiti: il riconoscimento è meccanico (un finding che cita il file giusto con parole sbagliate non conta, e viceversa);
i difetti sono quelli che conosciamo, quindi il richiamo misura la skill su queste classi, non su tutto.
"""
import json
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent   # lo stesso script serve bench-app, bench-php e bench-django (template e truth.json accanto)
TRUTH = json.loads((HERE / "truth.json").read_text(encoding="utf-8"))
SEV = {"critica": 0, "alta": 1, "media": 2, "bassa": 3, "informativa": 4}


def prepare(dest):
    app = Path(dest) / "bench-app"
    if app.exists():
        sys.exit(f"esiste già: {app}")
    shutil.copytree(HERE / "template", app)
    for b in app.rglob("*.bench"):   # manifest salvati come *.bench nel repository (dipendenze vulnerabili apposta)
        b.rename(b.with_suffix(""))
    for f in app.rglob("*"):   # segnaposto __NOME__ del modello → valori casuali (segreti «veri» diversi a ogni prova)
        if f.is_file() and f.suffix in {".yml", ".yaml", ".env", ".php", ".py", ".ts", ".js", ".json", ""}:
            s = f.read_text(encoding="utf-8", errors="replace")
            if re.search(r"__[A-Z_]{4,}__", s):
                f.write_text(re.sub(r"__[A-Z_]{4,}__", lambda m: secrets.token_hex(24), s), encoding="utf-8")
    g = lambda *a: subprocess.run(["git", "-C", str(app), "-c", "user.email=dev@example.test", "-c", "user.name=dev", *a],
                                  capture_output=True, text=True, check=True)
    g("init", "-q")
    (app / "scripts").mkdir(exist_ok=True)
    (app / "scripts" / "rotate-cron.sh").write_text("#!/bin/sh\nexport CRON_SECRET=" + secrets.token_urlsafe(32) +
                                                    "\ncurl -s -H \"Authorization: Bearer $CRON_SECRET\" https://gestionale.example.org/api/cron/reminder\n",
                                                    encoding="utf-8")
    g("add", "-A"); g("commit", "-qm", "versione iniziale")
    (app / "scripts" / "rotate-cron.sh").unlink()
    (app / "scripts" / ".gitkeep").write_text("", encoding="utf-8")
    g("add", "-A"); g("commit", "-qm", "pulizia script")
    print(f"pronto: {app}\nLancia l'agente dentro questa cartella; crea l'audit fuori (es. {Path(dest) / 'audit-bench-A'}).")


def load(audit):
    for p in (Path(audit) / "findings" / "findings.json", Path(audit) / "findings.json"):
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    sys.exit(f"nessun findings.json in {audit}")


def text(f):
    return " ".join(str(x) for x in (f.get("titolo"), f.get("osservato"), f.get("categoria"), (f.get("prova") or {}).get("descrizione"))).lower()


def cites(f, files):
    refs = [re.sub(r"^\./", "", str(r).split(":")[0]) for r in (f.get("prova") or {}).get("riferimenti_file") or []]
    refs.append(str(f.get("asset") or ""))
    return any(r.endswith(x) or x in r for r in refs for x in files)


def score_one(fs):
    found, fa, used = {}, {}, set()
    for t in TRUTH["difetti"]:
        hit = [f["id"] for f in fs if cites(f, t["file"]) and re.search(t["parole"], text(f))]
        if hit:
            found[t["id"]] = hit; used.update(hit)
    for d in TRUTH["esche"]:
        claim = lambda f: " ".join(str(x) for x in (f.get("titolo"), f.get("osservato"))).lower()   # solo ciò che il finding afferma
        hit = [f["id"] for f in fs if cites(f, d["file"]) and re.search(d["parole"], claim(f)) and SEV.get(f.get("severita"), 9) <= 2]
        if hit:
            fa[d["id"]] = hit
    extra = [f for f in fs if f["id"] not in used and not any(f["id"] in v for v in fa.values())]
    return found, fa, extra


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("prepare", "score"):
        print(__doc__); return 2
    if sys.argv[1] == "prepare":
        prepare(sys.argv[2]); return 0
    audits = sys.argv[2:]
    alti = {t["id"] for t in TRUTH["difetti"] if t["alto"]}
    n = len(TRUTH["difetti"])
    res = {}
    for a in audits:
        fs = load(a)
        found, fa, extra = score_one(fs)
        res[a] = found
        print(f"== {a}")
        print(f"  difetti trovati: {len(found)}/{n} · alti: {len(alti & set(found))}/{len(alti)} · falsi allarmi sulle esche: {len(fa)}/{len(TRUTH['esche'])} · finding fuori elenco: {len(extra)}")
        miss = [t for t in TRUTH["difetti"] if t["id"] not in found]
        for t in miss:
            print(f"  - mancato {t['id']} ({t['area']}{', alto' if t['alto'] else ''}): {t['titolo']}")
        for d, ids in fa.items():
            print(f"  ! falso allarme {d}: {next(x['titolo'] for x in TRUTH['esche'] if x['id'] == d)} ({', '.join(ids)})")
        for f in extra[:8]:
            print(f"  ? fuori elenco {f['id']} [{f.get('severita')}]: {f.get('titolo', '')[:90]} (da valutare a mano: difetto non piantato o rumore)")
    if len(audits) > 1:
        print("\n== difetto × giro")
        for t in TRUTH["difetti"]:
            print(f"  {t['id']} {'A' if t['alto'] else ' '} " + " ".join("x" if t["id"] in res[a] else "." for a in audits) + f"  {t['titolo'][:70]}")
        sets = [set(res[a]) for a in audits]
        union, inter = set().union(*sets), set.intersection(*sets)
        print(f"accordo sui difetti noti: {len(inter)}/{len(union)} trovati da tutti i giri · trovati da almeno un giro: {len(union)}/{n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
