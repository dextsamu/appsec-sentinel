#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Copertura cumulativa tra audit successivi: riporta avanti ciò che è ancora valido, segnala ciò che è cambiato.

Uso:
    python3 coverage_carry.py stamp <cartella-audit> --repo <codice> [--run <etichetta>]
    python3 coverage_carry.py carry <audit-precedente> <audit-nuovo> --repo <codice> [--run <etichetta>]

stamp  fotografa lo stato del codice: per ogni voce di coverage-matrix.csv esaminata (si/parziale) calcola
       un'impronta del contenuto e la salva nelle colonne `impronta`, `data_esame`, `run`, `origine`.
carry  parte dalla matrice dell'audit precedente e, per ogni voce già esaminata, ricalcola l'impronta sul codice
       attuale: se è uguale la copertura è «riportata» (resta si/parziale, origine = run di provenienza);
       se è cambiata o la voce non esiste più diventa «stantia» (esaminato = no, con motivo) e va rifatta.
       Elenca anche i file del repository non coperti da nessuna voce (aree mai inventariate).
       Scrive coverage-matrix.csv nella cartella nuova (senza sovrascrivere se esiste, salvo --force).

Limiti dichiarati: l'impronta prova che il contenuto non è cambiato, non che l'esame passato fosse corretto né che
una voce «riportata» sia sicura; i finding vanno comunque rivalidati (compare_audits.py). Le voci che non sono
percorsi del repository (verbali, documenti esterni) non hanno impronta e restano da riverificare a mano.
"""
import argparse
import csv
import datetime
import hashlib
import sys
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".next", "__pycache__", ".venv", "venv", "dist", "build", ".cache"}
EXTRA = ["impronta", "data_esame", "run", "origine"]


def is_example(path_value: str) -> bool:
    return (path_value or "").strip().upper().startswith("ESEMPIO")


def read_rows(path: Path):
    with path.open(newline="", encoding="utf-8") as fh:
        rd = csv.DictReader(fh)
        return list(rd), rd.fieldnames or []


def write_rows(path: Path, fields, rows):
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def files_under(p: Path):
    if p.is_file():
        yield p
        return
    for q in sorted(p.rglob("*")):
        if q.is_file() and not (set(q.relative_to(p).parts[:-1]) & SKIP_DIRS):
            yield q


def fingerprint(repo: Path, rel: str):
    """Impronta del contenuto di un file o di una cartella; None se il percorso non esiste nel repository."""
    rel = rel.strip().rstrip("/")
    if not rel or " " in rel and not (repo / rel).exists():
        return None
    p = (repo / rel).resolve()
    try:
        p.relative_to(repo.resolve())
    except ValueError:
        return None
    if not p.exists():
        return None
    h = hashlib.sha256()
    for f in files_under(p):
        h.update(str(f.relative_to(p) if p.is_dir() else f.name).encode("utf-8") + b"\0")
        h.update(hashlib.sha256(f.read_bytes()).digest())
    return h.hexdigest()[:20]


def examined(v: str) -> bool:
    return (v or "").strip().lower() in {"si", "sì", "yes", "parziale", "partial"}


def uncovered(repo: Path, rows):
    """File del repository non compresi in nessuna voce della matrice (aree mai inventariate)."""
    prefixes = [r["area_o_percorso"].strip().rstrip("/") for r in rows if not is_example(r["area_o_percorso"])]
    out = []
    for f in sorted(repo.rglob("*")):
        if not f.is_file() or set(f.relative_to(repo).parts[:-1]) & SKIP_DIRS:
            continue
        rel = str(f.relative_to(repo))
        if not any(rel == x or rel.startswith(x + "/") for x in prefixes if x):
            out.append(rel)
    return out


def top_dirs(paths):
    seen = {}
    for p in paths:
        k = p.split("/")[0] if "/" in p else p
        seen[k] = seen.get(k, 0) + 1
    return seen


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stamp")
    s.add_argument("audit", type=Path)
    c = sub.add_parser("carry")
    c.add_argument("prev", type=Path)
    c.add_argument("new", type=Path)
    c.add_argument("--force", action="store_true")
    for x in (s, c):
        x.add_argument("--repo", type=Path, required=True)
        x.add_argument("--run", default=datetime.date.today().isoformat(), help="etichetta del run (default: data di oggi)")
    a = ap.parse_args()
    today = datetime.date.today().isoformat()
    repo = a.repo.resolve()

    if a.cmd == "stamp":
        m = a.audit / "coverage-matrix.csv"
        rows, fields = read_rows(m)
        fields = fields + [f for f in EXTRA if f not in fields]
        n = 0
        for r in rows:
            if is_example(r["area_o_percorso"]) or not examined(r.get("esaminato", "")):
                continue
            fp = fingerprint(repo, r["area_o_percorso"])
            if fp:
                r["impronta"], r["data_esame"], r["run"], r["origine"] = fp, today, a.run, "esaminata in questo run"
                n += 1
        write_rows(m, fields, rows)
        print(f"impronte salvate: {n} voci esaminate in {m}")
        return 0

    prev_m = a.prev / "coverage-matrix.csv"
    new_m = a.new / "coverage-matrix.csv"
    if new_m.exists() and not a.force:
        print(f"ERRORE: {new_m} esiste già (usa --force per sovrascrivere)", file=sys.stderr)
        return 2
    rows, fields = read_rows(prev_m)
    fields = fields + [f for f in EXTRA if f not in fields]
    carried, stale, nofp, never = [], [], [], []
    out = []
    for r in rows:
        if is_example(r["area_o_percorso"]):
            continue
        r = dict(r)
        if not examined(r.get("esaminato", "")):
            never.append(r["area_o_percorso"])
            out.append(r)
            continue
        old = (r.get("impronta") or "").strip()
        if not old:
            nofp.append(r["area_o_percorso"])
            r["origine"] = f"da riverificare: nessuna impronta nel run {r.get('run') or 'precedente'}"
            r["esaminato"] = "no"
            r["motivo_esclusione"] = "copertura precedente senza impronta: rifare o fotografare con stamp"
            out.append(r)
            continue
        now = fingerprint(repo, r["area_o_percorso"])
        if now == old:
            r["origine"] = f"riportata dal run {r.get('run') or 'precedente'}"
            carried.append(r["area_o_percorso"])
        else:
            motivo = "voce non più presente nel repository" if now is None else "contenuto cambiato dopo l'esame"
            r["origine"] = f"stantia: {motivo} (esaminata nel run {r.get('run') or 'precedente'})"
            r["esaminato"] = "no"
            r["motivo_esclusione"] = f"da rifare: {motivo}"
            stale.append(r["area_o_percorso"])
        out.append(r)
    a.new.mkdir(parents=True, exist_ok=True)
    write_rows(new_m, fields, out)
    gap = uncovered(repo, out)
    print(f"voci nel registro: {len(out)}")
    print(f"  riportate (invariate, ancora valide): {len(carried)}")
    print(f"  stantie (cambiate o sparite, da rifare): {len(stale)}" + (": " + ", ".join(stale[:8]) + ("…" if len(stale) > 8 else "") if stale else ""))
    print(f"  senza impronta (da riverificare):       {len(nofp)}")
    print(f"  mai esaminate (restano buchi):          {len(never)}")
    if gap:
        d = top_dirs(gap)
        print(f"  file del repository non coperti da nessuna voce: {len(gap)} in {len(d)} aree: "
              + ", ".join(f"{k} ({v})" for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:8]))
    print(f"-> {new_m}\nOra esamina in priorità stantie, mai esaminate e aree non coperte; poi `stamp` a fine run.")
    print("Nota: «riportata» vale per il contenuto invariato, non per le sue dipendenze o per la configurazione di runtime.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
