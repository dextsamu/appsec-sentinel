#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Esegue gli scanner di base quando l'agente non ha una pipeline propria, con ripiego dichiarato.

Uso:
    python3 run_scanners.py deps    <repo> --out <cartella-audit>/registro-tool [--no-network]
    python3 run_scanners.py history <repo> --out <cartella-audit>/registro-tool

deps     Analisi delle dipendenze. NON serve node_modules né installare nulla: `npm audit --package-lock-only`
         lavora sul solo lockfile (package-lock.json / npm-shrinkwrap.json) e non esegue script del progetto.
         Invia a registry.npmjs.org SOLO nomi e versioni dei pacchetti; con --no-network non parte e lo registra.
         Per requirements.txt usa pip-audit e per composer.lock composer audit, se installati. Altri gestori (yarn, pnpm,
         poetry, Gemfile, go.sum): comando preparato, non eseguito.
history  Segreti nella cronologia Git: usa gitleaks se presente, altrimenti secret_triage.py sulle righe aggiunte di
         `git log -p --all`; in entrambi i casi classifica le occorrenze (in cima / da guardare / probabile esempio). Non riporta mai il valore: solo file, commit breve e tipo. Avvisa se il clone
         è superficiale (shallow): la storia incompleta non prova l'assenza di segreti.

Scrive in --out: sca-stato.json / history-stato.json (cosa è stato eseguito o perché no, con il comando preparato)
e candidati-sca.json / candidati-history.json (ipotesi da validare, importabili con import_scanner/--merge).
Un esito «non eseguito» va riportato nel report come limite; non è un test superato.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import import_scanner  # noqa: E402
import secret_triage  # noqa: E402
from collections import defaultdict  # noqa: E402

SKIP = {"node_modules", ".git", "vendor", "dist", "build", ".next"}


def sh(cmd, cwd, timeout=240):
    try:
        r = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: comando non trovato"
    except subprocess.TimeoutExpired:
        return 124, "", "tempo scaduto"


def write(out, name, data):
    out.mkdir(parents=True, exist_ok=True)
    (out / name).write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")


def deps(repo, out, network):
    stato, cands = [], []
    locks = [p for p in repo.rglob("package-lock.json") if not SKIP & set(p.relative_to(repo).parts)]
    locks += [p for p in repo.rglob("npm-shrinkwrap.json") if not SKIP & set(p.relative_to(repo).parts)]
    for lk in locks:
        rel = lk.relative_to(repo).as_posix()
        cmd = ["npm", "audit", "--package-lock-only", "--ignore-scripts", "--json"]
        prep = f"cd {lk.parent.relative_to(repo).as_posix() or '.'} && " + " ".join(cmd) + " > npm-audit.json"
        if not network:
            stato.append({"strumento": "npm audit", "file": rel, "esito": "non eseguito", "motivo": "rete non consentita (--no-network)", "comando_preparato": prep})
            continue
        rc, so, se = sh(cmd, lk.parent)
        try:
            d = json.loads(so)
        except json.JSONDecodeError:
            d = None
        if d is None or "vulnerabilities" not in d:
            motivo = (d or {}).get("error", {}).get("summary") if isinstance(d, dict) else None
            stato.append({"strumento": "npm audit", "file": rel, "esito": "non eseguito", "motivo": (motivo or se.strip().splitlines()[-1] if (motivo or se.strip()) else f"uscita {rc} senza JSON")[:200], "comando_preparato": prep})
            continue
        c = import_scanner.from_npm(d)
        for x in c:
            x["asset"] = x["asset"].replace("package-lock.json", rel)
        cands += c
        stato.append({"strumento": "npm audit", "file": rel, "esito": "eseguito", "vulnerabilita_pacchetti": len(c),
                      "dati_inviati": "solo nomi e versioni dei pacchetti a registry.npmjs.org"})
    for rq in [p for p in repo.rglob("requirements*.txt") if not SKIP & set(p.relative_to(repo).parts)]:
        rel = rq.relative_to(repo).as_posix()
        prep = f"pip-audit -r {rel} -f json"
        if not network or not shutil.which("pip-audit"):
            stato.append({"strumento": "pip-audit", "file": rel, "esito": "non eseguito", "motivo": "rete non consentita" if not network else "pip-audit non installato (pip install pip-audit)", "comando_preparato": prep})
            continue
        rc, so, se = sh(["pip-audit", "-r", str(rq), "-f", "json", "--progress-spinner", "off"], repo)
        try:
            d = json.loads(so)
        except json.JSONDecodeError:
            stato.append({"strumento": "pip-audit", "file": rel, "esito": "non eseguito", "motivo": (se.strip().splitlines() or ["senza JSON"])[-1][:200], "comando_preparato": prep})
            continue
        n = 0
        for dep in d.get("dependencies", []):
            vs = dep.get("vulns") or []
            if vs:
                n += 1
                ids = ", ".join(v.get("id", "") for v in vs[:6])
                cands.append(import_scanner.base(f"Dipendenza {dep.get('name')} {dep.get('version')} con vulnerabilità note", "dipendenze", f"{rel} · {dep.get('name')}", "medium",
                                                 f"pip-audit: {len(vs)} voci ({ids}).", [rel], "Versione in database di vulnerabilità; raggiungibilità non valutata."))
        stato.append({"strumento": "pip-audit", "file": rel, "esito": "eseguito", "vulnerabilita_pacchetti": n})
    for lk in [p for p in repo.rglob("composer.lock") if not SKIP & set(p.relative_to(repo).parts)]:
        rel = lk.relative_to(repo).as_posix()
        prep = f"cd {lk.parent.relative_to(repo).as_posix() or '.'} && composer audit --locked --format=json > composer-audit.json"
        if not network or not shutil.which("composer"):
            stato.append({"strumento": "composer audit", "file": rel, "esito": "non eseguito",
                          "motivo": "rete non consentita" if not network else "composer non installato (il comando legge solo composer.lock)", "comando_preparato": prep})
            continue
        rc, so, se = sh(["composer", "audit", "--locked", "--format=json", "--no-interaction"], lk.parent)
        try:
            d = json.loads(so)
        except json.JSONDecodeError:
            stato.append({"strumento": "composer audit", "file": rel, "esito": "non eseguito", "motivo": (se.strip().splitlines() or ["senza JSON"])[-1][:200], "comando_preparato": prep})
            continue
        n = 0
        for pkg, advs in (d.get("advisories") or {}).items():
            advs = advs.values() if isinstance(advs, dict) else advs
            advs = list(advs)
            if advs:
                n += 1
                ids = ", ".join(str(x.get("cve") or x.get("advisoryId") or "") for x in advs[:6])
                cands.append(import_scanner.base(f"Dipendenza {pkg} con advisory noti", "dipendenze", f"{rel} · {pkg}", "medium",
                                                 f"composer audit: {len(advs)} advisory ({ids}).", [rel], "Versione in un intervallo vulnerabile; raggiungibilità non valutata."))
        stato.append({"strumento": "composer audit", "file": rel, "esito": "eseguito", "vulnerabilita_pacchetti": n})
    for other in ("yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Gemfile.lock", "go.sum"):
        for p in repo.rglob(other):
            if not SKIP & set(p.relative_to(repo).parts):
                stato.append({"strumento": "nessuno", "file": p.relative_to(repo).as_posix(), "esito": "non eseguito", "motivo": "gestore non coperto da questo script",
                              "comando_preparato": "osv-scanner --lockfile " + p.relative_to(repo).as_posix()})
    if not stato:
        stato.append({"strumento": "nessuno", "esito": "non eseguito", "motivo": "nessun lockfile trovato"})
    for i, c in enumerate(cands, 1):
        c["id"] = f"SCA-{i:03d}"
    write(out, "sca-stato.json", stato)
    write(out, "candidati-sca.json", cands)
    return stato, cands


def to_candidates(voci):
    """Una voce per file e fascia; i «probabile esempio» raccolti in una sola voce informativa."""
    per = defaultdict(list)
    for v in voci:
        per[(v["file"], secret_triage.bucket(v["punteggio"]))].append(v)
    cands, esempi = [], []
    order = {"in cima": 0, "da guardare": 1}
    for (path, b), vs in sorted(per.items(), key=lambda kv: (order.get(kv[0][1], 2), -max(v["punteggio"] for v in kv[1]), kv[0][0])):
        if b == "probabile esempio":
            esempi.append(path); continue
        best = max(vs, key=lambda v: v["punteggio"])
        commits = sorted({c for v in vs for c in v["commit"]})[:4]
        tipi = sorted({v["tipo"] for v in vs})
        stato_codice = "ancora nel codice" if any(v["in_head"] for v in vs) else ("solo nella storia" if all(v["in_head"] is False for v in vs) else "")
        c = import_scanner.base(f"Possibile segreto ({', '.join(tipi)}) in {path}" + (f" · {stato_codice}" if stato_codice else ""), "segreti", path,
                                "medium" if b == "in cima" else "low",
                                f"{len(vs)} valori distinti (impronte {', '.join(v['impronta'] for v in vs[:4])}) in {len(commits)}+ commit (es. {', '.join(commits)}). "
                                f"Punteggio {best['punteggio']:+d}: {'; '.join(best['motivi'])}. Valore non riportato.",
                                [path], "Occorrenza classificata dagli indizi elencati; non verificato se reale o attivo.", cwe=["CWE-798"],
                                correzione="Verificare se è reale; se sì ruotarlo subito. Rimuoverlo dalla storia non basta se il repository è già stato clonato.")
        cands.append(c)
    if esempi:
        cands.append(import_scanner.base(f"Valori di esempio o di sviluppo in {len(esempi)} file (probabili segnaposto)", "segreti", "repository", "info",
                                         "Occorrenze con punteggio negativo (dizionario, bassa entropia, documentazione/test/seed, valore ripetuto in molti file). "
                                         "File: " + ", ".join(esempi[:25]) + ("…" if len(esempi) > 25 else "") + ". Valori non riportati.",
                                         esempi[:10], "Probabili segnaposto; da scorrere rapidamente, non da ignorare a priori.", cwe=["CWE-798"]))
    return cands


def history(repo, out):
    stato, cands = {}, []
    if not (repo / ".git").exists():
        stato = {"esito": "non eseguito", "motivo": "non è un repository Git"}
        write(out, "history-stato.json", stato); write(out, "candidati-history.json", [])
        return stato, cands
    shallow = sh(["git", "rev-parse", "--is-shallow-repository"], repo)[1].strip() == "true"
    ncommit = sh(["git", "rev-list", "--count", "--all"], repo)[1].strip()
    if shutil.which("gitleaks"):
        rep = out / "gitleaks-report.json"
        out.mkdir(parents=True, exist_ok=True)
        sh(["gitleaks", "detect", "--no-banner", "--redact", "--report-format", "json", "--report-path", str(rep)], repo, 600)
        try:
            d = json.loads(rep.read_text(encoding="utf-8")) if rep.exists() else []
        except json.JSONDecodeError:
            d = []
        voci = secret_triage.triage_gitleaks(d)
        stato = {"esito": "eseguito", "strumento": "gitleaks + classificazione", "commit_in_storia": ncommit, "clone_superficiale": shallow}
    else:
        voci, err = secret_triage.scan_history(repo)
        if err:
            stato = {"esito": "non eseguito", "motivo": err}
            voci = []
        else:
            stato = {"esito": "eseguito", "strumento": "secret_triage.py (pattern + classificazione), meno completo di gitleaks", "commit_in_storia": ncommit, "clone_superficiale": shallow}
    esclusi = [v for v in voci if v.get("escluso")]
    voci = [v for v in voci if not v.get("escluso")]
    if esclusi:
        stato["esclusi"] = esclusi[0]["motivi"][0]
    if voci:
        from collections import Counter
        stato["fasce"] = dict(Counter(secret_triage.bucket(v["punteggio"]) for v in voci))
        write(out, "history-voci.json", voci)   # impronte e motivi, mai i valori
    cands = to_candidates(voci)
    if shallow:
        stato["avviso"] = "clone superficiale: la storia è incompleta, l'assenza di risultati non prova l'assenza di segreti"
    for i, c in enumerate(cands, 1):
        c["id"] = f"SEC-{i:03d}"
    write(out, "history-stato.json", stato)
    write(out, "candidati-history.json", cands)
    return stato, cands


def main():
    import i18n
    i18n.install()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("modo", choices=["deps", "history"])
    ap.add_argument("repo", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--no-network", action="store_true")
    a = ap.parse_args()
    if not a.repo.is_dir():
        sys.exit(f"cartella non trovata: {a.repo}")
    if a.modo == "deps":
        stato, c = deps(a.repo, a.out, not a.no_network)
        for s in stato:
            print(f"  {s['esito']:13} {s.get('strumento', '')} {s.get('file', '')} {('— ' + s['motivo']) if s.get('motivo') else ''}")
        print(f"candidati dalle dipendenze: {len(c)} (ipotesi da validare)")
        if any(s["esito"] != "eseguito" for s in stato):
            print("ATTENZIONE: parte dell'analisi NON è stata eseguita: riportarlo nel report come limite; i comandi preparati sono in sca-stato.json.")
    else:
        s, c = history(a.repo, a.out)
        print(f"  {s['esito']} {s.get('strumento', '')} {('— ' + s['motivo']) if s.get('motivo') else ''}")
        if s.get("avviso"):
            print("AVVISO:", s["avviso"])
        print(f"candidati dalla cronologia: {len(c)} (ipotesi da validare, valori non riportati)")


if __name__ == "__main__":
    main()
