#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Pre-passaggio deterministico: esegue tutti gli strumenti automatici in ordine fisso prima del lavoro manuale.

Uso:
    python3 prepass.py <repo> --audit <cartella-audit> [--no-network]

Perché: in due giri reali sullo stesso repository gli unici finding coincidenti erano quelli prodotti dagli script;
il resto dipendeva da quali aree l'agente aveva deciso di guardare. Questo comando rende identica tra un giro e l'altro
la parte automatica e pre-compila la checklist delle aree, così il lavoro manuale parte sempre dallo stesso punto.

Ordine (sempre lo stesso):
  1. inventory_routes.py   -> endpoint-matrix.csv (se contiene solo righe d'esempio) e registro-tool/inventario.csv
  2. import_openapi.py     -> registro-tool/openapi-matrix.csv per ogni specifica trovata (openapi*/swagger*)
  3. iac_check.py          -> registro-tool/iac.json, iac.sarif
  4. run_scanners.py deps  -> registro-tool/sca-stato.json, candidati-sca.json (--no-network: non eseguito, dichiarato)
     ATTENZIONE: «nessuna richiesta di rete verso il sito reale» NON significa --no-network. npm audit contatta solo il registro
     npm e invia nomi e versioni dei pacchetti, non il codice né dati dell'app. Usare --no-network solo se il mandato vieta
     ogni connessione in uscita; altrimenti R07 resta «non esaminato» senza un motivo vero (due giri reali l'hanno fatto).
  5. run_scanners.py history -> registro-tool/history-stato.json, candidati-history.json
  6. candidati riuniti     -> registro-tool/candidati-prepass.json (ipotesi da validare: NON sono finding)
  7. checklist-rapido.csv  -> aree R01, R02, R03 (campione prioritario fisso di route con identificativo), R06–R11 pre-compilate come «parziale» (parte automatica fatta, validazione
                              manuale da fare); le aree già compilate non vengono toccate
  8. coverage-matrix.csv   -> una riga per strumento, se non già presente
Registro di ogni passo (comando, ora, esito) in registro-tool/prepass.json.
Non modifica il repository e non esegue il suo codice.
"""
import argparse
import csv
import json
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import checklist  # noqa: E402

SKIP = {"node_modules", ".git", "vendor", "dist", "build", ".next"}


def run(script, *args, timeout=900):
    t0 = time.time()
    p = subprocess.run([sys.executable, str(HERE / script), *map(str, args)], capture_output=True, text=True, timeout=timeout)
    return {"comando": " ".join([script, *map(str, args)]), "uscita": p.returncode, "secondi": round(time.time() - t0, 1),
            "ultime_righe": (p.stdout.strip().splitlines() or [""])[-3:]}, p


def specs(repo):
    found = []
    for pat in ("openapi*.json", "openapi*.yaml", "openapi*.yml", "swagger*.json", "swagger*.yaml", "swagger*.yml"):
        found += [p for p in repo.rglob(pat) if not SKIP & set(p.relative_to(repo).parts)]
    return sorted(set(found))


def only_examples(csv_path):
    if not csv_path.exists():
        return True
    with csv_path.open(encoding="utf-8") as fh:
        return all(str(r.get("endpoint", "")).startswith("ESEMPIO") for r in csv.DictReader(fh))


def main():
    import i18n
    i18n.install()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", type=Path)
    ap.add_argument("--audit", type=Path, required=True)
    ap.add_argument("--no-network", action="store_true")
    a = ap.parse_args()
    repo, audit = a.repo.resolve(), a.audit.resolve()
    if not repo.is_dir():
        sys.exit(f"cartella non trovata: {repo}")
    if not (audit / "checklist-rapido.csv").exists():
        sys.exit(f"{audit} non sembra una cartella di audit (manca checklist-rapido.csv): creala con init_audit.py")
    reg = audit / "registro-tool"
    reg.mkdir(exist_ok=True)
    log, prefill, cov = [], {}, []

    # 1. inventario
    e, p = run("inventory_routes.py", repo, "--out", reg / "inventario.csv")
    log.append(e)
    n_routes = n_noauth = 0
    if (reg / "inventario.csv").exists():
        rows = list(csv.DictReader((reg / "inventario.csv").open(encoding="utf-8")))
        n_routes, n_noauth = len(rows), sum(r["identita"] == "NESSUNA AUTH EVIDENTE" for r in rows)
        if only_examples(audit / "endpoint-matrix.csv"):
            (audit / "endpoint-matrix.csv").write_text((reg / "inventario.csv").read_text(encoding="utf-8"), encoding="utf-8")
        rsa = reg / "route-senza-auth.csv"
        if not rsa.exists():   # non sovrascrivere le classificazioni già fatte
            with rsa.open("w", newline="", encoding="utf-8") as fh:
                w = csv.writer(fh)
                w.writerow(["endpoint", "metodo", "file", "classificazione", "motivo"])
                for r in sorted((r for r in rows if r["identita"] == "NESSUNA AUTH EVIDENTE"), key=lambda r: (r["endpoint"], r["metodo"])):
                    w.writerow([r["endpoint"], r["metodo"], r["fonte_scoperta"].split(" · ")[-1], "", ""])
        prefill["R01"] = ("parziale", f"inventario automatico: {n_routes} route, {n_noauth} senza auth evidente; classificare ciascuna in registro-tool/route-senza-auth.csv "
                          "(pubblica per scelta / protetta altrove / difetto / deprecata)", "registro-tool/inventario.csv, registro-tool/route-senza-auth.csv")
        cov.append(("prepass: route (inventario automatico)", "inventario", "inventory_routes.py", "parziale", "", f"{n_routes} route, {n_noauth} senza auth evidente"))
        import re
        svc = sorted({r["endpoint"] for r in rows if re.search(r"(?i)/(internal|debug|seed\w*|demo\w*|test\w*|dev|admin|superadmin|migrat\w*|setup|install|fix[\w-]*|_?health\w*|metrics|actuator|phpinfo)(/|$)", r["endpoint"])})
        (reg / "route-di-servizio.txt").write_text("\n".join(svc) + ("\n" if svc else ""), encoding="utf-8")
        # campione prioritario per R03: stesso ordine in ogni giro (due giri reali avevano letto 2 e 10 route diverse:
        # solo quello che ha letto PATCH /api/users/{id} ha trovato la modifica dei propri privilegi)
        def risk(r):
            m, ep = r["metodo"], r["endpoint"].lower()
            s = {"PATCH": 0, "PUT": 0, "DELETE": 1, "POST": 2, "ANY": 2}.get(m, 4)
            admin = re.search(r"/(admin|superadmin|gestione|backoffice)(/|$)", ep) is not None   # già riservate ai ruoli alti: dopo
            kw = 0 if re.search(r"user|utent|role|ruol|permission|permess|password|org|tenant|member|invite|account|mfa|2fa|token|profil", ep) else 1
            return (admin, kw, s, ep, m)
        param = re.compile(r"\{[^}]+\}|/:[A-Za-z_]\w*|<[^>/]+>|\[[^\]/]+\]")   # Next.js/Spring {id}, Express :id, Flask <id>, [id]
        dyn = [r for r in rows if param.search(r["endpoint"]) and r["identita"] != "NESSUNA AUTH EVIDENTE"]
        top = sorted(dyn, key=risk)[:25]
        (reg / "campione-r03.txt").write_text("".join(f"{r['metodo']:6} {r['endpoint']}   [{r['fonte_scoperta'].split(' · ')[-1]}]\n" for r in top), encoding="utf-8")
        prefill["R03"] = ("parziale", f"campione prioritario fisso: {len(top)} route con identificativo su {len(dyn)} (prima le route non riservate ad admin che modificano utenti, ruoli, permessi, password, organizzazioni; le admin per ultime); da leggere nell'ordine, dichiarando quante lette",
                          "registro-tool/campione-r03.txt")
        prefill["R02"] = ("parziale", f"{len(svc)} route con nomi da funzione di servizio (internal, debug, seed, demo, admin…) elencate; controllo nell'handler da leggere a mano",
                          "registro-tool/route-di-servizio.txt")

    # 1b. punti pericolosi nel codice (anche client): stessi file in ogni giro. Su Juice Shop nessuno dei due giri reali
    # aveva aperto il frontend: le XSS lato client e il chatbot erano rimasti fuori.
    import re
    SINK = [("html senza escape", r"innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|bypassSecurityTrust\w+|dangerouslySetInnerHTML|v-html|\{!!|\|\s*safe\b|mark_safe\(|html_safe|document\.write\("),
            ("esecuzione di codice", r"\beval\(|new Function\(|\bvm\.run\w*|vm2|notevil|child_process|\bexec(Sync)?\(|subprocess\.|os\.system\(|shell_exec|\bsystem\("),
            ("deserializzazione", r"pickle\.loads?|yaml\.load\(|unserialize\(|ObjectInputStream|node-serialize|BinaryFormatter|Marshal\.load"),
            ("parser XML", r"libxml|parseXml|noent\s*:\s*true|XMLParser|DocumentBuilderFactory|etree\.(parse|fromstring)|simplexml_load"),
            ("AI e prompt", r"openai|anthropic|langchain|ollama|\bllm\b|chat.?bot|messages\.create|chat\.completions|system.?prompt"),
            ("recupero password", r"security.?(question|answer)|domand\w* di sicurezza|reset.?token|forgot.?password")]
    hits = []
    for p_ in sorted(repo.rglob("*")):
        rel = p_.relative_to(repo)
        if not p_.is_file() or {"node_modules", ".git", "dist", "build", ".next", "vendor", "coverage", "test", "tests", "__pycache__"} & set(rel.parts) \
                or p_.suffix.lower() not in {".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".html", ".py", ".php", ".rb", ".go", ".java", ".cs", ".yml", ".yaml"} \
                or re.search(r"\.(spec|test|min)\.", p_.name):
            continue
        try:
            lines = p_.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            if len(line) > 400:
                continue
            for cat, rx in SINK:
                if re.search(rx, line, re.I if cat in ("AI e prompt", "recupero password") else 0):
                    hits.append((cat, rel.as_posix(), n))
    by, per_file = {}, {}
    for cat, f, n in hits:   # al massimo 2 righe per file e categoria: conta quali file aprire, non quante righe
        per_file[(cat, f)] = per_file.get((cat, f), 0) + 1
        if per_file[(cat, f)] <= 2:
            by.setdefault(cat, []).append(f"{f}:{n}")
    out_lines = []
    for cat, _ in SINK:
        v = by.get(cat, [])
        out_lines.append(f"## {cat}: {len(v)}" + (" (primi 60)" if len(v) > 60 else ""))
        out_lines += v[:60]
    (reg / "punti-pericolosi.txt").write_text("\n".join(out_lines) + "\n", encoding="utf-8")
    prefill["R11"] = ("parziale", "punti pericolosi elencati per categoria (html senza escape anche nel client, esecuzione di codice, deserializzazione, XML, AI, recupero password): "
                      + ", ".join(f"{c} {len(by.get(c, []))}" for c, _ in SINK) + "; da leggere a mano, con upload, SSRF, query e redirect",
                      "registro-tool/punti-pericolosi.txt")

    # 2. OpenAPI
    sp = specs(repo)
    if sp:
        refs = []
        for i, s in enumerate(sp):
            out = reg / (f"openapi-matrix-{i + 1}.csv" if len(sp) > 1 else "openapi-matrix.csv")
            e, p = run("import_openapi.py", s, "--repo", repo, "--out", out)
            log.append(e); refs.append(out.relative_to(audit).as_posix())
        prefill["R10"] = ("parziale", "confronto specifica/codice eseguito; differenze da leggere", ", ".join(refs))
        cov.append(("prepass: specifica API", "documento", "import_openapi.py --repo", "parziale", "", ", ".join(x.relative_to(repo).as_posix() for x in sp)))
    else:
        prefill["R10"] = ("non applicabile", "nessuna specifica openapi*/swagger* trovata nel repository", "")
        log.append({"comando": "import_openapi.py", "uscita": None, "ultime_righe": ["nessuna specifica trovata"]})

    # 3. IaC
    e, p = run("iac_check.py", repo, "--sarif", reg / "iac.sarif", "--json", reg / "iac.json")
    log.append(e)
    iac = json.loads((reg / "iac.json").read_text(encoding="utf-8")) if (reg / "iac.json").exists() else []
    n_ci = sum(x["file"].startswith(".github/") for x in iac)
    prefill["R08"] = ("parziale", f"iac_check: {len(iac) - n_ci} indizi su container/host; servizi e socket da leggere a mano", "registro-tool/iac.json")
    prefill["R09"] = ("parziale", f"iac_check: {n_ci} indizi sui workflow; permessi e segreti da leggere a mano", "registro-tool/iac.json")
    cov.append(("prepass: infrastruttura come codice", "configurazione", "iac_check.py", "parziale", "", f"{len(iac)} indizi"))

    # 4-5. scanner
    if a.no_network:
        print("ATTENZIONE: --no-network salta npm audit (R07 resterà «non esaminato»). Serve solo se il mandato vieta ogni connessione "
              "in uscita: «nessuna rete verso il sito reale» non lo richiede, npm audit invia solo nomi e versioni al registro npm.")
    args = ["deps", repo, "--out", reg] + (["--no-network"] if a.no_network else [])
    e, p = run("run_scanners.py", *args); log.append(e)
    sca = json.loads((reg / "sca-stato.json").read_text(encoding="utf-8")) if (reg / "sca-stato.json").exists() else []
    if sca and all(s["esito"] == "eseguito" for s in sca):
        prefill["R07"] = ("parziale", "advisory elencati; raggiungibilità degli alti da valutare a mano", "registro-tool/sca-stato.json")
        cov.append(("prepass: dipendenze (lockfile)", "dipendenze", "run_scanners.py deps", "parziale", "", "eseguito"))
    else:
        mot = "; ".join((f"{s['file']}: " if s.get("file") else "") + s.get("motivo", "") for s in sca if s["esito"] != "eseguito")[:300] or "nessun lockfile"
        prefill["R07"] = ("non esaminato", f"analisi delle dipendenze non eseguita: {mot}; comando preparato in sca-stato.json", "registro-tool/sca-stato.json")
        cov.append(("prepass: dipendenze (lockfile)", "dipendenze", "run_scanners.py deps", "no", mot, "comando preparato in registro-tool/sca-stato.json"))
    e, p = run("run_scanners.py", "history", repo, "--out", reg); log.append(e)
    hs = json.loads((reg / "history-stato.json").read_text(encoding="utf-8")) if (reg / "history-stato.json").exists() else {}
    if hs.get("esito") == "eseguito":
        f = hs.get("fasce", {})
        prefill["R06"] = ("parziale", f"storia scansionata ({f.get('in cima', 0)} voci in cima, {f.get('da guardare', 0)} da guardare)"
                          + ("; clone superficiale: storia incompleta" if hs.get("clone_superficiale") else "") + "; voci in cima da valutare a mano",
                          "registro-tool/history-stato.json, registro-tool/candidati-history.json")
        cov.append(("prepass: segreti nella storia Git", "repository", "run_scanners.py history", "parziale", "", hs.get("strumento", "")))
    else:
        prefill["R06"] = ("non esaminato", f"scansione della storia non eseguita: {hs.get('motivo', '?')}", "registro-tool/history-stato.json")
        cov.append(("prepass: segreti nella storia Git", "repository", "run_scanners.py history", "no", hs.get("motivo", "?"), ""))

    # 6. candidati riuniti (non sono finding)
    e, p = run("import_scanner.py", "--sarif", reg / "iac.sarif", "--out", reg / "candidati-iac.json"); log.append(e)
    allc = []
    for n in ("candidati-iac.json", "candidati-sca.json", "candidati-history.json"):
        if (reg / n).exists():
            allc += json.loads((reg / n).read_text(encoding="utf-8"))
    (reg / "candidati-prepass.json").write_text(json.dumps(allc, indent=1, ensure_ascii=False), encoding="utf-8")

    # 7. checklist: solo aree vuote
    cl = checklist.load(audit)
    filled = []
    for r in cl:
        if r["id"] in prefill and not (r.get("esito") or "").strip():
            r["esito"], r["motivo"], r["riferimenti"] = prefill[r["id"]]
            filled.append(r["id"])
    checklist.write(audit, cl)

    # 8. coverage-matrix: righe degli strumenti, senza duplicati
    cm = audit / "coverage-matrix.csv"
    fields = ["area_o_percorso", "tipo", "modalita_verifica", "esaminato", "motivo_esclusione", "note"]
    old = list(csv.DictReader(cm.open(encoding="utf-8"))) if cm.exists() else []
    have = {r.get("area_o_percorso") for r in old}
    new = [dict(zip(fields, c)) for c in cov if c[0] not in have]
    with cm.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader(); w.writerows(old + new)

    (reg / "prepass.json").write_text(json.dumps({"repo": str(repo), "quando": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "passi": log},
                                                 indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"pre-passaggio completato: {n_routes} route ({n_noauth} senza auth evidente), {len(sp)} specifiche, {len(iac)} indizi IaC, "
          f"{len(allc)} candidati da validare")
    print(f"checklist pre-compilata: {', '.join(filled) or 'nessuna area (già compilate)'}; le altre aree restano da fare a mano")
    print("I candidati in registro-tool/candidati-prepass.json sono ipotesi: vanno validati prima di diventare finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
