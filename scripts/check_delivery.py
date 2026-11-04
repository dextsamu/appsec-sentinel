#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Controllo di consegna: un solo comando prima di dare l'audit al cliente.

Uso:
    python3 check_delivery.py <cartella-audit> [--app <cartella-dell-app>] [--strict] [--json esito.json]

Lancia, in questo ordine, i controlli che non devono dipendere dall'obbedienza del modello:
  1. la cartella di audit esiste, ha i file attesi e NON è dentro un repository Git;
  1b. valori enumerati canonici (stati e severità scritti in inglese vanno riportati con canonicalize.py);
  2. finding (se presenti): schema e coerenza (validate_findings.py) e revisore (verify_findings.py);
  3. ogni finding alto o critico ha la `smentita`; «non eseguita» è ammessa ma dichiarata come limite;
  4. matrice GDPR (se presente): check_matrix.py, comprese le smentite dei gap;
  5. redazione: redact_check.py sulla cartella; con --app cerca anche i VALORI dei segreti trovati nell'app
     dentro i file di audit (non li stampa mai: solo file e tipo);
  6. parole vietate: «conforme», «non conforme», «sicuro/sicura», «certificato» usate come giudizio (euristica:
     le frasi negate o di avvertenza non contano; ogni occorrenza va comunque riletta);
  7. copertura: coverage_summary.py (denominatori reali) se c'è coverage-matrix.csv.

Esito per ogni controllo: OK, DA VERIFICARE (warning) o FALLITO. Esce con 1 se c'è almeno un FALLITO
(con --strict anche per i DA VERIFICARE). Un esito pulito non prova che l'audit sia corretto: sono controlli
meccanici. Non può vedere i messaggi di chat: lì i valori dei segreti non vanno mai scritti.
Funziona anche con la sola gdpr-sentinel (usa gli script che trova nella propria cartella).
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

HERE = Path(__file__).resolve().parent
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".next", "dist", "build"}
TEXT_EXT = {".txt", ".md", ".csv", ".json", ".yml", ".yaml", ".html", ".log", ".py", ".js", ".ts", ".env", ".cfg", ".ini", ".toml", ".conf", ""}
VALUE_RE = re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token|auth[_-]?token|secret[_-]?key)\w*\b\s*[:=]\s*['\"]([^'\"\s]{10,})['\"]")
PLACEHOLDER = re.compile(r"(?i)^(?:x{3,}|\*+|redatto|redacted|changeme|example|esempio|tuo|your|<.*>|\$\{.*\}|process\.env|env:)")
VIETATE = re.compile(r"(?i)\b(non\s+conforme|conforme(?!\s+(?:a|al|alla|all'|alle|ai)\s*(?:informativ|quanto|dichiarat|codice|document))|conformi|sicuro|sicura|sicuri|certificat[oa])\b")
AVVERTENZE = re.compile(r"(?i)(giudizi?\s+di\s+conformit|non\s+(?:è|e'|esprime|certifica|dichiara|può|puo|sono)|mai\s+«?(?:conforme|sicur)|«\s*(?:conforme|non conforme|sicuro|sicura)\s*»|conformit[aà]\s+(?:non|a\s+)|nessun\w*\s+(?:giudizio|dichiarazione)|esclusi|vietat)")

results = []


def add(name, status, detail=""):
    results.append((name, status, detail))
    mark = {"OK": "ok  ", "DA VERIFICARE": "!!  ", "FALLITO": "FAIL"}[status]
    print(f"  {mark} {name}" + (f": {detail}" if detail else ""))


def find_script(script):
    """Cerca lo script accanto a questo file e, se le due skill sono installate affiancate, nella skill gemella."""
    for base in (HERE, HERE.parent.parent / "appsec-sentinel" / "scripts", HERE.parent.parent / "gdpr-sentinel" / "scripts"):
        if (base / script).exists():
            return base / script
    return None


def run(script, *args):
    p = find_script(script)
    if p is None:
        return None
    return subprocess.run([sys.executable, str(p), *map(str, args)], capture_output=True, text=True)


AUTO_OUT = {"retention-evidenze.csv", "privacy-scan.json", "processing-map-bozza.csv", "fornitori-bozza.csv", "gdpr-prepass.json",
            "inventario.csv", "iac.json", "iac.sarif", "punti-pericolosi.txt", "campione-r03.txt", "route-di-servizio.txt",
            "history-voci.json", "sca.json", "prepass.json", "candidati-prepass.json", "candidati-iac.json", "candidati-sca.json",
            "candidati-history.json"}


def files_of(root: Path):
    for f in sorted(root.rglob("*")):
        if f.is_file() and not (set(f.relative_to(root).parts[:-1]) & SKIP_DIRS) and f.suffix.lower() in TEXT_EXT:
            yield f


def inside_git(p: Path) -> bool:
    try:
        r = subprocess.run(["git", "-C", str(p), "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
        return r.stdout.strip() == "true"
    except FileNotFoundError:
        return False


def app_secret_values(app: Path):
    vals = {}
    for f in files_of(app):
        try:
            t = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in VALUE_RE.finditer(t):
            v = m.group(1)
            if not PLACEHOLDER.match(v):
                vals.setdefault(v, f.relative_to(app).as_posix())
    return vals


def main() -> int:
    import i18n
    i18n.install()  # --lang en per i messaggi in inglese
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit", type=Path)
    ap.add_argument("--app", type=Path, help="cartella dell'app esaminata: cerca nell'audit i valori dei suoi segreti")
    ap.add_argument("--strict", action="store_true", help="esce con 1 anche per i DA VERIFICARE")
    ap.add_argument("--json", type=Path, help="scrive l'esito in JSON")
    a = ap.parse_args()
    audit = a.audit.resolve()
    print(f"Controllo di consegna: {audit}\n")

    # 1. cartella
    if not audit.is_dir():
        add("cartella di audit", "FALLITO", "non esiste")
        return finish(a)
    add("cartella di audit fuori da Git", "FALLITO" if inside_git(audit) else "OK", "è dentro un repository Git" if inside_git(audit) else "")
    fj = audit / "findings" / "findings.json"
    gm = audit / "gdpr-matrix.csv"
    if not fj.exists() and not gm.exists():
        add("file attesi", "FALLITO", "né findings/findings.json né gdpr-matrix.csv")

    # 1b. valori in lingua canonica (se qualcuno ha scritto stati e severità in inglese gli script non li riconoscono)
    if fj.exists() or gm.exists():
        r = run("canonicalize.py", audit, "--dry-run")
        if r is not None:
            n = next((int(l.split(":")[1]) for l in r.stdout.splitlines() if l.startswith("sostituzioni")), 0)
            add("valori enumerati canonici", "DA VERIFICARE" if n else "OK",
                f"{n} valori in inglese: esegui canonicalize.py <cartella> prima della consegna" if n else "")

    # 2-3. finding
    if fj.exists():
        r = run("validate_findings.py", fj)
        if r is None:
            add("validazione dei finding", "DA VERIFICARE", "validate_findings.py non disponibile in questa skill")
        else:
            minimal = "jsonschema non installato" in r.stdout or "jsonschema module not installed" in r.stdout
            if r.returncode == 0 and minimal:
                add("validazione dei finding (schema e coerenza)", "DA VERIFICARE", "schema completo non eseguito (jsonschema assente): installa con pip install jsonschema e riesegui")
            else:
                add("validazione dei finding (schema e coerenza)", "OK" if r.returncode == 0 else "FALLITO", "" if r.returncode == 0 else r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "errori")
        try:
            fs = json.loads(fj.read_text(encoding="utf-8"))
        except Exception as e:
            fs = []
            add("lettura dei finding", "FALLITO", str(e))
        alti = [f for f in fs if f.get("severita") in ("alta", "critica")]
        senza = [f["id"] for f in alti if not f.get("smentita")]
        nonesg = [f["id"] for f in alti if (f.get("smentita") or {}).get("esito") == "non eseguita"]
        if alti:
            if senza:
                add("smentita dei finding alti", "FALLITO", f"mancante su {', '.join(senza)} (references/refutation-pass.md)")
            elif nonesg:
                add("smentita dei finding alti", "DA VERIFICARE", f"«non eseguita» su {', '.join(nonesg)}: dichiararlo nel report come limite")
            else:
                add("smentita dei finding alti", "OK", f"{len(alti)} finding alti con esito")
        else:
            add("smentita dei finding alti", "OK", "nessun finding alto o critico")
        r = run("verify_findings.py", fj)
        if r is not None:
            n = len([l for l in r.stdout.splitlines() if re.match(r"^[A-Z]{2,6}-\d{3,4}: ", l)])
            add("revisore dei finding", "OK" if r.returncode == 0 else "DA VERIFICARE", "" if r.returncode == 0 else f"{n} rilievi da risolvere o motivare (esegui verify_findings.py)")

    # 4. matrice GDPR
    if gm.exists():
        pm = audit / "processing-map.csv"
        gp = audit / "gaps.csv"
        r = run("check_matrix.py", gm, *(["--map", pm] if pm.exists() else []), *(["--gaps", gp] if gp.exists() else []))
        if r is None:
            add("matrice GDPR", "DA VERIFICARE", "check_matrix.py non disponibile in questa skill")
        else:
            lines = [l for l in r.stdout.splitlines() if l.startswith(("WARNING", "ERRORE"))]
            if r.returncode != 0:
                add("matrice GDPR A–N", "FALLITO", f"{sum(l.startswith('ERRORE') for l in lines)} errori (esegui check_matrix.py)")
            elif lines:
                add("matrice GDPR A–N", "DA VERIFICARE", f"{len(lines)} warning (esegui check_matrix.py)")
            else:
                add("matrice GDPR A–N", "OK")

    # 5. redazione
    r = run("redact_check.py", audit)
    if r is None:
        add("redazione", "DA VERIFICARE", "redact_check.py non disponibile")
    else:
        add("redazione (segreti e dati personali)", "OK" if r.returncode == 0 else "FALLITO", "" if r.returncode == 0 else "trovati segreti (esegui redact_check.py)")
    if a.app:
        vals = app_secret_values(a.app.resolve())
        hits = []
        for f in files_of(audit):
            t = f.read_text(encoding="utf-8", errors="replace")
            for v, origin in vals.items():
                if v in t:
                    hits.append(f"{f.relative_to(audit).as_posix()} (valore di un segreto in {origin})")
        add("valori dei segreti dell'app assenti dall'audit", "FALLITO" if hits else "OK",
            ("; ".join(hits[:5]) if hits else f"{len(vals)} valori cercati, nessuno trovato"))

    # 6. parole vietate
    sospette = []
    for f in files_of(audit):
        if f.suffix.lower() == ".json" and f.name in ("finding.schema.json",):
            continue
        if f.name in ("finding-template.md", "00-regole-di-ingaggio.md"):
            continue
        if f.parent.name == "registro-tool" and f.name in AUTO_OUT:
            continue   # uscite degli script: copiano estratti del repository, non sono giudizi dell'auditor
        if "smentite" in f.parts and (f.name.startswith("smentita-") or f.name in ("ISTRUZIONI.md", "refutation-pass.md")):
            continue   # brief e pacchetto di smentita: generati dagli script, con estratti del codice
        for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for m in VIETATE.finditer(line):
                pre = line[max(0, m.start() - 70):m.start()]
                if AVVERTENZE.search(line) or re.search(r"(?i)\b(non|nessun\w*|mai|senza|né)\b", pre):
                    continue
                sospette.append(f"{f.relative_to(audit).as_posix()}:{n}")
    add("parole vietate («conforme», «sicuro»…)", "DA VERIFICARE" if sospette else "OK",
        (f"{len(sospette)} occorrenze da rileggere: " + ", ".join(sospette[:6])) if sospette else "")

    # 7. copertura
    if (audit / "coverage-matrix.csv").exists():
        r = run("coverage_summary.py", audit)
        if r is not None:
            add("copertura con denominatori", "OK" if r.returncode == 0 else "FALLITO", "" if r.returncode == 0 else "coverage_summary.py ha fallito")

    # 7b. meta.json: versione e oggetto compilati (due giri reali avevano lasciato il testo del modello)
    mj = audit / "meta.json"
    if mj.exists():
        try:
            meta = json.loads(mj.read_text(encoding="utf-8"))
            vuoti = [k for k in ("versione", "oggetto", "data") if not str(meta.get(k, "")).strip() or str(meta.get(k, "")).strip().lower() in
                     ("commit o versione esaminata", "repository o ambiente esaminato", "da compilare", "aaaa-mm-gg", "yyyy-mm-dd")]
            add("meta.json compilato (versione, oggetto, data)", "DA VERIFICARE" if vuoti else "OK",
                ("ancora il testo del modello: " + ", ".join(vuoti)) if vuoti else "")
        except Exception as e:
            add("meta.json compilato (versione, oggetto, data)", "DA VERIFICARE", f"non leggibile: {e}")

    # 7c. ogni route senza auth evidente classificata (in un giro reale una route pubblica con dati personali non era stata citata)
    rsa = audit / "registro-tool" / "route-senza-auth.csv"
    if rsa.exists():
        import csv as _csv
        rr = list(_csv.DictReader(rsa.open(encoding="utf-8")))
        nc = [f"{r['metodo']} {r['endpoint']}" for r in rr if not (r.get("classificazione") or "").strip()]
        add("route senza auth classificate una per una", "DA VERIFICARE" if nc else "OK",
            (f"{len(nc)} su {len(rr)} senza classificazione: " + ", ".join(nc[:5]) + ("…" if len(nc) > 5 else "")) if nc else f"{len(rr)} route")

    # 8. aree della checklist: due giri reali sullo stesso repo hanno coperto aree diverse (in comune 2 su 14)
    import checklist
    cl = checklist.load(audit)
    if cl is not None:
        vuote, incoerenti = checklist.problems(cl)
        if vuote:
            add("checklist delle aree (checklist-rapido.csv)", "FALLITO", f"{len(vuote)} aree su {len(cl)} non compilate: {', '.join(vuote)} (anche «non esaminato» va bene, con il motivo)")
        elif incoerenti:
            add("checklist delle aree (checklist-rapido.csv)", "DA VERIFICARE", "; ".join(incoerenti[:6]))
        else:
            from collections import Counter
            c = Counter((r.get("esito") or "").strip().lower() for r in cl)
            add("checklist delle aree (checklist-rapido.csv)", "OK", ", ".join(f"{k} {v}" for k, v in c.most_common()))
        las = checklist.lasciati(cl, checklist.risposte(audit))
        add("problemi annotati nella checklist e non diventati finding", ("FALLITO" if strict_mode(audit) else "DA VERIFICARE") if las else "OK",
            (f"{', '.join(las)}: il motivo dice «non promosso», «da approfondire» o simili. Ogni problema visto con file e riga "
             "diventa un finding, anche come «ipotesi da validare»; se non è un difetto, scrivi perché in revisione.md sotto "
             "«## Risposte» citando l'area") if las else "")
    elif fj.exists() and (audit / "coverage-matrix.csv").exists():
        import csv
        rows = list(csv.DictReader((audit / "coverage-matrix.csv").open(encoding="utf-8")))
        blob = " ".join(" ".join(str(v) for v in r.values()).lower() for r in rows if not str(r.get("area_o_percorso", "")).startswith("ESEMPIO"))
        mancano = [n for n, rx in (("dipendenze", r"dipendenz|package|lockfile|\bsca\b|npm audit|pip-audit|osv"), ("segreti", r"segret|secret|gitleaks|cronologia|storia git")) if not re.search(rx, blob)]
        add("aree minime nel registro (dipendenze, segreti)", "DA VERIFICARE" if mancano else "OK",
            ("nel registro di copertura manca: " + ", ".join(mancano) + " (anche come «non eseguito», con il motivo; vedi run_scanners.py)") if mancano else "")

    # 9. punti pericolosi: una riga chiusa per categoria trovata dal pre-passaggio
    import punti
    pp = punti.problems(audit, strict_mode(audit))
    if pp:
        add("punti pericolosi chiusi per categoria (punti-pericolosi.csv)", *pp)
    lt = punti.letture_problems(audit, strict_mode(audit))
    if lt:
        add("letture obbligatorie (letture.csv)", *lt)
    em = punti.entita_problems(audit, strict_mode(audit))
    if em:
        add("matrice per entità (entita.csv)", *em)
    im = punti.entita_problems(audit, strict_mode(audit), "informativa.csv")
    if im:
        add("matrice dell'informativa (informativa.csv)", *im)
    am = punti.accessi_problems(audit, strict_mode(audit))
    if am:
        add("matrice dei ruoli e degli accessi (accessi.csv)", *am)

    deliverables(audit)
    return finish(a)


def strict_mode(audit: Path) -> bool:
    """standard e completo: le aree lasciate aperte bloccano la consegna; nel rapido sono da verificare."""
    try:
        mod = str(json.loads((audit / "meta.json").read_text(encoding="utf-8")).get("modalita", "")).lower()
    except (OSError, ValueError):
        mod = ""
    return mod.startswith(("standard", "completo")) or ((audit / "gaps.csv").exists() and not (audit / "findings" / "findings.json").exists())


def deliverables(audit: Path):
    """Definizione di «finito» per modalità (meta.json → modalita). Il rapido ha la checklist; standard e completo
    hanno anche file obbligatori: due giri reali li avevano scelti a caso e `chiudi` non se ne accorgeva."""
    import csv
    try:
        mod = str(json.loads((audit / "meta.json").read_text(encoding="utf-8")).get("modalita", "")).lower()
    except (OSError, ValueError):
        return
    mode = "completo" if mod.startswith("completo") else "standard" if mod.startswith("standard") else ""
    if not mode or not (audit / "findings" / "findings.json").exists():
        return
    def real_rows(name):
        f = audit / name
        if not f.exists():
            return []
        return [r for r in csv.DictReader(f.open(encoding="utf-8")) if not str(next(iter(r.values()), "")).startswith("ESEMPIO")]
    rep = audit / "report"
    need = {"report/sintesi.md": [rep / "sintesi.md", rep / "00-sintesi.md"], "report/threat-model.md": [rep / "threat-model.md"]}
    if mode == "completo":
        need.update({"report/inventario.md": [rep / "inventario.md"], "report/rapporto-tecnico.md": [rep / "rapporto-tecnico.md"],
                     "report/piano.md": [rep / "piano.md"]})
    miss = [k for k, alts in need.items() if not any(x.exists() and x.stat().st_size > 200 for x in alts)]
    ctl = real_rows("controls-matrix.csv")
    if not ctl:
        miss.append("controls-matrix.csv compilata (righe reali, non ESEMPIO)")
    if mode == "completo" and not real_rows("coverage-matrix.csv"):
        miss.append("coverage-matrix.csv compilata")
    add(f"deliverable della modalità {mode}", "FALLITO" if miss else "OK",
        ("mancano: " + ", ".join(miss) + " (vedi references/commands.md)") if miss else f"{len(need)} file del report, {len(ctl)} righe di controlli")
    snap = audit / "findings" / "rapido.json"
    if not snap.exists():
        add("base del rapido (findings/rapido.json)", "FALLITO", "manca la copia dei finding a fine rapido: la procedura la chiede prima dei passi della modalità")
    else:
        try:
            base = {f["id"] for f in json.loads(snap.read_text(encoding="utf-8"))}
            now = {f["id"] for f in json.loads((audit / "findings" / "findings.json").read_text(encoding="utf-8"))}
            resp = audit / "findings" / "respinti.json"
            gone = base - now - ({f["id"] for f in json.loads(resp.read_text(encoding="utf-8"))} if resp.exists() else set())
            add("base del rapido (findings/rapido.json)", "DA VERIFICARE" if gone else "OK",
                (f"{len(gone)} finding del rapido spariti senza smentita che li respinga: {', '.join(sorted(gone)[:8])}") if gone
                else f"{len(base)} finding del rapido, {len(now)} ora")
            import checklist
            if not gone and now <= base and "nessun nuovo finding" not in checklist.risposte(audit).lower():
                add(f"finding aggiunti dalla modalità {mode}", "DA VERIFICARE",
                    f"gli stessi {len(base)} del rapido: threat model, approfondimento delle aree «parziale» e prove dinamiche "
                    "non hanno aggiunto nulla. Se è corretto, scrivi in revisione.md sotto «## Risposte» «nessun nuovo finding» e il perché")
        except (OSError, ValueError, KeyError, TypeError):
            add("base del rapido (findings/rapido.json)", "DA VERIFICARE", "file illeggibile")
    if "dinamic" in mod and "non" not in mod.split("dinamic")[0][-12:]:
        ep = real_rows("endpoint-matrix.csv")
        done = [r for r in ep if (r.get("test_eseguito") or "").strip().lower() in ("si", "sì")]
        add("test dinamici registrati nella matrice endpoint", "OK" if done else "DA VERIFICARE",
            f"{len(done)} righe con test eseguito" if done else "il mandato prevede test dinamici ma nessuna riga di endpoint-matrix.csv ha test_eseguito=si "
            "(dynamic_authz_check.py --update-matrix, o riga scritta a mano con comando ed esito)")


def tempi(audit: Path):
    """Durata dell'audit: dall'inizio (registro-tool/tempi.json, scritto da init_audit/init_gdpr) a questa chiusura;
    pre-passaggio dai secondi registrati per ogni passo. Informativo: non è un controllo e non fa fallire nulla."""
    import time
    from datetime import datetime
    reg = audit / "registro-tool"
    t = {}
    try:
        t = json.loads((reg / "tempi.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    pre = 0.0
    for n in ("prepass.json", "gdpr-prepass.json"):
        try:
            pre += sum(float(x.get("secondi") or 0) for x in json.loads((reg / n).read_text(encoding="utf-8")).get("passi", []))
        except (OSError, ValueError, AttributeError):
            pass
    try:
        inizio = datetime.fromisoformat(t["inizio"]).timestamp()
    except (KeyError, ValueError, TypeError):
        print(f"\ntempi: pre-passaggio {pre:.0f} s; durata totale non disponibile (manca registro-tool/tempi.json: cartella creata senza init)")
        return
    tot = time.time() - inizio
    t.setdefault("chiusure", []).append({"quando": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "minuti_dall_inizio": round(tot / 60, 1),
                                         "secondi_prepass": round(pre, 1)})
    try:
        (reg / "tempi.json").write_text(json.dumps(t, indent=1, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass
    print(f"\ntempi: {tot / 60:.0f} min dall'inizio a questa chiusura · pre-passaggio {pre:.0f} s · resto (lettura, finding, report) "
          f"{max(tot - pre, 0) / 60:.0f} min (registro-tool/tempi.json; include le pause, se ce ne sono state)")


def finish(a) -> int:
    nf = sum(s == "FALLITO" for _, s, _ in results)
    nw = sum(s == "DA VERIFICARE" for _, s, _ in results)
    if getattr(a, "audit", None) and Path(a.audit).is_dir():
        tempi(Path(a.audit))
    print(f"\nesito: {len(results) - nf - nw} ok · {nw} da verificare · {nf} falliti")
    print("Controlli meccanici: non provano che l'audit sia corretto. Rileggi il report; nei messaggi di chat non scrivere mai valori di segreti.")
    if a.json:
        a.json.write_text(json.dumps([{"controllo": n, "esito": s, "dettaglio": d} for n, s, d in results], ensure_ascii=False, indent=2), encoding="utf-8")
    return 1 if nf or (a.strict and nw) else 0


if __name__ == "__main__":
    sys.exit(main())
