#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Importa l'output di scanner esistenti come CANDIDATI finding (mai come finding confermati).

Uso:
    python3 import_scanner.py --npm-audit audit.json --out candidati.json [--merge findings.json]
    python3 import_scanner.py --sarif semgrep.sarif --gitleaks gitleaks.json --osv osv.json --out candidati.json
    python3 import_scanner.py --semgrep semgrep.json --trivy trivy.json --zap zap.json --out candidati.json

Formati: `npm audit --json`, SARIF 2.1.0 (semgrep, trivy, codeql...), gitleaks JSON, osv-scanner JSON,
`semgrep --json`, `trivy ... -f json` (vulnerabilità, misconfigurazioni, segreti), report JSON di OWASP ZAP.
ZAP e le altre scansioni dinamiche sono importate comunque come «ipotesi da validare»: l'importazione non le riproduce.
Regole di onestà applicate:
  - stato sempre «ipotesi da validare», confidenza «bassa»: lo scanner non prova la raggiungibilità;
  - severità provvisoria dal solo scanner e mai oltre «media» finché non validata a mano;
  - per i segreti NON viene letto né scritto il valore: solo regola, file e riga;
  - con --merge i candidati si aggiungono a un findings.json esistente senza duplicare (stesso titolo e asset)
    e con ID nuovi (prefisso SCN-).
Dopo l'import: validare ogni candidato, alzare o scartare, poi eseguire validate_findings.py.
"""
import argparse
import json
import sys
from pathlib import Path

CAP = {"critical": "media", "high": "media", "critica": "media", "alta": "media", "moderate": "media", "medium": "media",
       "warning": "media", "error": "media", "low": "bassa", "note": "bassa", "info": "informativa", "none": "informativa"}


def base(titolo, categoria, asset, sev, prova, riferimenti, osservato, cwe=None, correzione="Verificare la raggiungibilità e applicare la correzione indicata dallo strumento."):
    f = {"id": "", "titolo": titolo, "categoria": categoria, "asset": asset, "ambiente": "repository (analisi statica)", "versione": "da indicare",
         "stato": "ipotesi da validare", "severita": CAP.get(str(sev).lower(), "bassa"), "attore": "da determinare",
         "prova": {"tipo": "log-tool", "descrizione": prova, "riferimenti_file": riferimenti, "test_eseguito": False},
         "atteso": "Nessuna vulnerabilità raggiungibile nel componente.", "osservato": osservato,
         "impatto": {"reale": "Non dimostrato.", "potenziale": "Dipende dalla raggiungibilità del componente, da verificare.",
                     "condizioni_limitanti": "Output di scanner non validato."},
         "motivazione_severita": "Provvisoria: derivata dal solo scanner e limitata a «media» finché non validata a mano.",
         "intervento": {"correzione": correzione}, "retest": "Rieseguire lo scanner e verificare a mano la raggiungibilità.",
         "limiti": "Candidato da scanner: raggiungibilità, configurazione e mitigazioni a monte non verificate.", "confidenza": "bassa"}
    if cwe:
        f["cwe"] = cwe
    return f


def from_npm(d):
    out = []
    for name, v in (d.get("vulnerabilities") or {}).items():
        via = [x for x in v.get("via", []) if isinstance(x, dict)]
        adv = ", ".join(sorted({x.get("url", "").rsplit("/", 1)[-1] for x in via if x.get("url")}))[:200]
        fix = v.get("fixAvailable")
        corr = "Aggiornare" + (f" a {fix.get('name')}@{fix.get('version')}" if isinstance(fix, dict) else " alla versione corretta") + " e rieseguire npm audit."
        out.append(base(f"Dipendenza {name} con advisory noti", "dipendenze", f"package-lock.json · {name}", v.get("severity", "low"),
                        f"npm audit: {len(via)} advisory ({adv or 'vedi output'}) nell'intervallo {v.get('range', '?')}.", ["package-lock.json"],
                        f"Versione nell'intervallo vulnerabile secondo npm audit; raggiungibilità non valutata.", correzione=corr))
    return out


def from_sarif(d):
    out = []
    for run in d.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", "scanner")
        for r in run.get("results", []):
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "?")
            line = loc.get("region", {}).get("startLine", "")
            ref = f"{uri}:{line}" if line else uri
            msg = (r.get("message", {}).get("text") or r.get("ruleId", ""))[:160]
            out.append(base(f"{tool}: {r.get('ruleId', 'regola')}", "codice", uri, r.get("level", "warning"),
                            f"{tool} segnala {r.get('ruleId', '')} in {ref}: {msg}", [ref], msg))
    return out


def from_gitleaks(d):
    out = []
    for r in d if isinstance(d, list) else []:
        ref = f"{r.get('File', '?')}:{r.get('StartLine', '')}".rstrip(":")
        out.append(base(f"Possibile segreto esposto ({r.get('RuleID', 'regola')})", "segreti", r.get("File", "?"), "medium",
                        f"gitleaks regola {r.get('RuleID', '?')} in {ref}. Valore non riportato.", [ref],
                        "Pattern di segreto rilevato; non verificato se reale, se attivo o se solo di esempio.",
                        cwe=["CWE-798"], correzione="Verificare se è reale; se sì ruotarlo, rimuoverlo dal repository e dalla cronologia."))
    return out


def from_osv(d):
    out = []
    for res in d.get("results", []):
        for pk in res.get("packages", []):
            p = pk.get("package", {})
            vulns = pk.get("vulnerabilities", [])
            ids = ", ".join(v.get("id", "") for v in vulns[:6])
            out.append(base(f"Dipendenza {p.get('name', '?')} {p.get('version', '')} con vulnerabilità note", "dipendenze",
                            f"{p.get('ecosystem', '')}/{p.get('name', '?')}", "medium", f"osv-scanner: {len(vulns)} voci ({ids}).",
                            [res.get("source", {}).get("path", "lockfile")], "Versione presente in database di vulnerabilità; raggiungibilità non valutata."))
    return out


def from_semgrep(d):
    out = []
    for r in d.get("results", []):
        ex = r.get("extra", {}) or {}
        ref = f"{r.get('path', '?')}:{(r.get('start') or {}).get('line', '')}".rstrip(":")
        cwe = ex.get("metadata", {}).get("cwe")
        cwe = [str(c).split(":")[0] for c in (cwe if isinstance(cwe, list) else [cwe] if cwe else [])][:3] or None
        msg = (ex.get("message") or r.get("check_id", ""))[:160]
        out.append(base(f"semgrep: {r.get('check_id', 'regola').rsplit('.', 1)[-1]}", "codice", r.get("path", "?"), ex.get("severity", "WARNING"),
                        f"semgrep regola {r.get('check_id', '?')} in {ref}: {msg}", [ref], msg, cwe=cwe))
    return out


def from_trivy(d):
    out = []
    for res in d.get("Results", []) if isinstance(d, dict) else []:
        tgt = res.get("Target", "?")
        pk = {}
        for v in res.get("Vulnerabilities") or []:
            pk.setdefault((v.get("PkgName", "?"), v.get("InstalledVersion", "")), []).append(v)
        for (name, ver), vs in pk.items():
            ids = ", ".join(v.get("VulnerabilityID", "") for v in vs[:6])
            sev = max((v.get("Severity", "LOW") for v in vs), key=lambda s: ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(s) if s in ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"] else 0)
            fix = next((v.get("FixedVersion") for v in vs if v.get("FixedVersion")), None)
            out.append(base(f"Dipendenza {name} {ver} con vulnerabilità note", "dipendenze", f"{tgt} · {name}", sev,
                            f"trivy: {len(vs)} voci ({ids}) in {tgt}.", [tgt], "Versione presente in database di vulnerabilità; raggiungibilità non valutata.",
                            correzione="Aggiornare" + (f" a {fix}" if fix else " alla versione corretta") + " e rieseguire trivy."))
        for m in res.get("Misconfigurations") or []:
            ref = f"{tgt}:{(m.get('CauseMetadata') or {}).get('StartLine', '')}".rstrip(":")
            out.append(base(f"trivy: {m.get('ID', 'misconfigurazione')} {m.get('Title', '')}".strip(), "configurazione", tgt, m.get("Severity", "LOW"),
                            f"trivy misconfigurazione {m.get('ID', '?')} in {ref}: {(m.get('Message') or '')[:140]}", [ref], (m.get("Message") or "")[:160]))
        for s in res.get("Secrets") or []:
            ref = f"{tgt}:{s.get('StartLine', '')}".rstrip(":")
            out.append(base(f"Possibile segreto esposto ({s.get('RuleID', 'regola')})", "segreti", tgt, "medium",
                            f"trivy regola {s.get('RuleID', '?')} in {ref}. Valore non riportato.", [ref],
                            "Pattern di segreto rilevato; non verificato se reale, se attivo o se solo di esempio.", cwe=["CWE-798"],
                            correzione="Verificare se è reale; se sì ruotarlo, rimuoverlo dal repository e dalla cronologia."))
    return out


def from_zap(d):
    out = []
    risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    for site in d.get("site", []) if isinstance(d, dict) else []:
        for al in site.get("alerts", []):
            insts = al.get("instances", [])
            uris = sorted({f"{i.get('method', '')} {i.get('uri', '')}".strip() for i in insts})[:5]
            cwe = [f"CWE-{al['cweid']}"] if str(al.get("cweid", "")).isdigit() and al.get("cweid") != "-1" else None
            # niente «evidence» né «attack»: possono contenere payload o dati reali
            out.append(base(f"ZAP: {al.get('alert') or al.get('name', 'allarme')}", "applicazione", site.get("@name", "sito"), risk.get(str(al.get("riskcode", "0")), "low"),
                            f"OWASP ZAP segnala «{al.get('alert') or al.get('name', '')}» su {len(insts)} istanze (es. {'; '.join(uris[:3])}). Scansione non riprodotta da noi.",
                            uris[:3] or ["report ZAP"], (al.get("riskdesc") or "")[:120] + ": da validare a mano su ambiente autorizzato.", cwe=cwe))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--npm-audit", type=Path)
    ap.add_argument("--sarif", type=Path, action="append", default=[])
    ap.add_argument("--gitleaks", type=Path)
    ap.add_argument("--osv", type=Path)
    ap.add_argument("--semgrep", type=Path)
    ap.add_argument("--trivy", type=Path)
    ap.add_argument("--zap", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--merge", type=Path)
    a = ap.parse_args()
    cands = []
    if a.npm_audit:
        cands += from_npm(json.loads(a.npm_audit.read_text(encoding="utf-8")))
    for s in a.sarif:
        cands += from_sarif(json.loads(s.read_text(encoding="utf-8")))
    if a.gitleaks:
        cands += from_gitleaks(json.loads(a.gitleaks.read_text(encoding="utf-8")))
    if a.osv:
        cands += from_osv(json.loads(a.osv.read_text(encoding="utf-8")))
    if a.semgrep:
        cands += from_semgrep(json.loads(a.semgrep.read_text(encoding="utf-8")))
    if a.trivy:
        cands += from_trivy(json.loads(a.trivy.read_text(encoding="utf-8")))
    if a.zap:
        cands += from_zap(json.loads(a.zap.read_text(encoding="utf-8")))
    existing = json.loads(a.merge.read_text(encoding="utf-8")) if a.merge and a.merge.exists() else []
    seen = {(f["titolo"], f["asset"]) for f in existing}
    used = {f["id"] for f in existing}
    n, added = 0, []
    for c in cands:
        if (c["titolo"], c["asset"]) in seen:
            continue
        while True:
            n += 1
            nid = f"SCN-{n:03d}"
            if nid not in used:
                break
        c["id"] = nid; used.add(nid); seen.add((c["titolo"], c["asset"])); added.append(c)
    result = existing + added if a.merge else added
    a.out.write_text(json.dumps(result, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"candidati importati: {len(added)} (duplicati saltati: {len(cands) - len(added)}) -> {a.out}")
    print("Sono ipotesi da validare: severità provvisoria, nessun valore di segreto riportato.")


if __name__ == "__main__":
    main()
