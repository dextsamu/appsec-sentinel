#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Controlli statici su infrastruttura come codice: Dockerfile, docker-compose, Kubernetes, Terraform, GitHub Actions.

Uso:
    python3 iac_check.py <cartella> [--sarif iac.sarif] [--json iac.json]
    python3 import_scanner.py --sarif iac.sarif --out candidati.json

Regole a pattern, poche e di alta precisione (id IAC-*). Sono indizi: ogni riga resta «ipotesi da validare»
(un `USER` può arrivare da un'immagine base, un 0.0.0.0/0 può essere voluto). Non sostituisce trivy/checkov/tfsec.
I valori di segreti non vengono mai riportati: solo file, riga e nome della variabile.
Sola lettura: non esegue nulla né contatta la rete.
"""
import argparse
import json
import re
import sys
from pathlib import Path

SKIP = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".terraform"}
SECRET_NAME = re.compile(r"(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)", re.I)
PLACEHOLDER = re.compile(r"^\s*[\"']?(\$\{?[\w:-]+\}?|<.*>|changeme.*|xxx+|\s*)[\"']?\s*$", re.I)
DB_PORTS = {"5432", "3306", "6379", "27017", "9200", "1433", "5984"}

# (id, livello, titolo, cwe)
R = {
    "IAC-001": ("warning", "Container eseguito come root (nessuna istruzione USER)", "CWE-250"),
    "IAC-002": ("note", "Immagine base senza tag fisso (latest o assente)", "CWE-1357"),
    "IAC-003": ("warning", "Segreto con valore in chiaro in ENV/ARG/environment", "CWE-798"),
    "IAC-004": ("warning", "Scarica ed esegue script remoto senza verifica (curl|sh)", "CWE-494"),
    "IAC-005": ("error", "Container privilegiato o con accesso al socket Docker", "CWE-250"),
    "IAC-006": ("warning", "Porta di un database pubblicata su tutte le interfacce", "CWE-668"),
    "IAC-007": ("warning", "Kubernetes: root, privilege escalation o hostNetwork/hostPath", "CWE-250"),
    "IAC-008": ("error", "Terraform: ingresso aperto a 0.0.0.0/0 su porta di amministrazione o database", "CWE-284"),
    "IAC-009": ("warning", "Terraform: risorsa pubblica o non cifrata", "CWE-311"),
    "IAC-010": ("warning", "Terraform: segreto codificato nel file", "CWE-798"),
    "IAC-011": ("error", "GitHub Actions: pull_request_target con checkout del codice della PR", "CWE-94"),
    "IAC-012": ("note", "GitHub Actions: azione di terzi non fissata a un commit", "CWE-829"),
    "IAC-013": ("warning", "GitHub Actions: input non fidato dell'evento usato in uno step run", "CWE-94"),
    "IAC-014": ("warning", "GitHub Actions: permessi di scrittura estesi al token", "CWE-732"),
}


def lines_of(p):
    try:
        return p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def val_after(line):
    m = re.search(r"[:=]\s*(.*)$", line)
    return m.group(1) if m else ""


def check_docker(p, L, add):
    froms = [(i, l) for i, l in enumerate(L, 1) if re.match(r"\s*FROM\s", l, re.I)]
    if froms and not any(re.match(r"\s*USER\s+(?!root\b|0\b)\S+", l, re.I) for l in L):
        add("IAC-001", p, froms[-1][0], "nessuna USER non-root nell'ultimo stadio")
    for i, l in froms:
        img = re.sub(r"(?i)^\s*FROM\s+(--\S+\s+)*", "", l).split()[0] if l.split() else ""
        if img.lower() != "scratch" and not img.startswith("$") and "@sha256:" not in img and (":" not in img.rsplit("/", 1)[-1] or img.endswith(":latest")):
            if not any(re.search(rf"(?i)\bAS\s+{re.escape(img)}\b", x) for _, x in froms):
                add("IAC-002", p, i, f"immagine {img}")
    for i, l in enumerate(L, 1):
        m = re.match(r"\s*(ENV|ARG)\s+([A-Z0-9_]*)(?:[= ]\s*(.+))?$", l, re.I)
        if m and SECRET_NAME.search(m.group(2) or "") and m.group(3) and not PLACEHOLDER.match(m.group(3)):
            add("IAC-003", p, i, f"variabile {m.group(2)} (valore non riportato)")
        if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba)?sh\b", l):
            add("IAC-004", p, i, "pipe di curl/wget verso shell")


def check_compose(p, L, add):
    for i, l in enumerate(L, 1):
        if re.match(r"\s*privileged:\s*true", l) or "docker.sock" in l:
            add("IAC-005", p, i, "privileged: true" if "privileged" in l else "mount del socket Docker")
        m = re.match(r"\s*-?\s*[\"']?(?:(\d+\.\d+\.\d+\.\d+):)?(\d+):(\d+)", l)
        if m and m.group(3) in DB_PORTS and m.group(1) in (None, "0.0.0.0") and re.match(r"\s*-\s*[\"']?\d", l):
            add("IAC-006", p, i, f"porta {m.group(3)} pubblicata senza 127.0.0.1")
        m = re.match(r"\s*-?\s*([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY)[A-Z0-9_]*)\s*[:=]\s*(.+)$", l)
        if m and not PLACEHOLDER.match(m.group(2)):
            add("IAC-003", p, i, f"variabile {m.group(1)} (valore non riportato)")


def check_k8s(p, L, add):
    for i, l in enumerate(L, 1):
        if re.match(r"\s*(privileged|allowPrivilegeEscalation|hostNetwork|hostPID):\s*true", l) or re.match(r"\s*runAsNonRoot:\s*false", l) or re.match(r"\s*runAsUser:\s*0\b", l) or re.match(r"\s*hostPath:", l):
            add("IAC-007", p, i, l.strip()[:60])


def check_tf(p, L, add):
    blk_cidr = False
    for i, l in enumerate(L, 1):
        if re.search(r"cidr_blocks\s*=\s*\[[^\]]*\"0\.0\.0\.0/0\"", l):
            ctx = "\n".join(L[max(0, i - 8):i + 4])
            if re.search(r"(from_port|to_port)\s*=\s*(22|3389|3306|5432|6379|27017|0)\b", ctx) and "egress" not in ctx.split("cidr_blocks")[0][-120:]:
                add("IAC-008", p, i, "0.0.0.0/0 con porta sensibile")
        if re.search(r"acl\s*=\s*\"public-read(-write)?\"|publicly_accessible\s*=\s*true|(encrypted|storage_encrypted|enable_key_rotation)\s*=\s*false", l):
            add("IAC-009", p, i, l.strip()[:60])
        m = re.match(r"\s*(\w*(?:password|secret|access_key|token)\w*)\s*=\s*\"([^\"$]{4,})\"", l, re.I)
        if m:
            add("IAC-010", p, i, f"attributo {m.group(1)} (valore non riportato)")


def check_gha(p, L, add):
    txt = "\n".join(L)
    if re.search(r"(?m)^\s*pull_request_target\b|^\s*on:\s*\[?.*pull_request_target", txt):
        for i, l in enumerate(L, 1):
            if re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", l):
                add("IAC-011", p, i, "checkout/uso del codice della PR in un contesto con segreti")
    for i, l in enumerate(L, 1):
        m = re.match(r"\s*-?\s*uses:\s*([\w./-]+)@(\S+)", l)
        if m and not m.group(1).startswith(("actions/", "./", "github/")) and not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
            add("IAC-012", p, i, f"{m.group(1)}@{m.group(2)}")
        if re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit)\.[\w.]*(title|body|message|name|ref)\s*\}\}", l) and not re.match(r"\s*(if|name):", l):
            add("IAC-013", p, i, "espressione dell'evento interpolata nello script")
        if re.match(r"\s*permissions:\s*write-all", l):
            add("IAC-014", p, i, "permissions: write-all")


def kind(p, L):
    n = p.name.lower()
    if n == "dockerfile" or n.startswith("dockerfile.") or n.endswith(".dockerfile"):
        return check_docker
    if n.endswith(".tf"):
        return check_tf
    if n.endswith((".yml", ".yaml")):
        if ".github" in p.parts and "workflows" in p.parts:
            return check_gha
        head = "\n".join(L[:200])
        if n.startswith(("docker-compose", "compose")) or re.search(r"(?m)^services:\s*$", head):
            return check_compose
        if re.search(r"(?m)^kind:\s*(Deployment|StatefulSet|DaemonSet|Pod|Job|CronJob)\b", head):
            return check_k8s
    return None


def scan(root):
    out = []

    def add(rid, p, line, detail):
        out.append({"ruleId": rid, "level": R[rid][0], "message": f"{R[rid][1]}: {detail}", "file": str(p.relative_to(root)), "line": line, "cwe": R[rid][2]})

    for p in sorted(root.rglob("*")):
        if not p.is_file() or any(s in p.relative_to(root).parts for s in SKIP):
            continue
        n = p.name.lower()
        if not (n.endswith((".yml", ".yaml", ".tf")) or "dockerfile" in n):
            continue
        L = lines_of(p)
        fn = kind(p, L)
        if fn:
            fn(p, L, add)
    return out


def to_sarif(res):
    rules = {r["ruleId"] for r in res}
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "iac_check (appsec-sentinel)", "rules": [{"id": i, "shortDescription": {"text": R[i][1]}, "properties": {"tags": [R[i][2]]}} for i in sorted(rules)]}},
        "results": [{"ruleId": r["ruleId"], "level": r["level"], "message": {"text": r["message"]},
                     "locations": [{"physicalLocation": {"artifactLocation": {"uri": r["file"]}, "region": {"startLine": r["line"]}}}]} for r in res]}]}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", type=Path)
    ap.add_argument("--sarif", type=Path)
    ap.add_argument("--json", type=Path)
    a = ap.parse_args()
    if not a.repo.is_dir():
        sys.exit(f"cartella non trovata: {a.repo}")
    res = scan(a.repo)
    print(f"indizi IaC: {len(res)} (tutti da validare)")
    for r in res[:50]:
        print(f"  - {r['ruleId']} {r['file']}:{r['line']}  {r['message']}")
    if a.sarif:
        a.sarif.write_text(json.dumps(to_sarif(res), indent=1, ensure_ascii=False), encoding="utf-8"); print(f"scritto: {a.sarif}")
    if a.json:
        a.json.write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8"); print(f"scritto: {a.json}")


if __name__ == "__main__":
    main()
