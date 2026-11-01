#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Banco indipendente su OWASP Juice Shop: vulnerabilità documentate da altri, con file e riga esatti.

Uso:
    python3 tests/bench-juice/juice_bench.py prepare <cartella> [--source <clone di juice-shop>]
    python3 tests/bench-juice/juice_bench.py score <cartella>/juice-truth.bin <audit> [<audit> …]

Perché: i banchi tests/bench-app sono scritti da noi con le stesse classi di difetti su cui la checklist fa domande,
quindi misurano l'applicazione della skill, non la generalizzazione. Juice Shop marca nel sorgente le righe vulnerabili
delle sue sfide di codice («vuln-code-snippet vuln-line <sfida>»): è una verità scritta da altri, con la posizione.

`prepare` (senza --source clona github.com/juice-shop/juice-shop al commit fissato):
  - legge i marcatori e salva la verità in <cartella>/juice-truth.bin (compressa: non va data all'agente);
  - toglie dalla copia i marcatori (le righe restano, i numeri di riga non cambiano), le soluzioni, i suggerimenti,
    le descrizioni delle sfide, i test, le istruzioni per agenti e la storia Git;
  - sostituisce i nomi delle sfide nel codice (es. challenges.loginAdminChallenge → challenges.c017), che altrimenti
    direbbero all'agente dove guardare.
`score`: una vulnerabilità è trovata se un finding cita lo stesso file e una riga entro 3 dalle righe vulnerabili;
si stampa anche la misura «vicino» (entro 15 righe), perché un finding corretto spesso cita l'inizio della funzione.
Limiti: Juice Shop è un'app didattica (molto più densa di difetti di un'app reale); le vulnerabilità con marcatori sono
una parte di quelle documentate (le altre non hanno una posizione nel codice); la chiamata che segna una sfida come
risolta resta nel codice, anche se con il nome nascosto.
"""
import base64
import json
import re
import shutil
import subprocess
import sys
import zlib
from pathlib import Path

REPO = "https://github.com/juice-shop/juice-shop.git"
COMMIT = "717f5ef"
NEAR = 15   # seconda misura, meno severa: un finding che cita l'inizio della funzione è a 5-10 righe dalla riga marcata
MARK = re.compile(r"\s*(//|#|<!--|/\*)\s*vuln-code-snippet\b[^\n]*?(-->|\*/)?\s*$")
DROP = ["SOLUTIONS.md", "REFERENCES.md", "HALL_OF_FAME.md", "AGENTS.md", "CONTRIBUTING.md", "threat-model.json", ".ai", ".github",
        "test", "cypress.config.ts", "data/static/codefixes", "data/static/challenges.yml", "data/static/i18n", "frontend/src/assets/i18n",
        "screenshots", ".git", "node_modules", "ctf.key", "rsn", "lib/codingChallenges.ts", "frontend/src/app/coding-challenge-page",
        "frontend/src/app/Services/vuln-lines.service.ts", "frontend/src/app/Services/code-snippet.service.ts", "routes/vulnCodeSnippet.ts",
        "routes/vulnCodeFixes.ts", "data/static/web3-snippets"]
TEXT = {".ts", ".js", ".html", ".yml", ".yaml", ".json", ".tf", ".sql", ".md", ".hbs", ".pug", ".mjs", ".cjs", ".txt", ".xml", ".sh"}


def obtain(source, work):
    if source:
        return Path(source)
    src = work / "_juice-src"
    if not src.exists():
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", REPO, str(src)], check=True)
        subprocess.run(["git", "-C", str(src), "checkout", "-q", COMMIT], check=True)
    return src


def extract_truth(src):
    truth = {}
    for p in sorted(src.rglob("*")):
        rel = p.relative_to(src).as_posix()
        if not p.is_file() or p.suffix.lower() not in TEXT or rel.split("/")[0] in ("node_modules", ".git", "test", ".ai") or "codefixes" in rel:
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for n, line in enumerate(lines, 1):
            for m in re.finditer(r"vuln-code-snippet vuln-line ([\w ]+?)\s*(?:-->|\*/|$)", line):
                for key in m.group(1).split():
                    truth.setdefault(key, {}).setdefault(rel, []).append(n)
    return truth


def prepare(dest, source):
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    app = dest / "juice-app"
    if app.exists():
        sys.exit(f"esiste già: {app}")
    src = obtain(source, dest)
    truth = extract_truth(src)
    keys = sorted({k for k in truth} | {m for p in src.rglob("*.ts") if "node_modules" not in p.parts
                                        for m in re.findall(r"challenges\.(\w+Challenge)\b", p.read_text(encoding="utf-8", errors="replace"))})
    alias = {k: f"c{i:03d}" for i, k in enumerate(keys, 1)}
    shutil.copytree(src, app, ignore=shutil.ignore_patterns("node_modules", ".git"))
    for d in DROP:
        t = app / d
        if t.is_dir():
            shutil.rmtree(t, ignore_errors=True)
        elif t.exists():
            t.unlink()
    for p in app.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in TEXT:
            continue
        if p.name.endswith((".spec.ts", ".test.ts")):
            p.unlink(); continue
        txt = p.read_text(encoding="utf-8", errors="replace")
        new = "\n".join(MARK.sub("", ln) if "vuln-code-snippet" in ln else ln for ln in txt.split("\n"))
        new = re.sub(r"challenges\.(\w+Challenge)\b", lambda m: "challenges." + alias.get(m.group(1), "cx"), new)
        new = re.sub(r"\b(\w+Challenge)\b", lambda m: alias.get(m.group(1), m.group(1)), new)
        new = new.replace("vuln-code-snippet", "code-annotation")   # resta solo in codice che toglie i marcatori (server.ts)
        if new != txt:
            p.write_text(new, encoding="utf-8")
    left = [str(p.relative_to(app)) for p in app.rglob("*") if p.is_file() and p.suffix.lower() in TEXT
            and "vuln-code-snippet" in p.read_text(encoding="utf-8", errors="replace")]
    if left:
        sys.exit(f"marcatori rimasti in: {left[:5]}")
    g = lambda *a: subprocess.run(["git", "-C", str(app), "-c", "user.email=b@example.test", "-c", "user.name=b", *a], capture_output=True, text=True)
    g("init", "-q"); g("add", "-A"); g("commit", "-qm", "import")
    blob = base64.b64encode(zlib.compress(json.dumps({"commit": COMMIT, "truth": truth}).encode()))
    (dest / "juice-truth.bin").write_bytes(blob)
    n = sum(len(v) for v in truth.values())
    print(f"pronto: {app}\n{len(truth)} vulnerabilità con posizione ({n} file coinvolti) salvate in {dest / 'juice-truth.bin'} (non darlo all'agente).")


def load_findings(a):
    a = Path(a)
    for p in (a / "findings" / "findings.json", a / "findings.json"):
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    sys.exit(f"nessun findings.json in {a}")


def refs(f):
    out = []
    for r in (f.get("prova") or {}).get("riferimenti_file") or []:
        m = re.match(r"\s*\.?/?([^:\s]+)(?::(\d+)(?:-(\d+))?)?", str(r))
        if m:
            a_ = int(m.group(2)) if m.group(2) else None
            out.append((m.group(1), a_, int(m.group(3)) if m.group(3) else a_))
    return out


def score(truthfile, audits):
    truth = json.loads(zlib.decompress(base64.b64decode(Path(truthfile).read_bytes())))["truth"]
    res = {}
    for a in audits:
        fs = load_findings(a)
        found, near = {}, {}
        for key, files in truth.items():
            for f in fs:
                for path, l1, l2 in refs(f):
                    for tf, lines in files.items():
                        if not ((path == tf or path.endswith("/" + tf) or tf.endswith("/" + path)) and l1):
                            continue
                        if any(l1 - 3 <= ln <= (l2 or l1) + 3 for ln in lines):
                            found.setdefault(key, set()).add(f["id"])
                        if any(l1 - NEAR <= ln <= (l2 or l1) + NEAR for ln in lines):
                            near.setdefault(key, set()).add(f["id"])
        res[a] = found
        locs = {tuple(sorted((f, tuple(l)) for f, l in v.items())) for v in truth.values()}
        locs_found = {tuple(sorted((f, tuple(l)) for f, l in truth[k].items())) for k in found}
        print(f"== {a}\n  vulnerabilità di Juice Shop trovate con file e riga: {len(found)}/{len(truth)} "
              f"(posizioni distinte: {len(locs_found)}/{len(locs)}) · finding totali: {len(fs)}")
        print(f"  vicino (stesso file, entro {NEAR} righe): {len(near)}/{len(truth)} — il finding cita la funzione o il blocco, non la riga marcata")
        miss = sorted(set(truth) - set(found))
        print("  mancate:", ", ".join(f"{k} ({', '.join(truth[k])})" for k in miss[:40]))
    if len(audits) > 1:
        sets = [set(res[a]) for a in audits]
        u, i = set().union(*sets), set.intersection(*sets)
        print(f"\ntrovate da almeno un giro: {len(u)}/{len(truth)} · da tutti: {len(i)}")
    return 0


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("prepare", "score"):
        print(__doc__); return 2
    if sys.argv[1] == "prepare":
        src = sys.argv[sys.argv.index("--source") + 1] if "--source" in sys.argv else None
        prepare(sys.argv[2], src); return 0
    return score(sys.argv[2], sys.argv[3:])


if __name__ == "__main__":
    sys.exit(main())
