#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Ricerca e classificazione dei possibili segreti nella storia Git, senza mai riportarne il valore.

Uso diretto (di norma lo chiama `run_scanners.py history`):
    python3 secret_triage.py <repo> [--json]

Perché: i pattern da soli segnalano anche password di esempio, segnaposto, variabili d'ambiente e valori di sviluppo
copiati ovunque. Qui ogni occorrenza riceve un punteggio da indizi verificabili e dichiarati nel report:
  + formato di un fornitore (ghp_, AKIA, sk_live_, chiave privata, xox…);
  + alta entropia e lunghezza adeguata del valore (+1 se il nome della variabile è da segreto: JWT_SECRET, API_KEY…);
  + file di configurazione reale (.env senza «example»), host remoto in una stringa di connessione;
  - valore da dizionario o segnaposto (password, changeme, your-…, example, test, demo, postgres…);
  - bassa entropia o valore corto;
  - file di documentazione, esempio, template, test, seed o fixture;
  - stesso valore debole in 3 o più file (valore di sviluppo condiviso); se invece il valore è casuale, la ripetizione
    alza il punteggio: un segreto reale copiato in script e documentazione è il caso peggiore;
  - host locale con credenziali banali.
I riferimenti a variabili (${VAR}, process.env.X, os.environ[...]) non sono valori e vengono scartati.
Esito per file: «in cima» (punteggio ≥ 3, severità media), «da guardare» (0–2, bassa) o «probabile esempio»
(< 0, raccolti in un'unica voce informativa con l'elenco dei file). Il valore resta solo in memoria: in uscita
compaiono file, commit brevi, tipo, motivi e un'impronta corta (8 caratteri di SHA-256) per riconoscere i duplicati.
Le cartelle di dipendenze vendorizzate (node_modules, vendor, site-packages…) sono escluse e contate a parte:
contengono chiavi di test delle librerie, non segreti del progetto. Fuori dai file di configurazione (.env, .ini, .yml,
.sh…) contano solo i letterali stringa e le righe in stile variabile d'ambiente (NOME_MAIUSCOLO=valore), comuni nella documentazione. Euristico: un punteggio basso non prova che il valore sia innocuo, uno alto non prova che sia attivo.
"""
import argparse
import hashlib
import json
import math
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROVIDER = {
    "chiave privata": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    "AWS access key": re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    "token GitHub": re.compile(r"\b((?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    "token GitLab": re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})"),
    "token Slack": re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})"),
    "chiave Stripe live": re.compile(r"\b([sr]k_live_[A-Za-z0-9]{16,})"),
    "chiave Google API": re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"),
    "chiave OpenAI/Anthropic": re.compile(r"\b(sk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,})"),
    "token SendGrid": re.compile(r"\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})"),
    "token npm": re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"),
}
PUTTY = re.compile(r"PuTTY-User-Key-File-\d")
HASH = re.compile(r"(\$(?:2[abxy]|apr1|1|5|6|y)\$[^\s:'\"<>,]{20,})")
XMLTAG = re.compile(r"(?i)<(\w*(?:pass|password|passwd|pwd|secret|token|apikey|api_key)\w*)\b[^>]*>([^<]{4,200})</\1>")
PHPDEFINE = re.compile(r"(?i)define\(\s*['\"](\w*(?:pass|password|secret|key|token|salt)\w*)['\"]\s*,\s*(['\"])(.{4,200}?)\2")
NETRC = re.compile(r"(?i)\bpassword\s+(\S{4,})")
SENSITIVE_FILE = re.compile(r"(?i)(^|/)(\.git-credentials|\.?_?netrc|\.pgpass|\.htpasswd|shadow|master\.key|[^/]*\.ppk|id_(rsa|dsa|ecdsa|ed25519)|"
                            r"\.dockercfg|\.docker/config\.json|\.npmrc|filezilla\.xml|recentservers\.xml|sitemanager\.xml|proftpdpasswd|"
                            r"\.s3cfg|\.aws/credentials|\.credentials|\.tugboat|logins\.json|key[34]\.db|webservers\.xml|sftp-config\.json|"
                            r"\.ftpconfig|\.remote-sync\.json|deployment-config\.json|\.vscode/sftp\.json|\.esmtprc|"
                            r"dbeaver-data-sources\.xml|robomongo\.json|credentials\.json|service-account[^/]*\.json|[^/]*\.keystore|[^/]*\.jks|"
                            r"[^/]*\.p12|[^/]*\.pfx|wp-config\.php|secrets\.ya?ml|\.env)$")
CONN = re.compile(r"\b([a-z][a-z0-9+]+)://([^/\s:@'\"]+):([^/\s@'\"]{3,})@([^/\s:'\"]+)")
ASSIGN = re.compile(r"(?i)([A-Za-z0-9_.\-]*(?:password|passwd|pwd|pass|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credential|auth)[A-Za-z0-9_.\-]*)"
                    r"[\"']?\s*(?::=|=>|=|:)\s*(?:([\"'])((?:(?!\2).){4,300})\2|(`)|([^\s\"'`<>,;)\]}]{4,}))")
AUTH_ONLY = {"auth", "_auth", "authtoken", "_authtoken", "auth_token", "basicauth", "basic_auth", "http_auth"}
BEARER = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{16,})")
JWT = re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})")

VARREF = re.compile(r"^(\$\{?|%\w|process\.env|os\.environ|os\.getenv|env\(|getenv|config\.|settings\.|ENV\[|<|\{\{|import\.meta\.env|Deno\.env|System\.getenv|\$\()", re.I)
PLACEHOLDER = ("your", "changeme", "change-this", "change_me", "changethis", "change_this", "example", "sample", "placeholder", "xxx", "redacted",
               "insert", "replace", "todo", "fixme", "here", "generate", "openssl", "random", "copy", "paste", "enter", "dummy", "fake", "mock",
               "lorem", "foobar", "genera", "copia", "incolla", "inserir", "inserisc", "cambia", "modifica", "sostitu", "tuo", "tua", "qui",
               "esempio", "cambiami", "da_", "<", "***", "...", "…")
WEAK = ("password", "passwd", "secret", "admin", "postgres", "root", "letmein", "qwerty", "12345", "test", "demo", "default", "local",
        "dev", "pass", "user", "guest", "lab-", "prova", "segreto", "chiave", "abc123", "aaaa", "xyz", "mypass")
EXAMPLE_PATH = re.compile(r"(?i)(\.md$|\.mdx$|\.rst$|\.txt$|readme|changelog|\.example|example\.|\.sample|\.template|\.tpl$|\.dist$|"
                          r"(^|/)(test|tests|spec|specs|__tests__|e2e|cypress|playwright|fixtures?|mocks?|docs?|examples?|samples?|seeds?|scratch)/|"
                          r"\.test\.|\.spec\.|(^|/)seed[^/]*$|(^|/)[^/]*seed[^/]*\.(ts|js|mjs|py|sql)$)")
SECRET_NAME = re.compile(r"(?i)(secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|token|password|passwd|credential)")
LOCAL_HOST = re.compile(r"(?i)^(localhost|127\.0\.0\.1|0\.0\.0\.0|db|postgres|mysql|redis|mongo|database|host\.docker\.internal)$")


def entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def fp(v):
    return hashlib.sha256(v.encode("utf-8", "replace")).hexdigest()[:8]


CODE_EXT = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".rb", ".go", ".java", ".cs", ".php", ".kt", ".swift", ".rs", ".scala", ".vue", ".svelte")


CONFIG_EXT = (".env", ".ini", ".conf", ".cfg", ".cnf", ".properties", ".yml", ".yaml", ".toml", ".sh", ".bash", ".zsh", ".ps1",
              ".bashrc", ".bash_profile", ".profile", ".zshrc", ".netrc", ".pgpass", ".npmrc", ".htpasswd", ".txt", ".config", ".tfvars", ".rc")
VENDOR = re.compile(r"(^|/)(node_modules|bower_components|vendor|\.yarn|jspm_packages|site-packages|\.venv|venv|Pods|Carthage|third_party|3rdparty)/")


def config_like(path):
    name = path.rsplit("/", 1)[-1].lower()
    return name.endswith(CONFIG_EXT) or "." not in name.lstrip(".") or re.match(r"\.env(\.|$)", name) is not None


def extract(line, path=""):
    """Restituisce [(tipo, valore, contesto)] trovati in una riga; i riferimenti a variabili sono esclusi."""
    hits, used = [], set()
    code = not config_like(path)   # fuori dai file di configurazione contano solo i letterali stringa
    if PROVIDER["chiave privata"].search(line) or PUTTY.search(line):
        hits.append(("chiave privata", line.strip(), {"provider": True}))
        return hits
    for m in HASH.finditer(line):
        hits.append(("hash di password", m.group(1), {"hash": True})); used.add(m.group(1))
    for m in XMLTAG.finditer(line):
        if not VARREF.match(m.group(2)):
            hits.append(("password o segreto in chiaro", m.group(2), {"nome": m.group(1), "quoted": True})); used.add(m.group(2))
    for m in PHPDEFINE.finditer(line):
        if not VARREF.match(m.group(3)):
            hits.append(("password o segreto in chiaro", m.group(3), {"nome": m.group(1), "quoted": True})); used.add(m.group(3))
    if re.search(r"(?i)(^|/)\.?_?netrc$", path):
        for m in NETRC.finditer(line):
            hits.append(("password o segreto in chiaro", m.group(1), {"nome": "netrc password"})); used.add(m.group(1))
    for kind, rx in PROVIDER.items():
        if kind == "chiave privata":
            continue
        for m in rx.finditer(line):
            hits.append((kind, m.group(1), {"provider": True})); used.add(m.group(1))
    for m in CONN.finditer(line):
        user, pw, host = m.group(2), m.group(3), m.group(4)
        if VARREF.match(pw) or pw in used:
            continue
        hits.append(("stringa di connessione con password", pw, {"host": host, "user": user})); used.add(pw)
    for m in BEARER.finditer(line):
        v = m.group(1)
        if not VARREF.match(v) and v not in used:
            hits.append(("token Bearer", v, {"nome": "Authorization Bearer"})); used.add(v)
    for m in JWT.finditer(line):
        if m.group(1) not in used:
            hits.append(("JWT", m.group(1), {})); used.add(m.group(1))
    for m in ASSIGN.finditer(line):
        name = m.group(1)
        if m.group(4):
            continue   # template literal: espressione
        quoted = m.group(3) is not None
        val = m.group(3) if quoted else (m.group(5) or "").rstrip(".")
        low_name = name.lower().strip("\"'")
        if "auth" in low_name and not re.search(r"(?i)pass|pwd|secret|token|key|credential", low_name) and low_name.split(".")[-1] not in AUTH_ONLY:
            continue   # «author», «authority», «authMethod»…: non sono segreti
        if re.fullmatch(r"(?i)[\w.\-]*pass[\w.\-]*", low_name) and not re.search(r"(?i)password|passwd|passphrase|^pass$|_pass$|^pass_|userpass|dbpass|pass_?word", low_name):
            continue   # «bypass», «passport», «compass»…
        if not val or len(val) < 4:
            continue
        envstyle = bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", name)) and line[m.start(1) + len(name):m.start(1) + len(name) + 1] == "="
        if not quoted and ((code and not envstyle) or val.startswith(("/", "./", "~/")) or re.search(r"[(\[{]|\$\{|\?\.", val)):
            continue   # nel codice contano solo i letterali; fuori, percorsi ed espressioni non sono valori
        if quoted and re.search(r"\$\{|\{\{|%\(|#\{", val):
            continue   # stringa con interpolazione
        if quoted and (line[m.end():m.end() + 1] == "." or val.count(",") >= 2):
            continue   # letterale usato come lista o con un metodo ('a,b,c'.split): non è un segreto
        if quoted and re.search(r"\s", val.strip()):
            continue   # testo, messaggi o classi CSS: i segreti non contengono spazi (limite: perde le passphrase con spazi)
        if val in used or any(val in u for u in used) or VARREF.match(val) or "://" in val:
            continue
        if re.fullmatch(r"(?i)(true|false|null|none|nil|undefined|required|optional|string|number|bool|boolean|str|int)", val):
            continue
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\(?", val) and not re.search(r"\d", val) and "_" not in val[1:]:
            continue   # identificatore o chiamata: name = otherVariable
        if re.fullmatch(r"[A-Za-z_][\w.]*\.[A-Za-z_]\w*", val):
            continue   # accesso a proprietà: secret = config.jwtSecret
        hits.append(("password o segreto in chiaro", val, {"nome": name, "quoted": quoted})); used.add(val)
    return hits


def file_class(path):
    if EXAMPLE_PATH.search(path) and not SENSITIVE_FILE.search(path.replace(".example", "§")):
        return "esempio"
    if SENSITIVE_FILE.search(path) or re.search(r"(?i)(^|/)\.env\.(prod|production|staging|live|remote)$", path):
        return "credenziali"
    return "altro"


def score(kind, val, ctx, path, nfiles):
    """Due assi: il valore (segnaposto / debole / casuale / formato noto) e il file (credenziali / altro / esempio)."""
    s, why = 0, []
    fc = file_class(path)
    strong = False
    low = val.lower()
    placeholder = next((w for w in PLACEHOLDER if w in low), None) if not ctx.get("provider") else None
    weak = next((w for w in WEAK if w in low), None) if not (ctx.get("provider") or placeholder) else None
    if ctx.get("provider"):
        s += 4; why.append(f"formato riconosciuto ({kind})")
    elif ctx.get("hash"):
        s += 2; why.append("hash di password (attaccabile offline)")
    elif placeholder:
        s -= 4; why.append("segnaposto")
    else:
        ent, n = entropy(val), len(val)
        hexv = bool(re.fullmatch(r"[0-9a-fA-F]+", val))
        if weak:
            why.append("password debole o predefinita")
            remote = "host" in ctx and not LOCAL_HOST.match(ctx["host"])
            cfgname = re.search(r"(?i)(config|settings|credential|secret|deploy|sftp|ftp)[^/]*$", path) is not None
            if fc == "credenziali":
                s += 1   # debole ma reale in un file di credenziali: è un rischio, non un esempio
            elif fc == "esempio":
                s -= 2
            elif remote or config_like(path) or cfgname:
                s += 0   # debole in una configurazione reale o verso un host remoto: da guardare
            elif kind == "stringa di connessione con password" or path.lower().endswith(CODE_EXT):
                s -= 2
            else:
                s -= 1
        elif n >= 16 and ent >= (3.0 if hexv else 3.5):   # l'esadecimale ha al massimo 4 bit per carattere
            s += 2; why.append("alta entropia"); strong = True
            if SECRET_NAME.search(ctx.get("nome", "")):
                s += 1; why.append(f"nome da segreto ({ctx['nome'][:40]})")
        elif n >= 8 and ent >= 2.8:
            s += 1; why.append("valore non banale")
        else:
            s -= 1; why.append("valore corto o a bassa entropia")
        if kind == "JWT":
            s += 1; why.append("token JWT completo")
        if kind == "token Bearer" and strong:
            s += 1; why.append("token Bearer letterale in un'intestazione")
    if fc == "credenziali":
        s += 2; why.append("file di credenziali o configurazione reale")
    elif fc == "esempio":
        if strong and SECRET_NAME.search(ctx.get("nome", "")):
            s -= 1; why.append("file di documentazione/esempio, ma valore casuale con nome da segreto")
        else:
            s -= 2; why.append("file di documentazione, esempio, test o seed")
    if "host" in ctx:
        if LOCAL_HOST.match(ctx["host"]):
            s -= 1; why.append("host locale")
            if ctx.get("user", "").lower() == low:
                s -= 1; why.append("utente uguale alla password")
        else:
            s += 1; why.append("host remoto")
    if nfiles >= 3 and strong:
        s += 1; why.append(f"stesso valore casuale in {nfiles} file (probabile segreto reale copiato)")
    elif nfiles >= 3 and not ctx.get("provider") and not ctx.get("hash") and fc != "credenziali":
        s -= 2; why.append(f"stesso valore debole in {nfiles} file (valore di sviluppo)")
    return s, why


def scan_history(repo):
    """Scorre le righe aggiunte di tutta la storia. Restituisce (voci, stato)."""
    p = subprocess.run(["git", "-C", str(repo), "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff", "--format=@@COMMIT %h"],
                       capture_output=True, text=True, errors="replace")
    if p.returncode != 0:
        return None, (p.stderr.strip() or "git log fallito")[:200]
    occ = defaultdict(lambda: {"commits": set(), "kinds": set(), "ctx": {}})   # (path, fp) -> dati
    vals = {}                                                                  # fp -> valore (solo in memoria)
    files_of = defaultdict(set)                                                # fp -> file
    cur, path = "?", "?"
    seen_paths, vendored = set(), set()
    for line in p.stdout.splitlines():
        if line.startswith("@@COMMIT "):
            cur = line[9:]; continue
        if line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else "?"; continue
        if not line.startswith("+") or line.startswith("+++") or len(line) > 3000:
            continue
        if VENDOR.search(path):
            vendored.add(path); continue
        if path not in seen_paths:
            seen_paths.add(path)
        for kind, val, ctx in extract(line[1:], path):
            h = fp(val)
            vals[h] = val
            files_of[h].add(path)
            o = occ[(path, h)]
            o["commits"].add(cur); o["kinds"].add(kind); o["ctx"].update(ctx)
    # file di credenziali noti senza un valore riconosciuto: la presenza stessa nel repository è da verificare
    with_value = {pth for (pth, _h) in occ}
    for pth in sorted(seen_paths - with_value):
        if file_class(pth) == "credenziali" and not re.search(r"(?i)\.env$", pth):
            h = fp("file:" + pth)
            vals[h] = ""
            occ[(pth, h)] = {"commits": {"?"}, "kinds": {"file di credenziali"}, "ctx": {"filefound": True}}
    head = set(subprocess.run(["git", "-C", str(repo), "ls-files"], capture_output=True, text=True).stdout.splitlines())
    voci = []
    head_cache = {}
    for (path, h), o in occ.items():
        kind = sorted(o["kinds"], key=lambda k: (k == "password o segreto in chiaro", k))[0]
        if o["ctx"].get("filefound"):
            s, why = 3, ["file di credenziali noto presente nella storia (contenuto non riconosciuto dai pattern)"]
        else:
            s, why = score(kind, vals[h], o["ctx"], path, len(files_of[h]))
        if path not in head_cache:
            head_cache[path] = subprocess.run(["git", "-C", str(repo), "show", f"HEAD:{path}"], capture_output=True, text=True, errors="replace").stdout if path in head else ""
        in_head = (path in head) if o["ctx"].get("filefound") else (vals[h] in head_cache[path])
        why.append("presente nel codice attuale" if in_head else "rimosso dal codice ma presente nella storia")
        voci.append({"file": path, "tipo": kind, "impronta": h, "commit": sorted(o["commits"])[:5], "n_commit": len(o["commits"]),
                     "punteggio": s, "motivi": why, "in_head": in_head})
    if vendored:
        voci.append({"file": "(dipendenze vendorizzate)", "tipo": "nota", "impronta": "", "commit": [], "n_commit": 0, "punteggio": -99,
                     "motivi": [f"{len(vendored)} file in cartelle di dipendenze (node_modules, vendor…) presenti nella storia ed esclusi dall'analisi"],
                     "in_head": None, "escluso": True})
    return voci, None


def triage_gitleaks(report):
    """Stessa classificazione sui risultati di gitleaks (valore già redatto: si usano entropia e regola del report)."""
    voci = []
    for r in report or []:
        path = r.get("File", "?")
        ent = float(r.get("Entropy") or 0)
        s, why = 0, []
        rule = r.get("RuleID", "regola")
        if rule not in ("generic-api-key",):
            s += 3; why.append(f"regola specifica ({rule})")
        if ent >= 3.5:
            s += 2; why.append("alta entropia")
        elif ent and ent < 3.0:
            s -= 2; why.append("bassa entropia")
        if EXAMPLE_PATH.search(path):
            s -= 2; why.append("file di documentazione, esempio, test o seed")
        voci.append({"file": path, "tipo": rule, "impronta": (r.get("Fingerprint") or "")[-8:], "commit": [str(r.get("Commit", ""))[:7]],
                     "n_commit": 1, "punteggio": s, "motivi": why, "in_head": None})
    return voci


def bucket(s):
    return "in cima" if s >= 3 else ("da guardare" if s >= 0 else "probabile esempio")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", type=Path)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    voci, err = scan_history(a.repo)
    if err:
        sys.exit(err)
    if a.json:
        print(json.dumps(voci, ensure_ascii=False, indent=1)); return
    c = Counter(bucket(v["punteggio"]) for v in voci)
    print(f"occorrenze: {len(voci)} · in cima: {c['in cima']} · da guardare: {c['da guardare']} · probabile esempio: {c['probabile esempio']}")
    for v in sorted(voci, key=lambda v: -v["punteggio"])[:30]:
        print(f"  {v['punteggio']:+d} {bucket(v['punteggio']):17} {v['file']}  [{v['tipo']}] {'; '.join(v['motivi'])}")


if __name__ == "__main__":
    main()
