#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Inventario automatico delle route di una web app, come punto di partenza per endpoint-matrix.csv.

Uso:
    python3 inventory_routes.py <repo> [--out endpoint-matrix.csv] [--summary]

Per Express/Fastify l'auth è cercata sulla riga della singola route (middleware inline); se la applichi con app.use() o app.METHOD(percorso, auth) a monte, la route coperta da un prefisso con auth è segnalata «autenticato a monte»; gli altri middleware globali e i router montati altrove restano da verificare a mano.
Riconosce: Next.js (app router: route.ts/js; pages/api), Express/Koa/Fastify (app.get, router.post...),
Flask e FastAPI (decorator), Django (path/re_path), Laravel (Route::get...), Spring (@GetMapping...),
ASP.NET (attributi [HttpGet]), Rails (config/routes.rb), Go (net/http, gin, echo, chi). Per questi ultimi l'auth è cercata
vicino alla singola route (attributi, annotazioni, middleware sulla riga): i gruppi di route e i filtri globali non sono visibili. È euristico: segnala solo se nel file compare una
chiamata di autenticazione o di autorizzazione dal nome comune. Non prova che il controllo sia corretto
né che manchi: ogni riga resta da verificare. Le righe senza auth evidente vanno lette per prime.
Sola lettura: non esegue il codice del repository.
"""
import argparse
import csv
import re
import sys
from pathlib import Path

SKIP = {"node_modules", ".git", ".next", "dist", "build", "vendor", "__pycache__", ".venv", "venv", "coverage",
        "test", "tests", "spec", "__tests__", "e2e", "cypress", "codefixes"}  # codice di test e snippet didattici non sono superficie dell'app
METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
AUTH = re.compile(r"(requireAuth|getServerSession|getSession|auth\(\)|currentUser|getCurrentUser|withAuth|isAuthenticated|"
                  r"ensureAuth|authenticate|verifyToken|jwt\.verify|login_required|permission_classes|Depends\(\s*\w*(user|auth)|"
                  r"@jwt_required|@requires_auth|authorize\(|checkPermission|hasPermission|requireRole|can\(|"
                  r"isAuthorized|isAuthenticated|ensureAuth\w*|ensureLoggedIn|passport\.authenticate|verifyToken|checkJwt|authMiddleware|requireLogin|denyAll|"
                  r"\bis(?:Logged\w*|Auth\w*|Admin)\b|\brequire(?:Auth\w*|User|Admin|Role\w*|Session)\b|\bcheck(?:Auth\w*|Login|Session)\b|"
                  r"\bwithAuth\b|\bauthGuard\b|\bprotect(?:ed)?\b|login_required|"
                  r"@PreAuthorize|@Secured|@RolesAllowed|\[Authorize|authenticate_user!|before_action\s+:authenticate|"
                  r"middleware\(\s*\[?\s*['\"](?:auth|can:|verified)|auth:sanctum|->middleware\(\s*\[?['\"]auth|AuthMiddleware|RequireAuth|authRequired|JWTMiddleware)", re.I)
ROLE = re.compile(r"(role|ruolo|isAdmin|requireRole|hasPermission|checkPermission|permission|ADMIN)", re.I)
CRON = re.compile(r"(CRON_SECRET|Bearer|x-cron|INTERNAL_TOKEN|x-api-key|signature|webhook)", re.I)
FIELDS = ["endpoint", "metodo", "fonte_scoperta", "identita", "ruolo", "tenant", "oggetto", "azione", "controllo_atteso", "test_eseguito", "esito", "finding_id"]


def files(root: Path):
    for p in root.rglob("*"):
        if p.is_file() and not (set(p.relative_to(root).parts) & SKIP):
            yield p


def read(p: Path):
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def next_path(rel: Path):
    parts = list(rel.parts)
    if "api" in parts and parts[-1].startswith("route."):
        i = len(parts) - 1 - parts[::-1].index("api")
        segs = parts[i:-1]
    elif "pages" in parts and "api" in parts:
        i = parts.index("api")
        segs = parts[i:]
        segs[-1] = re.sub(r"\.(t|j)sx?$", "", segs[-1])
        if segs[-1] == "index":
            segs = segs[:-1]
    else:
        return None
    segs = [s for s in segs if not (s.startswith("(") and s.endswith(")"))]
    return "/" + "/".join(re.sub(r"^\[\.\.\.(\w+)\]$", r"{\1*}", re.sub(r"^\[(\w+)\]$", r"{\1}", s)) for s in segs)


def line_of(txt, pos):
    ls = txt.rfind("\n", 0, pos) + 1
    le = txt.find("\n", pos)
    return txt[ls: le if le != -1 else len(txt)]


def window(txt, pos, before=3, after=1):
    """Testo delle righe vicine alla posizione: serve a cercare attributi/annotazioni di auth della singola route."""
    lines = txt.splitlines(True)
    n = txt.count("\n", 0, pos)
    return "".join(lines[max(0, n - before): n + 1 + after])


def scan_other(p: Path, rel: Path, txt: str, rows: list):
    ext = p.suffix.lower()
    if ext == ".php" and ("routes" in rel.parts or p.name in ("web.php", "api.php")):
        # gruppi: Route::middleware('auth')->prefix('x')->group(function () { … }) — middleware e prefisso valgono per tutto il blocco
        groups = []
        for g in re.finditer(r"Route::((?:(?:middleware|prefix|name|controller|as|namespace)\([^)]*\)\s*->\s*)*(?:middleware|prefix|name|controller|as|namespace)\([^)]*\))\s*->\s*group\(\s*function\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?\{", txt):
            depth, i = 1, g.end()
            while i < len(txt) and depth:
                depth += {"{": 1, "}": -1}.get(txt[i], 0); i += 1
            mw = " ".join(re.findall(r"middleware\(([^)]*)\)", g.group(1)))
            px = "".join(x.strip("/") + "/" for x in re.findall(r"prefix\(\s*['\"]([^'\"]*)['\"]", g.group(1)))
            groups.append((g.end(), i, mw, px))
        for m in re.finditer(r"Route::(get|post|put|patch|delete|any|match)\(\s*(?:\[[^\]]*\]\s*,\s*)?['\"]([^'\"]*)['\"]", txt):
            line = line_of(txt, m.start())
            inside = [g for g in groups if g[0] <= m.start() < g[1]]
            ctx = " ".join(f"->middleware({g[2]})" for g in inside if g[2])
            pref = "".join(g[3] for g in inside)
            chain = txt[m.end():m.end() + 200].split(";")[0]
            rows.append(("/" + (pref + m.group(2).lstrip("/")).strip("/"), m.group(1).upper(), "codice: Laravel", str(rel),
                         line + (" " + chain if "->middleware" in chain else "") + (" " + ctx if ctx else "")))
        for m in re.finditer(r"Route::(?:api)?[Rr]esource\(\s*['\"]([^'\"]+)['\"]", txt):
            for meth in ("GET", "POST", "PUT", "DELETE"):
                rows.append(("/" + m.group(1), meth, "codice: Laravel (resource)", str(rel), line_of(txt, m.start())))
    elif ext == ".java" or ext == ".kt":
        pref = ""
        cm = re.search(r"@RequestMapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*\"([^\"]*)\"[^)]*\)\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public\s+)?(?:class|open class)", txt)
        if cm:
            pref = cm.group(1)
        class_auth = bool(re.search(r"(@PreAuthorize|@Secured|@RolesAllowed)[^\n]*\n(?:\s*@\w+[^\n]*\n)*\s*(?:public\s+)?(?:class|open class)", txt))
        for m in re.finditer(r"@(Get|Post|Put|Patch|Delete|Request)Mapping(?:\(\s*(?:(?:value|path)\s*=\s*)?\{?\s*(?:\"([^\"]*)\")?([^)]*)\))?", txt):
            if m.group(1) == "Request" and re.match(r"\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:public\s+)?(?:class|open class)", txt[m.end():m.end() + 200]):
                continue
            meth = m.group(1).upper() if m.group(1) != "Request" else ("/".join(re.findall(r"RequestMethod\.(\w+)", m.group(3) or "")) or "ANY")
            path = (pref.rstrip("/") + "/" + (m.group(2) or "").lstrip("/")).rstrip("/") or "/"
            rows.append((path if path.startswith("/") else "/" + path, meth, "codice: Spring", str(rel),
                         window(txt, m.start(), 3, 1) + (" @PreAuthorize" if class_auth else "")))
    elif ext == ".cs":
        croute = re.search(r"\[Route\(\"([^\"]+)\"\)\]", txt)
        cname = re.search(r"class\s+(\w+?)(?:Controller)?\b", txt)
        cls_auth = bool(re.search(r"\[Authorize[^\]]*\]\s*(?:\[[^\]]+\]\s*)*public\s+(?:class|sealed class)", txt))
        for m in re.finditer(r"\[Http(Get|Post|Put|Patch|Delete)(?:\(\"([^\"]*)\"\))?\]", txt):
            base = (croute.group(1) if croute else "").replace("[controller]", (cname.group(1) if cname else "").lower())
            path = "/" + (base.strip("/") + "/" + (m.group(2) or "").strip("/")).strip("/")
            w = window(txt, m.start(), 2, 2)
            if "[AllowAnonymous]" in w:
                w = w.replace("[Authorize", "[x")
            elif cls_auth:
                w += " [Authorize]"
            rows.append((path, m.group(1).upper(), "codice: ASP.NET", str(rel), w))
    elif ext == ".rb" and p.name == "routes.rb":
        rb_root = p.parent.parent
        for m in re.finditer(r"^\s*(get|post|put|patch|delete)\s+['\"]?([^'\"\s,]+)['\"]?(?:.*?(?:to:\s*|=>\s*)['\"](\w+)#\w+['\"])?", txt, re.M):
            ctrl = m.group(3) or ""
            rows.append(("/" + m.group(2).lstrip("/"), m.group(1).upper(), "codice: Rails", str(rel), rails_ctrl(rb_root, ctrl)))
        for m in re.finditer(r"^\s*resources?\s+:(\w+)", txt, re.M):
            for meth in ("GET", "POST", "PATCH", "DELETE"):
                rows.append(("/" + m.group(1), meth, "codice: Rails (resources)", str(rel), rails_ctrl(rb_root, m.group(1))))
    elif ext == ".go":
        for m in re.finditer(r"\b(?:\w+)\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\(\s*\"([^\"]+)\"([^\n]*)", txt):
            verb = m.group(1).upper()
            meth = "ANY" if verb.startswith("HANDLE") else verb
            path = m.group(2)
            mm = re.match(r"(GET|POST|PUT|PATCH|DELETE)\s+(/.*)", path)
            if mm:
                meth, path = mm.group(1), mm.group(2)
            if path.startswith("/"):
                rows.append((path, meth, "codice: Go", str(rel), line_of(txt, m.start())))


def rails_ctrl(app_root: Path, name: str) -> str:
    """Testo del controller Rails (per cercare before_action di auth); vuoto se non trovato."""
    if not name:
        return ""
    for cand in (app_root / "app" / "controllers" / f"{name}_controller.rb", app_root / "controllers" / f"{name}_controller.rb"):
        if cand.exists():
            return read(cand)
    return ""


def covers(prefix: str, ep: str) -> bool:
    """Il middleware dichiarato su `prefix` (app.use / app.METHOD) copre `ep`? I segmenti :param sono equivalenti."""
    norm = lambda s: [("*" if x.startswith(":") else x) for x in s.strip("/").split("/") if x]
    a, b = norm(prefix), norm(ep)
    return bool(a) and len(a) <= len(b) and all(x == y or "*" in (x, y) for x, y in zip(a, b))


DJ_AUTH = re.compile(r"(login_required|permission_required|user_passes_test|staff_member_required|superuser_required|"
                     r"LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin|IsAuthenticated\w*|IsAdminUser|"
                     r"request\.user\.is_authenticated|raise PermissionDenied)")


def scan_django(root: Path, urls: list, rows: list):
    """Django: route da path()/re_path(), prefissi da include(), autenticazione letta sulla view (decoratori, mixin,
    permission_classes, controlli nelle prime righe), non sul file urls.py. Un file urls senza include che lo raggiunge
    resta con il suo percorso relativo."""
    defs = {}   # nome -> [(file, testo della view: decoratori + firma/classe + prime righe)]
    for p in files(root):
        if p.suffix != ".py":
            continue
        lines = read(p).splitlines()
        for i, ln in enumerate(lines):
            m = re.match(r"(def|class)\s+(\w+)", ln)
            if not m:
                continue
            j = i
            while j > 0 and lines[j - 1].lstrip().startswith("@"):
                j -= 1
            k, body = i + 1, []
            while k < len(lines) and len(body) < 12 and (not lines[k].strip() or lines[k][:1] in " \t"):
                body.append(lines[k]); k += 1
            defs.setdefault(m.group(2), []).append((p, "\n".join(lines[j:i + 1] + body)))
    settings = "\n".join(read(p) for p in files(root) if p.name == "settings.py" or "settings" in p.parent.name)
    drf_default = bool(re.search(r"DEFAULT_PERMISSION_CLASSES[^\]]*IsAuthenticated", settings, re.S))
    mod_of = lambda p: ".".join(p.relative_to(root).with_suffix("").parts)
    prefix = {}  # file urls -> prefisso da include()
    for p, rel, txt in urls:
        for m in re.finditer(r"\b(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*include\(\s*['\"]([\w.]+)['\"]", txt):
            for q, _, _ in urls:
                if mod_of(q).endswith(m.group(2)):
                    prefix[q] = m.group(1).lstrip("^")
    for p, rel, txt in urls:
        pre = prefix.get(p, "")
        for m in re.finditer(r"\b(?:re_)?path\(\s*r?['\"]([^'\"]*)['\"]\s*,\s*([^,)]+(?:\([^)]*\))?)", txt):
            target = m.group(2).strip()
            if target.startswith("include("):
                continue
            ep = "/" + (pre + m.group(1).lstrip("^")).lstrip("/").rstrip("$")
            name = [w for w in re.findall(r"\w+", target.replace(".as_view", "")) if not DJ_AUTH.search(w) and w not in ("csrf_exempt", "never_cache", "cache_page")]
            cand = defs.get(name[-1], []) if name else []
            here = [c for c in cand if c[0].parent == p.parent] or cand   # stessa app prima
            view = here[0][1] if here else ""
            seen_txt = target + "\n" + view
            drf = bool(re.search(r"class\s+\w+\([^)]*(APIView|ViewSet|generics\.)", view))
            if DJ_AUTH.search(seen_txt):
                txt_auth = "login_required " + (view if ROLE.search(view) else "")
            elif drf and drf_default and "permission_classes" not in view:
                txt_auth = "login_required (DEFAULT_PERMISSION_CLASSES)"
            else:
                txt_auth = view if CRON.search(view) else ""
            src = "codice: Django" + ("" if here else " · view non risolta")
            rows.append((ep, "ANY", src, str(rel), txt_auth))


def scan(root: Path):
    rows = []
    prefixes = []
    django_urls = []
    for p in files(root):
        rel = p.relative_to(root)
        ext = p.suffix.lower()
        if ext in (".ts", ".tsx", ".js", ".mjs", ".cjs", ".jsx"):
            txt = read(p)
            np_ = next_path(rel)
            if np_ and (p.name.startswith("route.") or "pages" in rel.parts):
                if p.name.startswith("route."):
                    ms = set(re.findall(r"export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b", txt))
                    ms |= set(re.findall(r"export\s*\{[^}]*\b(GET|POST|PUT|PATCH|DELETE)\b", txt))
                else:
                    ms = set(re.findall(r"req\.method\s*===?\s*['\"](GET|POST|PUT|PATCH|DELETE)['\"]", txt)) or {"ANY"}
                for m in sorted(ms) or ["ANY"]:
                    rows.append((np_, m, "codice: Next.js", str(rel), txt))
            for m in re.finditer(r"\b(app|router|server|api|fastify)\.(get|post|put|patch|delete|all|use)\(\s*['\"`]([^'\"`]+)['\"`]", txt):
                ls = txt.rfind("\n", 0, m.start()) + 1
                le = txt.find("\n", m.end())
                line = txt[ls: le if le != -1 else len(txt)]
                obj, verb, path = m.group(1), m.group(2), m.group(3)
                if verb == "use" and not path.startswith("/"):
                    continue
                if verb in ("use", "get", "post", "put", "patch", "delete", "all") and AUTH.search(line) and line.rstrip().endswith((")", ");", ")  //")) and not re.search(r"(?:async|=>|function)", line):
                    prefixes.append(path)  # middleware di auth dichiarato a monte su questo percorso
                if verb == "use":
                    if AUTH.search(line):
                        continue  # solo dichiarazione di auth su un prefisso: non è una route
                    rows.append((path, "ANY", "codice: Express (montaggio app.use)", f"{rel}", line))
                    continue
                src = "codice: Express/Fastify" + (" · router: prefisso di montaggio non risolto" if obj == "router" else "")
                rows.append((path, verb.upper(), src, f"{rel}", line))  # auth cercata sulla riga della route
        elif ext in (".php", ".java", ".kt", ".cs", ".rb", ".go"):
            scan_other(p, rel, read(p), rows)
        elif ext == ".py":
            txt = read(p)
            for m in re.finditer(r"@(?:\w+)\.(get|post|put|patch|delete|route)\(\s*['\"]([^'\"]+)['\"]([^)]*)\)", txt):
                meth = m.group(1).upper()
                if meth == "ROUTE":
                    mm = re.search(r"methods\s*=\s*\[([^\]]+)\]", m.group(3))
                    meth = "/".join(re.findall(r"[A-Z]+", mm.group(1))) if mm else "GET"
                rows.append((m.group(2), meth, "codice: Flask/FastAPI", str(rel), txt))
            if "urls" in p.name:
                django_urls.append((p, rel, txt))
    if django_urls:
        scan_django(root, django_urls, rows)
    out, seen = [], set()
    for ep, meth, src, rel, txt in rows:
        key = (ep, meth, rel)
        if key in seen:
            continue
        seen.add(key)
        has_auth, has_role, has_tok = bool(AUTH.search(txt)), bool(ROLE.search(txt)), bool(CRON.search(txt))
        ident = "autenticato (da verificare)" if has_auth else ("token/segreto condiviso (da verificare)" if has_tok else "NESSUNA AUTH EVIDENTE")
        if ident == "NESSUNA AUTH EVIDENTE" and any(covers(px, ep) for px in prefixes):
            ident = "autenticato a monte: middleware sul prefisso (da verificare)"
        out.append({"endpoint": ep, "metodo": meth, "fonte_scoperta": f"{src} · {rel}", "identita": ident,
                    "ruolo": "controllo ruolo presente (da verificare)" if has_role else "nessun controllo ruolo evidente",
                    "tenant": "da verificare", "oggetto": "", "azione": "lettura" if meth in ("GET", "HEAD") else "modifica (da verificare)",
                    "controllo_atteso": "", "test_eseguito": "no", "esito": "", "finding_id": ""})
    out.sort(key=lambda r: (r["identita"] != "NESSUNA AUTH EVIDENTE", r["endpoint"], r["metodo"]))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()
    if not a.repo.is_dir():
        sys.exit(f"cartella non trovata: {a.repo}")
    rows = scan(a.repo)
    noauth = [r for r in rows if r["identita"] == "NESSUNA AUTH EVIDENTE"]
    methods = len({(r["endpoint"], r["metodo"]) for r in rows})
    print(f"route trovate: {len(rows)} ({methods} endpoint+metodo distinti); senza auth evidente: {len(noauth)}")
    if a.summary:
        for r in noauth[:40]:
            print(f"  - {r['metodo']:6} {r['endpoint']}   [{r['fonte_scoperta'].split(' · ')[-1]}]")
    if a.out:
        with a.out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader(); w.writerows(rows)
        print(f"scritto: {a.out}")


if __name__ == "__main__":
    main()
