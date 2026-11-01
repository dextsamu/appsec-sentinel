#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Importa un file OpenAPI/Swagger (2.0, 3.x; JSON o YAML) come endpoint-matrix.csv.

Uso:
    python3 import_openapi.py <openapi.json|yaml> [--out endpoint-matrix.csv] [--repo <cartella>] [--summary]

Con --repo confronta la specifica con l'inventario del codice (inventory_routes.py) e segnala:
  - «documentato ma non trovato nel codice»: può essere un limite dell'inventario euristico o un endpoint morto;
  - «nel codice ma non documentato»: superficie non dichiarata, da leggere per prima.
Il confronto normalizza i parametri di percorso ({id}, :id, <id>, [id]) e il prefisso `servers[].url`/`basePath`.
La specifica dichiara l'intento, non il comportamento: un endpoint con `security` non è per questo protetto davvero.
Sola lettura: non esegue il codice e non contatta alcun server.
"""
import argparse
import csv
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

METHODS = ("get", "post", "put", "patch", "delete", "head", "options")
FIELDS = ["endpoint", "metodo", "fonte_scoperta", "identita", "ruolo", "tenant", "oggetto", "azione",
          "controllo_atteso", "test_eseguito", "esito", "finding_id"]


def load(p):
    txt = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError:
            sys.exit("per i file YAML serve PyYAML (pip install pyyaml), oppure converti la specifica in JSON")
        return yaml.safe_load(txt)
    return json.loads(txt)


def norm(path):
    path = re.sub(r"\{[^}/]+\}|:[A-Za-z_]\w*|<[^>/]+>|\[[^\]/]+\]", "{}", path)
    return "/" + path.strip("/")


def base_prefix(spec):
    if spec.get("basePath"):
        return spec["basePath"]
    srv = spec.get("servers") or []
    if srv and isinstance(srv[0], dict) and srv[0].get("url"):
        return urlparse(srv[0]["url"]).path or ""
    return ""


def rows_from(spec, src):
    glob_sec = spec.get("security")
    pre = base_prefix(spec).rstrip("/")
    out = []
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for m in METHODS:
            op = item.get(m)
            if not isinstance(op, dict):
                continue
            sec = op["security"] if "security" in op else glob_sec
            if sec is None:
                ident = "NESSUNA SECURITY DICHIARATA"
            elif sec == [] or sec == [{}]:
                ident = "pubblico per dichiarazione (security: [])"
            else:
                names = sorted({k for s in sec if isinstance(s, dict) for k in s})
                ident = f"security dichiarata: {', '.join(names) or '?'} (da verificare)"
            ep = (pre + "/" + path.lstrip("/")) if pre else path
            out.append({"endpoint": ep, "metodo": m.upper(), "fonte_scoperta": f"openapi · {src}", "identita": ident,
                        "ruolo": "da verificare", "tenant": "da verificare",
                        "oggetto": (op.get("operationId") or op.get("summary") or "")[:60],
                        "azione": "lettura" if m in ("get", "head") else "modifica (da verificare)",
                        "controllo_atteso": "", "test_eseguito": "no", "esito": "", "finding_id": ""})
    out.sort(key=lambda r: (not r["identita"].startswith("NESSUNA"), r["endpoint"], r["metodo"]))
    return out


def compare(rows, repo):
    sys.path.insert(0, str(Path(__file__).parent))
    import inventory_routes
    code = inventory_routes.scan(repo)
    spec_k = {(norm(r["endpoint"]), r["metodo"]) for r in rows}
    code_k = {(norm(r["endpoint"]), r["metodo"]) for r in code if r["metodo"] in {x.upper() for x in METHODS}}
    code_paths = {k[0] for k in code_k} | {norm(r["endpoint"]) for r in code}
    only_spec = sorted(k for k in spec_k if k not in code_k and k[0] not in code_paths)
    only_code = sorted(k for k in code_k if k not in spec_k)
    return only_spec, only_code


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("spec", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--repo", type=Path)
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()
    if not a.spec.is_file():
        sys.exit(f"file non trovato: {a.spec}")
    spec = load(a.spec)
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")):
        sys.exit("non sembra una specifica OpenAPI/Swagger (manca la chiave openapi o swagger)")
    rows = rows_from(spec, a.spec.name)
    nosec = [r for r in rows if r["identita"].startswith("NESSUNA")]
    pub = [r for r in rows if r["identita"].startswith("pubblico")]
    print(f"operazioni nella specifica: {len(rows)}; senza security dichiarata: {len(nosec)}; pubbliche per dichiarazione: {len(pub)}")
    if a.summary:
        for r in nosec[:40] + pub[:20]:
            print(f"  - {r['metodo']:6} {r['endpoint']}   [{r['identita'].split(' (')[0]}]")
    if a.repo:
        if not a.repo.is_dir():
            sys.exit(f"cartella non trovata: {a.repo}")
        os_, oc = compare(rows, a.repo)
        print(f"documentato ma non trovato nel codice: {len(os_)} · nel codice ma non documentato: {len(oc)}")
        for p, m in os_[:30]:
            print(f"  - [spec soltanto] {m:6} {p}")
        for p, m in oc[:30]:
            print(f"  - [codice soltanto] {m:6} {p}")
        print("Nota: l'inventario del codice è euristico; una differenza è un indizio da verificare, non un finding.")
    if a.out:
        with a.out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=FIELDS)
            w.writeheader(); w.writerows(rows)
        print(f"scritto: {a.out}")


if __name__ == "__main__":
    main()
