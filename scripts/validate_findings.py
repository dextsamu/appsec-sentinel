#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Valida findings.json contro finding.schema.json e controlla la coerenza di onestà.

Uso:
    python3 validate_findings.py <findings.json> [--schema <schema.json>]

Controlli:
  1. conformità allo schema (se il modulo `jsonschema` è installato; altrimenti
     controllo minimo di campi obbligatori ed enum);
  2. coerenza: ID unici; nessuno stato "riprodotto dinamicamente" senza test eseguito;
     nessun CVSS senza versione; nessun segreto evidente nei testi (token, chiavi private,
     password in chiaro) che violerebbe la regola di redazione.
Esce con codice 1 se trova errori, 0 altrimenti (i warning non bloccano).
"""
import argparse
import json
import re
import sys
from pathlib import Path

DEFAULT_SCHEMA = Path(__file__).resolve().parent.parent / "assets" / "finding.schema.json"

SECRET_PATTERNS = {
    "chiave privata": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "token AWS": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "token GitHub": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "token Slack": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    "password in chiaro": re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key)\b\s*[:=]\s*['\"]?(?!\*|<|redatt|\[)(?![a-zà-ù]+\s+[a-zà-ù])[^\s'\"]{6,}"),   # parola minuscola seguita da altre parole («secret = chiave pubblica») è testo, non un valore
}


def walk_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from walk_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from walk_strings(v)


def schema_errors(findings, schema):
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return None
    validator = jsonschema.Draft202012Validator(schema)
    errs = []
    for i, f in enumerate(findings):
        fid = f.get("id", f"#{i}") if isinstance(f, dict) else f"#{i}"
        for e in sorted(validator.iter_errors(f), key=lambda x: list(x.path)):
            where = "/".join(str(p) for p in e.path) or "(radice)"
            errs.append(f"{fid}: {where}: {e.message}")
    return errs


def minimal_errors(findings, schema):
    errs = []
    req = schema.get("required", [])
    stati = schema["properties"]["stato"]["enum"]
    sev = schema["properties"]["severita"]["enum"]
    for i, f in enumerate(findings):
        fid = f.get("id", f"#{i}")
        for k in req:
            if k not in f:
                errs.append(f"{fid}: campo obbligatorio mancante: {k}")
        if f.get("stato") not in stati:
            errs.append(f"{fid}: stato non valido: {f.get('stato')!r}")
        if f.get("severita") not in sev:
            errs.append(f"{fid}: severita non valida: {f.get('severita')!r}")
        walk(f, schema, fid, "", errs)
    return errs


_TYPES = {"boolean": bool, "array": list, "string": str, "object": dict, "integer": int}


def walk(val, sch, fid, path, errs):
    """Controllo minimo di enum e tipi annidati, senza jsonschema (stesse regole dello schema)."""
    if not isinstance(sch, dict):
        return
    t = sch.get("type")
    if isinstance(t, str) and t in _TYPES and val is not None and not (isinstance(val, bool) and t == "integer") and not isinstance(val, _TYPES[t]):
        errs.append(f"{fid}: {path or '(radice)'}: tipo atteso {t}")
        return
    if "enum" in sch and val not in sch["enum"]:
        errs.append(f"{fid}: {path}: valore {val!r} non ammesso (ammessi: {', '.join(map(str, sch['enum']))})")
    if isinstance(val, dict):
        for k, sub in (sch.get("properties") or {}).items():
            if k in val:
                walk(val[k], sub, fid, f"{path}/{k}" if path else k, errs)


def honesty_errors(findings):
    errs, warns = [], []
    seen = set()
    for i, f in enumerate(findings):
        fid = f.get("id", f"#{i}")
        if fid in seen:
            errs.append(f"{fid}: ID duplicato")
        seen.add(fid)
        prova = f.get("prova", {}) or {}
        if f.get("stato") == "riprodotto dinamicamente" and not prova.get("test_eseguito"):
            errs.append(f"{fid}: stato 'riprodotto dinamicamente' ma prova.test_eseguito non è true")
        if f.get("stato") in ("ipotesi da validare", "non verificabile") and f.get("severita") in ("critica", "alta"):
            warns.append(f"{fid}: severità {f.get('severita')} su stato '{f.get('stato')}': motiva esplicitamente il livello")
        cvss = f.get("cvss")
        if cvss and not cvss.get("versione"):
            errs.append(f"{fid}: CVSS senza versione")
        if f.get("categoria", "").lower().startswith(("privacy", "gdpr")) and cvss:
            warns.append(f"{fid}: CVSS su finding privacy/compliance: non va attribuito alla mera assenza di un documento")
        for text in walk_strings(f):
            for label, pat in SECRET_PATTERNS.items():
                if pat.search(text):
                    errs.append(f"{fid}: possibile {label} non redatto nei testi del finding")
                    break
    return errs, warns


def main() -> int:
    import i18n
    i18n.install()  # --lang en per i messaggi in inglese
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", type=Path)
    ap.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    args = ap.parse_args()

    try:
        findings = json.loads(args.findings.read_text(encoding="utf-8"))
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"ERRORE di lettura: {exc}", file=sys.stderr)
        return 2
    if not isinstance(findings, list):
        print("ERRORE: findings.json deve contenere un array di finding", file=sys.stderr)
        return 2

    errs = schema_errors(findings, schema)
    if errs is None:
        print("nota: modulo jsonschema non installato, uso il controllo minimo (pip install jsonschema per quello completo)")
        errs = minimal_errors(findings, schema)
    h_errs, warns = honesty_errors(findings)
    errs += h_errs

    for w in warns:
        print(f"WARNING {w}")
    for e in errs:
        print(f"ERRORE  {e}")
    print(f"\n{len(findings)} finding · {len(errs)} errori · {len(warns)} warning")
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
