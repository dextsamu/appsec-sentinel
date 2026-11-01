#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Controllo di redazione: cerca segreti e dati personali in report e file di audit PRIMA della consegna.

Uso:
    python3 redact_check.py <cartella-o-file> [--strict]

Legge testo, CSV, JSON, Markdown e PDF (con pdftotext o pypdf se disponibili). Non stampa MAI il valore
trovato: solo file, riga e tipo. Esce con 1 se trova segreti (livello alto); i dati personali possibili
(email, codice fiscale, IBAN, telefono) sono segnalati come «da controllare» ed escono con 1 solo con --strict.
Un esito pulito non garantisce l'assenza di dati sensibili: rileggi sempre il documento.
"""
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

HIGH = {
    "chiave privata": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY"),
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "token GitHub": re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{20,}"),
    "token Slack": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "chiave Stripe live": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "stringa di connessione con password": re.compile(r"\b[a-z][a-z0-9+]+://[^/\s:@]+:[^/\s@]{4,}@[^/\s]+"),
    "password o segreto in chiaro": re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"]?([^\s'\"<>*]{8,})"),
}
PII = {
    "email": re.compile(r"\b[\w.+-]+@(?!(?:[\w-]+\.)*example\.|.*\.test\b|.*\.invalid\b)[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b"),   # il dominio finisce con lettere: «pacchetto@7.10.1» non è un'email
    "codice fiscale": re.compile(r"\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b"),
    "IBAN": re.compile(r"\bIT\d{2}[A-Z]\d{10}[0-9A-Z]{12}\b"),
    "telefono": re.compile(r"(?<!\d)(?:\+39|0039)?[ .]?3\d{2}[ .]?\d{6,7}(?!\d)"),
}
PLACEHOLDER = re.compile(r"(?i)^(?:x{3,}|\*+|redatto|redacted|changeme|example|esempio|tuo|your|<.*>|\$\{.*\}|process\.env|null|none|true|false|env:)")
TEXT_EXT = {".txt", ".md", ".csv", ".json", ".yml", ".yaml", ".env", ".html", ".sh", ".py", ".ts", ".js", ".sql", ".log"}
SKIP_DIRS = {".git", "node_modules", "__pycache__"}


def text_of(p: Path):
    if p.suffix.lower() == ".pdf":
        if shutil.which("pdftotext"):
            return subprocess.run(["pdftotext", "-layout", str(p), "-"], capture_output=True, text=True).stdout
        try:
            from pypdf import PdfReader
            return "\n".join(pg.extract_text() or "" for pg in PdfReader(str(p)).pages)
        except Exception:
            return None
    if p.suffix.lower() in TEXT_EXT or p.suffix == "":
        try:
            return p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    return None


def main():
    import i18n
    i18n.install()  # --lang en per i messaggi in inglese
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", type=Path)
    ap.add_argument("--strict", action="store_true")
    a = ap.parse_args()
    items = [a.path] if a.path.is_file() else [p for p in sorted(a.path.rglob("*")) if p.is_file() and not (set(p.parts) & SKIP_DIRS)]
    high, pii, skipped = [], [], []
    for p in items:
        t = text_of(p)
        if t is None:
            if p.suffix.lower() == ".pdf":
                skipped.append(str(p))
            continue
        for n, line in enumerate(t.splitlines(), 1):
            for name, rx in HIGH.items():
                for m in rx.finditer(line):
                    val = m.group(1) if m.groups() else m.group(0)
                    if PLACEHOLDER.match(val):
                        continue
                    high.append((p, n, name))
            for name, rx in PII.items():
                if rx.search(line):
                    pii.append((p, n, name))
    for p, n, k in high:
        print(f"ALTO   {p}:{n}  {k}  (valore non mostrato)")
    for p, n, k in pii[:200]:
        print(f"CONTROLLARE {p}:{n}  possibile {k}")
    for s in skipped:
        print(f"NON LETTO  {s}  (serve pdftotext o pypdf)")
    print(f"\nfile controllati: {len(items)}  segreti: {len(high)}  possibili dati personali: {len(pii)}")
    sys.exit(1 if high or (a.strict and pii) else 0)


if __name__ == "__main__":
    main()
