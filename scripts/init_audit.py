#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Crea la cartella di audit con i template della skill.

Uso:
    python3 init_audit.py <cartella-audit> [--force]

La cartella di audit contiene evidenze, segreti redatti e finding non ancora
corretti: deve stare FUORI dal repository del progetto e da sync non autorizzati.
Lo script rifiuta di creare la cartella dentro un repository Git, salvo --force.
"""
import argparse
import json
import shutil
from datetime import datetime
import subprocess
import sys
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent / "assets"
COPIES = {
    "engagement-rules-template.md": "00-regole-di-ingaggio.md",
    "coverage-matrix.csv": "coverage-matrix.csv",
    "endpoint-matrix.csv": "endpoint-matrix.csv",
    "controls-matrix.csv": "controls-matrix.csv",
    "finding-template.md": "finding-template.md",
    "finding.schema.json": "finding.schema.json",
    "documentary-matrix.csv": "documentary-matrix.csv",
    "meta-template.json": "meta.json",
    "authz-config.example.json": "authz-config.example.json",
    "authz-tests.example.csv": "authz-tests.example.csv",
    "rapido-checklist.csv": "checklist-rapido.csv",
}
SUBDIRS = ["findings", "evidenze-redatte", "registro-tool", "report"]


def inside_git_repo(path: Path) -> bool:
    probe = path if path.exists() else path.parent
    try:
        out = subprocess.run(
            ["git", "-C", str(probe), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True, check=False,
        )
        return out.stdout.strip() == "true"
    except FileNotFoundError:
        return False


def main() -> int:
    import i18n
    i18n.install()  # --lang en per i messaggi in inglese
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dest", type=Path)
    ap.add_argument("--force", action="store_true", help="ignora il controllo sul repository Git")
    args = ap.parse_args()

    dest = args.dest.resolve()
    if inside_git_repo(dest) and not args.force:
        print(f"ERRORE: {dest} è dentro un repository Git. Le evidenze di audit non devono finire in Git.\n"
              "Scegli una cartella riservata esterna oppure usa --force sapendo cosa fai.", file=sys.stderr)
        return 2

    dest.mkdir(parents=True, exist_ok=True)
    for sub in SUBDIRS:
        (dest / sub).mkdir(exist_ok=True)
    for src_name, dst_name in COPIES.items():
        dst = dest / dst_name
        if dst.exists():
            print(f"  salto (esiste): {dst_name}")
            continue
        shutil.copy2(ASSETS / src_name, dst)
    (dest / "findings" / "findings.json").write_text("[]\n", encoding="utf-8") if not (dest / "findings" / "findings.json").exists() else None
    (dest / ".gitignore").write_text("*\n", encoding="utf-8") if not (dest / ".gitignore").exists() else None
    tj = dest / "registro-tool" / "tempi.json"   # inizio del lavoro: check_delivery ne ricava la durata
    if not tj.exists():
        tj.parent.mkdir(exist_ok=True)
        tj.write_text(json.dumps({"inizio": datetime.now().astimezone().isoformat(timespec="seconds")}), encoding="utf-8")
    print(f"Cartella di audit pronta: {dest}")
    print("Prossimo passo: compilare 00-regole-di-ingaggio.md e farla confermare dal proprietario.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
