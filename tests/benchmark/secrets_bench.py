#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Banco di prova per la ricerca di segreti nella storia Git (run_scanners.py history), con verità nota.

Uso:
    python3 tests/benchmark/secrets_bench.py [--keep DIR] [--json]

Crea un repository Git sintetico con segreti «veri» (generati a caso a ogni esecuzione, mai salvati nel repo
della skill) ed esche tipiche dei progetti reali: segnaposto, file .example, documentazione, variabili d'ambiente,
seed con password di prova, test, lo stesso valore copiato in molti file. Poi misura:
- richiamo: segreti veri segnalati con severità «media» (cioè in cima, da guardare);
- falsi allarmi: esche segnalate «media»;
- copertura: segreti veri segnalati a qualunque severità.
I valori non vengono mai stampati.
"""
import argparse
import json
import secrets
import string
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RS = ROOT / "scripts" / "run_scanners.py"


GENERATED = []


def rnd(n, alphabet=string.ascii_letters + string.digits):
    v = "".join(secrets.choice(alphabet) for _ in range(n))
    GENERATED.append(v)
    return v


SNIP = r"""CRON_SECRET=$(grep "^CRON_SECRET=" .env | cut -d'=' -f2- | tr -d '"')
echo "CRON_SECRET: ${CRON_SECRET:0:20}...${CRON_SECRET: -4}"
curl -H "Authorization: Bearer $CRON_SECRET" http://localhost:3000/api/cron
"""


def build(repo: Path):
    """Restituisce {file: classe attesa}: «vero» (deve stare in cima) o «esca» (non deve stare in cima)."""
    g = lambda *a: subprocess.run(["git", "-C", str(repo), "-c", "user.email=b@example.test", "-c", "user.name=b", *a],
                                  capture_output=True, text=True, check=True)
    g("init", "-q")
    shared = "lab-" + "test-only-pass"   # stesso valore debole in molti file
    files = {
        # --- segreti veri (casuali, alta entropia) ---
        "src/config.ts": ("vero", f'export const GH = "ghp_{rnd(36)}"\n', "rimosso"),
        "deploy/aws.sh": ("vero", f"export AWS_ACCESS_KEY_ID=AKIA{rnd(16, string.ascii_uppercase + string.digits)}\nexport AWS_SECRET_ACCESS_KEY={rnd(40)}\n", "presente"),
        ".env": ("vero", f"DATABASE_URL=postgresql://app:{rnd(24)}@db.internal:5432/prod\n", "rimosso"),
        "keys/server.pem": ("vero", "-----BEGIN RSA PRIVATE KEY-----\n" + rnd(64) + "\n-----END RSA PRIVATE KEY-----\n", "rimosso"),
        "src/lib/auth.ts": ("vero", f'const JWT_SECRET = "{rnd(40)}"\n', "presente"),
        "billing/stripe.js": ("vero", f'const key = "sk_live_{rnd(24)}"\n', "presente"),
        "ops/backup.py": ("vero", f'API_KEY = "{rnd(32, string.hexdigits.lower())}"\n', "rimosso"),
        "docs/deploy.md": ("vero", "Impostare sul server:\n    CRON_SECRET=" + (cron := rnd(40)) + "\n", "presente"),
        "scripts/fix-cron.sh": ("vero", f"CORRECT_SECRET={cron}\n", "presente"),
        ".env.production": ("vero", f"CRON_SECRET={cron}\n", "rimosso"),
        "ops/call-cron.sh": ("vero", f'curl -H "Authorization: Bearer {rnd(43)}" https://app.example.test/api/cron\n', "rimosso"),
        # --- esche ---
        ".env.example": ("esca", "DATABASE_URL=postgresql://user:password@localhost:5432/db\nNEXTAUTH_SECRET=your-nextauth-secret-here-CHANGE-THIS\n", "presente"),
        "README.md": ("esca", "Accedi con utente admin e password: changeme123\n", "presente"),
        "docker-compose.yml": ("esca", "    environment:\n      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}\n      - DATABASE_URL=postgresql://postgres:postgres@db:5432/app\n", "presente"),
        "prisma/seed.ts": ("esca", 'const password = await hash("DemoPass123!")\n', "presente"),
        "docs/setup.md": ("esca", 'NEXTAUTH_SECRET="your-nextauth-secret-here-CHANGE-THIS"\n', "presente"),
        "tests/auth.test.ts": ("esca", 'const token = "test-token-1234567890"\n', "presente"),
        "CLAUDE.md": ("esca", "psql postgres://postgres:postgres@localhost:5432/dev\n", "presente"),
        "src/db.ts": ("esca", "const password = process.env.DB_PASSWORD\nconst secret = config.get('jwtSecret')\n", "presente"),
        "src/settings.py": ("esca", 'PASSWORD = "password"\nSECRET_KEY = "dev-secret-key"\n', "presente"),
        "src/app/page.tsx": ("esca", 'const tokenParam = searchParams.get("token")\nconst id = Buffer.from(credentialID, "base64url")\n', "presente"),
        "deploy/sudoers.sh": ("esca", "echo \"app ALL=(ALL) NOPASSWD: /usr/bin/systemctl status\" > /etc/sudoers.d/app\n", "presente"),
        "scripts/test-cron-1.sh": ("esca", SNIP, "presente"),
        "scripts/test-cron-2.sh": ("esca", SNIP, "presente"),
        "scripts/test-cron-3.sh": ("esca", SNIP, "presente"),
        "scripts/test-cron-4.sh": ("esca", SNIP, "presente"),
        ".env.docker": ("esca", "NEXTAUTH_SECRET=GENERA_CON_openssl_rand_base64_32\n", "presente"),
        ".env.test": ("esca", f"DB_PASSWORD={shared}\n", "presente"),
        ".github/workflows/ci.yml": ("esca", f"        env:\n          DB_PASSWORD: {shared}\n", "presente"),
        "scripts/dev.sh": ("esca", f"export DB_PASSWORD={shared}\n", "presente"),
        "e2e/helpers.ts": ("esca", f'const password = "{shared}"\n', "presente"),
        ".env.staging.local.example": ("esca", "SMTP_PASSWORD=your-smtp-password-or-app-password\n", "presente"),
    }
    for f, (_, content, _) in files.items():
        p = repo / f
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    g("add", "-A"); g("commit", "-qm", "primo")
    for f, (_, _, state) in files.items():
        if state == "rimosso":
            (repo / f).unlink()
    (repo / "src/later.ts").write_text("// nessun segreto\n", encoding="utf-8")
    g("add", "-A"); g("commit", "-qm", "rimuove i segreti dal codice")
    return {f: c for f, (c, _, _) in files.items()}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", type=Path)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    base = a.keep or Path(tempfile.mkdtemp(prefix="secbench-"))
    repo, out = base / "repo", base / "out"
    repo.mkdir(parents=True, exist_ok=True)
    truth = build(repo)
    r = subprocess.run([sys.executable, str(RS), "history", str(repo), "--out", str(out)], capture_output=True, text=True)
    cands = json.loads((out / "candidati-history.json").read_text(encoding="utf-8"))
    top = {c["asset"] for c in cands if c["severita"] in ("media", "alta", "critica")}
    anyf = {c["asset"] for c in cands}
    veri = [f for f, c in truth.items() if c == "vero"]
    esche = [f for f, c in truth.items() if c == "esca"]
    res = {
        "candidati": len(cands), "candidati_in_cima": sum(c["severita"] in ("media", "alta", "critica") for c in cands),
        "veri_in_cima": sum(f in top for f in veri), "veri_totali": len(veri),
        "veri_trovati_a_qualunque_severita": sum(f in anyf for f in veri),
        "esche_in_cima": sum(f in top for f in esche), "esche_totali": len(esche),
        "veri_mancati": [f for f in veri if f not in top], "esche_in_cima_elenco": [f for f in esche if f in top],
    }
    blob = r.stdout + r.stderr + "".join(p.read_text(encoding="utf-8", errors="replace") for p in out.glob("*.json"))
    leaked = any(v[:12] in blob for v in GENERATED)
    res["valori_trapelati"] = leaked
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        print(f"segreti veri in cima: {res['veri_in_cima']}/{res['veri_totali']} · trovati a qualunque severità: {res['veri_trovati_a_qualunque_severita']}/{res['veri_totali']}")
        print(f"esche in cima (falsi allarmi): {res['esche_in_cima']}/{res['esche_totali']} · candidati totali: {res['candidati']} (in cima: {res['candidati_in_cima']})")
        if res["veri_mancati"]:
            print("  veri non in cima:", ", ".join(res["veri_mancati"]))
        if res["esche_in_cima_elenco"]:
            print("  esche in cima:", ", ".join(res["esche_in_cima_elenco"]))
        print("valori trapelati nell'output:", "SÌ" if leaked else "no")
    return 0


if __name__ == "__main__":
    sys.exit(main())
