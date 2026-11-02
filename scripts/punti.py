# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""punti-pericolosi.csv: una riga per ogni categoria di punti pericolosi trovata dal pre-passaggio.

Ogni riga chiude con uno di questi esiti:
  finding        → id dei finding (anche «ipotesi da validare») in `finding`; almeno uno deve citare un file della categoria
  non difetto    → `motivo` con almeno un file:riga della categoria letto, e perché non è un difetto
  non esaminato  → `motivo`; accettato nel `rapido`, non nello `standard` e nel `completo`

Perché: su Juice Shop due giri `standard` avevano visto XSS nel client, SSRF, chatbot e recupero password e li avevano
lasciati nel motivo della checklist («annotato», «non promosso», «superficie nota»): 7–8 vulnerabilità su 32. Un
controllo sulle parole del motivo si aggira con un sinonimo; una riga per categoria con un esito chiuso no.
"""
import csv
import json
import re
from pathlib import Path

CAMPI = ["categoria", "punti", "esito", "finding", "motivo"]
ESITI = ("finding", "gap", "non difetto", "non esaminato")   # «gap» per le cartelle di gdpr-sentinel


def write(audit, cats):
    p = Path(audit) / "punti-pericolosi.csv"
    with p.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CAMPI)
        w.writeheader()
        for c, n in cats:
            w.writerow({"categoria": c, "punti": n, "esito": "", "finding": "", "motivo": ""})


def _files_by_cat(audit):
    t = Path(audit) / "registro-tool" / "punti-pericolosi.txt"
    out, cur = {}, None
    if not t.exists():
        return out
    for line in t.read_text(encoding="utf-8").splitlines():
        m = re.match(r"## (.+?): \d+", line)
        if m:
            cur = m.group(1)
            out[cur] = []
        elif cur and line.strip():
            out[cur].append(line.strip())
    return out


def problems(audit, strict):
    """Restituisce (stato, dettaglio) oppure None se il file non c'è. strict = standard/completo."""
    p = Path(audit) / "punti-pericolosi.csv"
    if not p.exists():
        return None
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    if not rows:
        return ("OK", "nessuna categoria trovata dal pre-passaggio")
    try:
        fl = json.loads((Path(audit) / "findings" / "findings.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        fl = []
    refs = {f.get("id"): " ".join(map(str, (f.get("prova") or {}).get("riferimenti_file") or [])) + " " + json.dumps(f, ensure_ascii=False)
            for f in fl if isinstance(f, dict)}
    gp = Path(audit) / "gaps.csv"
    if not fl and gp.exists():   # gdpr-sentinel: i gap al posto dei finding
        refs = {r.get("id"): f"{r.get('riferimenti', '')} {r.get('titolo', '')}" for r in csv.DictReader(gp.open(encoding="utf-8"))}
    files = _files_by_cat(audit)
    bad, aperti = [], []
    for r in rows:
        c, e = r.get("categoria", "").strip(), (r.get("esito") or "").strip().lower()
        mot, ids = (r.get("motivo") or "").strip(), [x for x in re.split(r"[\s,;]+", r.get("finding") or "") if x]
        nomi = {x.split(":")[0] for x in files.get(c, [])}
        if e not in ESITI:
            bad.append(f"{c} (esito mancante: finding o gap, non difetto, non esaminato)")
        elif e in ("finding", "gap"):
            miss = [i for i in ids if i not in refs]
            if not ids or miss:
                bad.append(f"{c} (finding {'assenti' if not ids else 'inesistenti: ' + ', '.join(miss)})")
            elif nomi and not any(any(n in refs[i] for n in nomi) for i in ids):
                bad.append(f"{c} (nessuno dei finding cita un file della categoria)")
        elif e == "non difetto":
            if not mot or (nomi and not any(n in mot for n in nomi)):
                bad.append(f"{c} (non difetto: il motivo deve citare almeno un file:riga letto della categoria)")
        elif e == "non esaminato":
            if not mot:
                bad.append(f"{c} (non esaminato senza motivo)")
            else:
                aperti.append(c)
    if bad:
        return ("FALLITO" if strict else "DA VERIFICARE", "; ".join(bad))
    if aperti:
        return ("FALLITO" if strict else "DA VERIFICARE", "non esaminate: " + ", ".join(aperti)
                + (" (nello standard e nel completo ogni categoria chiude con un finding o con «non difetto»)" if strict else ""))
    return ("OK", f"{len(rows)} categorie chiuse")


def letture_problems(audit, strict):
    """letture.csv (gdpr-sentinel): ogni file dell'elenco fisso va letto («si») o escluso («no» con il motivo in note)."""
    p = Path(audit) / "letture.csv"
    if not p.exists():
        return None
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    aperti = [r["file"] for r in rows if (r.get("letto") or "").strip().lower().replace("sì", "si") not in ("si", "no")
              or ((r.get("letto") or "").strip().lower() == "no" and not (r.get("note") or "").strip())]
    if aperti:
        return ("FALLITO" if strict else "DA VERIFICARE",
                f"{len(aperti)} su {len(rows)} senza «si» o «no» con motivo: {', '.join(aperti[:5])}{'…' if len(aperti) > 5 else ''}")
    n = sum(1 for r in rows if (r.get("letto") or "").strip().lower() in ("si", "sì"))
    return ("OK", f"{n} letti su {len(rows)}")


def entita_problems(audit, strict):
    """entita.csv (gdpr-sentinel): ogni riga con prepass «non trovato» va chiusa con un esito; «gap» richiede un gap_id
    presente in gaps.csv, «non verificabile» il motivo in note."""
    p = Path(audit) / "entita.csv"
    if not p.exists():
        return None
    rows = list(csv.DictReader(p.open(encoding="utf-8")))
    gp = Path(audit) / "gaps.csv"
    ids = {r.get("id") for r in csv.DictReader(gp.open(encoding="utf-8"))} if gp.exists() else set()
    aperte, bad = [], []
    for r in rows:
        pre = (r.get("prepass") or "").strip().lower()
        e = (r.get("esito") or "").strip().lower()
        k = f"{r.get('entita')}/{r.get('domanda')}"
        if pre.startswith(("si", "n/a")) and not e:
            continue
        if e not in ("ok", "gap", "non applicabile", "non verificabile"):
            aperte.append(k)
        elif e == "gap" and not any(x in ids for x in re.split(r"[\s,;]+", r.get("gap_id") or "") if x):
            bad.append(f"{k} (gap senza gap_id esistente)")
        elif e == "non verificabile" and not (r.get("note") or "").strip():
            bad.append(f"{k} (non verificabile senza motivo)")
    if aperte or bad:
        det = (f"{len(aperte)} righe «non trovato» senza esito: {', '.join(aperte[:5])}{'…' if len(aperte) > 5 else ''}" if aperte else "")
        det += ("; " if aperte and bad else "") + "; ".join(bad[:5])
        return ("FALLITO" if strict else "DA VERIFICARE", det)
    g = sum(1 for r in rows if (r.get("esito") or "").strip().lower() == "gap")
    return ("OK", f"{len(rows)} righe, {g} con gap")
