#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Calcola i denominatori reali di copertura dai CSV di audit.

Uso:
    python3 coverage_summary.py <cartella-audit>

Legge (se presenti) coverage-matrix.csv, endpoint-matrix.csv, controls-matrix.csv e stampa
un riepilogo in Markdown: quanti elementi inventariati/esaminati, endpoint censiti/testati,
controlli applicabili/verificati/non verificabili. Non produce percentuali "di sicurezza":
solo conteggi con il loro denominatore. Le righe d'esempio dei template iniziano con
'ESEMPIO' e vengono ignorate. Il campo `esaminato` ammette si / parziale / no.
Per le route (o altri insiemi grandi) dichiara nelle note quante ne hai lette davvero:
una ricerca euristica non è una lettura.
"""
import csv
import re
import sys
from collections import Counter
from pathlib import Path


def rows(path: Path):
    if not path.exists():
        return None
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def yes(v: str) -> bool:
    v = (v or "").strip().lower()
    return v in {"si", "sì", "yes", "true", "1"} or bool(re.match(r"(si|sì|yes)\b", v))   # anche «si (L3 valutato)»


def partial(v: str) -> bool:
    return (v or "").strip().lower() in {"parziale", "partial"}


def is_example(r: dict) -> bool:
    """Le righe dei template che iniziano con 'ESEMPIO' non contano come dati."""
    first = next(iter(r.values()), "") or ""
    return first.strip().upper().startswith("ESEMPIO")


def real(rs):
    """Toglie le righe di esempio; restituisce (righe reali, numero di esempi ignorati)."""
    keep = [r for r in rs if not is_example(r)]
    return keep, len(rs) - len(keep)


def main() -> int:
    import i18n
    i18n.install()  # --lang en per i messaggi in inglese
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    base = Path(sys.argv[1])
    out = ["# Riepilogo di copertura (conteggi con denominatore)\n"]

    cov = rows(base / "coverage-matrix.csv")
    if cov is None:
        out.append("## File/componenti\nnon disponibile: coverage-matrix.csv assente\n")
    else:
        cov, skipped = real(cov)
        if skipped:
            out.append(f"_Ignorate {skipped} righe d'esempio del template in coverage-matrix.csv._\n")
        by_mode = Counter(r.get("modalita_verifica", "").strip() or "non indicata" for r in cov)
        examined = sum(yes(r.get("esaminato", "")) for r in cov)
        part = sum(partial(r.get("esaminato", "")) for r in cov)
        out.append(f"## File/componenti\n- Voci inventariate: **{len(cov)}**\n- Esaminate per intero (si): **{examined}** su {len(cov)}\n- Esaminate in parte (parziale): **{part}** (indica nelle note cosa è stato letto e cosa no)\n- Non esaminate o escluse con motivo: **{len(cov) - examined - part}**")
        for mode, n in by_mode.most_common():
            out.append(f"  - {mode}: {n}")
        carried = sum((r.get("origine") or "").startswith("riportata") for r in cov)
        stale = sum((r.get("origine") or "").startswith("stantia") for r in cov)
        if carried or stale:
            out.append(f"- Da audit precedente: **{carried}** voci riportate (contenuto invariato), **{stale}** stantie da rifare")
        no_reason = [r["area_o_percorso"] for r in cov if not yes(r.get("esaminato", "")) and not (r.get("motivo_esclusione") or "").strip() and not partial(r.get("esaminato", ""))]
        if no_reason:
            out.append(f"- ATTENZIONE: {len(no_reason)} voci non esaminate senza motivo di esclusione: {', '.join(no_reason[:5])}{'…' if len(no_reason) > 5 else ''}")
        out.append("")

    ep = rows(base / "endpoint-matrix.csv")
    if ep is None:
        out.append("## Endpoint\nnon disponibile: endpoint-matrix.csv assente\n")
    else:
        ep, skipped_ep = real(ep)
        if skipped_ep:
            out.append(f"_Ignorate {skipped_ep} righe d'esempio del template in endpoint-matrix.csv._\n")
        endpoints = {(r.get("endpoint", ""), r.get("metodo", "")) for r in ep}
        tested = [r for r in ep if yes(r.get("test_eseguito", ""))]
        tested_ep = {(r.get("endpoint", ""), r.get("metodo", "")) for r in tested}
        single_source = [r for r in ep if (r.get("fonte_scoperta", "") or "").strip().lower().startswith("solo")]
        out.append(f"## Endpoint × identità\n- Endpoint×metodo censiti: **{len(endpoints)}**; con almeno un test eseguito: **{len(tested_ep)}**\n- Combinazioni (endpoint×identità×azione) pianificate: **{len(ep)}**; eseguite: **{len(tested)}**; mancanti: **{len(ep) - len(tested)}**")
        if single_source:
            out.append(f"- Righe scoperte da una sola fonte (da incrociare): {len(single_source)}")
        out.append("")

    ctl = rows(base / "controls-matrix.csv")
    if ctl is None:
        out.append("## Controlli\nnon disponibile: controls-matrix.csv assente\n")
    else:
        ctl, _ = real(ctl)
        applicable = [r for r in ctl if yes(r.get("applicabile", ""))]
        stati = Counter((r.get("stato", "") or "non indicato").strip().lower() for r in applicable)
        out.append(f"## Controlli (baseline)\n- Requisiti censiti: **{len(ctl)}**; applicabili: **{len(applicable)}**; non applicabili: {len(ctl) - len(applicable)}")
        for st, n in stati.most_common():
            out.append(f"  - {st}: {n} su {len(applicable)} applicabili")
        out.append("")

    doc = rows(base / "documentary-matrix.csv")
    if doc is not None:
        doc, _ = real(doc)
        stati = Counter((r.get("stato", "") or "non indicato").strip().lower() for r in doc)
        out.append(f"## Audit documentale\n- Voci esaminate: **{len(doc)}**")
        for st, n in stati.most_common():
            out.append(f"  - {st}: {n}")
        out.append("")

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import checklist
    cl = checklist.load(base)
    if cl is not None:
        c = Counter((r.get("esito") or "").strip().lower() or "non compilata" for r in cl)
        out.append(f"## Checklist delle aree\n- Aree: **{len(cl)}**; esaminate: **{c['esaminato']}**; parziali: {c['parziale']}; non esaminate: {c['non esaminato']}; non applicabili: {c['non applicabile']}; non compilate: {c['non compilata']}")
        for r in cl:
            if (r.get("esito") or "").strip().lower() in ("non esaminato", "parziale", ""):
                out.append(f"  - {r['id']} {r['area']}: {(r.get('esito') or 'NON COMPILATA').strip()}{(' — ' + r['motivo'].strip()) if (r.get('motivo') or '').strip() else ''}")
        out.append("")

    out.append("> I conteggi riguardano solo ciò che è stato inventariato: non provano l'assenza di asset o vulnerabilità non censiti.")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
