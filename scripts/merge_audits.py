#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Unisce più giri indipendenti sullo stesso repository in un unico elenco, con deduplica per causa e misura di accordo.

Uso:
    python3 merge_audits.py <audit-1> <audit-2> [<audit-3> …] --out <cartella-unione> [--etichette G1,G2,…]

Ogni argomento è una cartella di audit (findings/findings.json, oppure findings.json nella cartella) o una cartella di
gdpr-sentinel con gaps.csv: in quel caso l'unione scrive gaps.csv (ID GDPR-nnn) invece di findings.json.
Perché: due giri «rapido» sullo stesso repo hanno trovato finding quasi diversi (2 in comune su 10). Un giro non è
riproducibile né esaustivo; l'unione di più giri lo è di più, e l'accordo tra i giri dice quanto fidarsi di uno solo.

Abbinamento per contenuto, mai per ID (tra giri indipendenti «APP-001» indica cose diverse):
  - citazioni file:riga identiche                 +0.5 (+0.1 per ogni altra, fino a +0.3)
  - se nessuna è identica, righe o intervalli dello stesso file che si sovrappongono (± 3 righe)   +0.4 (+0.1 per ogni altra, fino a +0.2)
  - file citati in comune                         +0.4 × Jaccard
  - almeno un CWE in comune                       +0.15
  - parole in comune di titolo, osservato, asset, categoria   +0.8 × Jaccard
Punteggio ≥ 0.45: stessa causa. Tra 0.3 e 0.45: «possibile stessa causa», NON uniti e segnalati da guardare.
Vincoli: un gruppo non contiene mai due finding dello stesso giro (quel giro li aveva già separati) e due gruppi si
uniscono solo se ogni coppia fra i loro membri è almeno «possibile» (niente catene A~B~C per un file in comune).
Taratura: tre giri reali sullo stesso repo con le cause etichettate a mano (vedi docs/BENCHMARK.md).
Del gruppo resta il finding con lo stato più forte (riprodotto > confermato > ipotesi > non verificabile), poi la
severità più alta; gli altri sono citati nei limiti. Le severità discordanti sono segnalate, non mediate.

Scrive in --out: findings/findings.json (valido per lo schema), checklist-rapido.csv (per ogni area l'esito migliore
tra i giri), unione-giri.json e unione-giri.md (accordo, finding visti da un solo giro, aree mai esaminate).
"""
import argparse
import csv
import json
import re
import sys
from itertools import combinations
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import checklist  # noqa: E402

STATO = {"riprodotto dinamicamente": 0, "confermato da codice o configurazione": 1, "ipotesi da validare": 2, "non verificabile": 3}
SEV = {"critica": 0, "alta": 1, "media": 2, "bassa": 3, "informativa": 4}
ESITO = {"esaminato": 0, "parziale": 1, "non applicabile": 2, "non esaminato": 3, "": 4}
STOP = set("il lo la i gli le un una uno di da del della dei delle in con su per tra fra e o che non è a al alla ai agli "
           "nel nella nei sono come più senza anche the of to and a in is on for with".split())


GAPS_FIELDS = ["id", "controllo", "titolo", "riferimenti", "stato", "priorita", "rischio_interessati", "norma", "domanda_id", "smentita"]


def load_findings(d):
    """findings.json (appsec-sentinel) oppure gaps.csv (gdpr-sentinel), convertiti nello stesso formato interno."""
    for p in (d / "findings" / "findings.json", d / "findings.json"):
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    g = d / "gaps.csv"
    if g.exists():
        out = []
        for r in csv.DictReader(g.open(encoding="utf-8")):
            if (r.get("id") or "").startswith("ESEMPIO") or not (r.get("id") or "").strip():
                continue
            out.append({"id": r["id"].strip(), "titolo": r.get("titolo", ""), "categoria": (r.get("controllo") or "").strip().upper(),
                        "osservato": f"{r.get('titolo', '')} {r.get('rischio_interessati', '')}", "asset": r.get("norma", ""), "cwe": [],
                        "severita": {"alta": "alta", "media": "media", "bassa": "bassa"}.get((r.get("priorita") or "").strip().lower(), "media"),
                        "stato": (r.get("stato") or "").strip(), "limiti": "", "_gap": r,
                        "prova": {"riferimenti_file": [x.strip() for x in re.split(r"[;\n]", r.get("riferimenti") or "") if x.strip()]}})
        return out
    sys.exit(f"nessun findings.json né gaps.csv in {d}")


def refs(f):
    out = []
    for r in (f.get("prova") or {}).get("riferimenti_file") or []:
        m = re.match(r"\s*([^:\s]+)(?::(\d+)(?:-(\d+))?)?", str(r))
        if m:
            a = int(m.group(2)) if m.group(2) else None
            out.append((re.sub(r"^\./", "", m.group(1)), a, int(m.group(3)) if m.group(3) else a))
    return out


def words(s):
    return {w for w in re.findall(r"[a-zà-ù0-9]{3,}", (s or "").lower()) if w not in STOP}


def text_words(f):
    return words(" ".join(str(f.get(k) or "") for k in ("titolo", "osservato", "asset", "categoria")))


def similarity(a, b):
    """Somiglianza fra due finding di giri diversi (0–1.5 circa). Tarata su tre giri reali con cause etichettate a mano."""
    s, why = 0.0, []
    ra, rb = refs(a), refs(b)
    la = {(f, l) for f, l, _ in ra if l}
    lb = {(f, l) for f, l, _ in rb if l}
    exact = len(la & lb)
    if exact:
        s += 0.5 + min(0.3, 0.1 * (exact - 1)); why.append(f"{exact} citazioni file:riga identiche")
    if not exact:   # righe o intervalli che si toccano (a meno di 3 righe): la stessa istruzione citata come route.ts:312 e :313,
        # o come 330-346 e 313-346; un intervallo conta per tutte le sue righe, non solo per la prima
        ia = [(f, a1, a2 or a1) for f, a1, a2 in ra if a1]
        ib = [(f, b1, b2 or b1) for f, b1, b2 in rb if b1]
        near = sum(1 for f, a1, a2 in ia if any(f == g and a1 <= b2 + 3 and b1 <= a2 + 3 for g, b1, b2 in ib))
        if near:
            s += 0.4 + min(0.2, 0.1 * (near - 1)); why.append(f"{near} citazioni sovrapposte o a meno di 3 righe")
    fa, fb = {f for f, _, _ in ra}, {f for f, _, _ in rb}
    if fa | fb:
        fj = len(fa & fb) / len(fa | fb)
        if fj:
            s += 0.4 * fj; why.append(f"file in comune ({fj:.2f})")
    if set(a.get("cwe") or []) & set(b.get("cwe") or []):
        s += 0.15; why.append("CWE in comune")
    ta, tb = text_words(a), text_words(b)
    if ta and tb:
        tj = len(ta & tb) / len(ta | tb)
        if tj:
            s += 0.8 * tj; why.append(f"testo simile ({tj:.2f})")
    return round(s, 2), why


MERGE, MAYBE = 0.45, 0.3


def main():
    import i18n
    i18n.install()
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audits", nargs="+", type=Path)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--etichette")
    a = ap.parse_args()
    if len(a.audits) < 2:
        sys.exit("servono almeno due giri da unire")
    labels = a.etichette.split(",") if a.etichette else [f"G{i + 1}" for i in range(len(a.audits))]
    items = []   # (giro, finding)
    for lab, d in zip(labels, a.audits):
        for f in load_findings(d):
            items.append((lab, f))

    parent = list(range(len(items)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]; x = parent[x]
        return x

    # coppie di giri diversi, dalla più simile; due gruppi si uniscono solo se (1) non contengono due finding dello stesso
    # giro (il giro li aveva già separati) e (2) ogni coppia fra i loro membri è almeno «possibile»: niente catene A~B~C.
    pairs, sim = [], {}
    for i, j in combinations(range(len(items)), 2):
        if items[i][0] == items[j][0]:
            continue   # dentro lo stesso giro la deduplica è compito del revisore (verify_findings)
        s, why = similarity(items[i][1], items[j][1])
        sim[(i, j)] = sim[(j, i)] = s
        pairs.append((s, i, j, why))
    pairs.sort(key=lambda p: (-p[0], p[1], p[2]))
    members = {i: {i} for i in range(len(items))}
    possibili = []
    for s, i, j, why in pairs:
        ri, rj = find(i), find(j)
        if ri == rj:
            continue
        lbl = {"a": f"{items[i][0]} {items[i][1]['id']}", "b": f"{items[j][0]} {items[j][1]['id']}", "punteggio": s, "motivi": why}
        if s < MERGE:
            if s >= MAYBE:
                possibili.append(lbl)
            continue
        runs_i, runs_j = {items[x][0] for x in members[ri]}, {items[x][0] for x in members[rj]}
        if runs_i & runs_j:
            lbl["motivi"] = why + ["non unito: il gruppo ha già un finding dello stesso giro (forse un finding che ne raggruppa due)"]
            possibili.append(lbl)
            continue
        if any(sim.get((x, y), 0) < MAYBE for x in members[ri] for y in members[rj]):
            lbl["motivi"] = why + ["non unito: altri membri del gruppo non somigliano abbastanza"]
            possibili.append(lbl)
            continue
        parent[ri] = rj
        members[rj] |= members.pop(ri)

    groups = {}
    for i in range(len(items)):
        groups.setdefault(find(i), []).append(i)
    merged, report_groups = [], []
    for n, idx in enumerate(sorted(groups.values(), key=lambda g: min(STATO.get(items[i][1].get("stato"), 9) * 10 + SEV.get(items[i][1].get("severita"), 9) for i in g)), 1):
        best = min(idx, key=lambda i: (STATO.get(items[i][1].get("stato"), 9), SEV.get(items[i][1].get("severita"), 9)))
        f = json.loads(json.dumps(items[best][1]))
        seen = [f"{items[i][0]} {items[i][1]['id']}" for i in idx]
        giri = sorted({items[i][0] for i in idx}, key=labels.index)
        sevs = sorted({items[i][1].get("severita") for i in idx}, key=lambda s: SEV.get(s, 9))
        stati = sorted({items[i][1].get("stato") for i in idx}, key=lambda s: STATO.get(s, 9))
        f["id"] = f"UNI-{n:03d}"
        note = f" Unione di giri: visto in {', '.join(seen)} ({len(giri)} su {len(labels)} giri)."
        if len(sevs) > 1:
            note += f" Severità discordanti tra i giri: {' / '.join(sevs)}."
        if len(stati) > 1:
            note += f" Stati discordanti: {' / '.join(stati)}."
        f["limiti"] = (f.get("limiti") or "").rstrip() + note
        merged.append(f)
        report_groups.append({"id": f["id"], "titolo": f["titolo"], "visto_in": seen, "giri": giri, "severita": sevs, "stati": stati})

    # checklist: per ogni area l'esito migliore tra i giri
    cls = {lab: checklist.load(d) for lab, d in zip(labels, a.audits)}
    union_cl = None
    if any(cls.values()):
        base = next(v for v in cls.values() if v)
        union_cl = []
        for r in base:
            cands = [(lab, next((x for x in (cls[lab] or []) if x["id"] == r["id"]), None)) for lab in labels]
            cands = [(lab, x) for lab, x in cands if x and (x.get("esito") or "").strip()]
            row = dict(r)
            if cands:
                lab, x = min(cands, key=lambda c: ESITO.get(c[1]["esito"].strip().lower(), 9))
                row.update(esito=x["esito"], motivo=(x.get("motivo") or "") + f" [da {lab}]", riferimenti=x.get("riferimenti") or "")
            else:
                row.update(esito="", motivo="", riferimenti="")
            union_cl.append(row)

    n_all = sum(1 for g in report_groups if len(g["giri"]) == len(labels))
    per = {lab: sum(1 for it in items if it[0] == lab) for lab in labels}
    uniq = {lab: sum(1 for g in report_groups if g["giri"] == [lab]) for lab in labels}
    acc = round(n_all / len(report_groups), 2) if report_groups else 0
    res = {"giri": labels, "finding_per_giro": per, "cause_distinte": len(report_groups), "viste_da_tutti": n_all,
           "accordo": acc, "solo_in_un_giro": uniq, "gruppi": report_groups, "possibili_stessa_causa": possibili}
    # seconda misura, senza il vincolo «un finding per giro e per gruppo»: quota di finding con almeno un corrispondente
    # (punteggio da unione) in un altro giro. Più alta dell'accordo quando i giri dividono le cause in modo diverso
    # (in privacy succede spesso); è una stima alta, perché un abbinamento può reggersi su una sola citazione in comune.
    corr = sum(1 for i in range(len(items)) if any(sim.get((i, j), 0) >= MERGE for j in range(len(items)) if items[j][0] != items[i][0]))
    res["con_corrispondente"] = round(corr / len(items), 2) if items else 0

    # matrice per entità (gdpr-sentinel): accordo cella per cella sulle righe che lo script non chiude da solo. È la misura
    # di stabilità giusta per le domande strutturate: due giri possono dare le stesse risposte e raggrupparle in gap diversi.
    mats = []
    for d in a.audits:
        ep = d / "entita.csv"
        mats.append({(r["entita"], r["domanda"]): r for r in csv.DictReader(ep.open(encoding="utf-8"))} if ep.exists() else None)
    if all(m is not None for m in mats) and mats:
        keys = [k for k in mats[0] if all(k in m for m in mats[1:])
                and not any((m[k].get("prepass") or "").strip().lower().startswith(("si", "n/a")) and not (m[k].get("esito") or "").strip() for m in mats)]
        isgap = lambda m, k: (m[k].get("esito") or "").strip().lower() == "gap"
        same = [k for k in keys if len({isgap(m, k) for m in mats}) == 1]
        perq = {}
        for k in keys:
            t = perq.setdefault(k[1], [0, 0]); t[1] += 1; t[0] += k in same
        res["matrice_entita"] = {"righe": len(keys), "stesso_giudizio": len(same), "per_domanda": perq}
    infs = []
    for d in a.audits:
        ip_ = d / "informativa.csv"
        infs.append({r["voce"]: r for r in csv.DictReader(ip_.open(encoding="utf-8"))} if ip_.exists() else None)
    if all(m is not None for m in infs) and infs:
        ks = [k for k in infs[0] if all(k in m for m in infs[1:])
              and not any((m[k].get("prepass") or "").strip().lower().startswith(("si", "n/a")) and not (m[k].get("esito") or "").strip() for m in infs)]
        sm = [k for k in ks if len({(m[k].get("esito") or "").strip().lower() == "gap" for m in infs}) == 1]
        res["matrice_informativa"] = {"righe": len(ks), "stesso_giudizio": len(sm)}
    accs = []
    for d in a.audits:
        ap_ = d / "accessi.csv"
        accs.append({(r["entita"], r["ruolo"]): r for r in csv.DictReader(ap_.open(encoding="utf-8"))} if ap_.exists() else None)
    if all(m is not None for m in accs) and accs:   # ruoli e accessi: stesso giudizio (gap o no) e stesso ambito
        ka = [k for k in accs[0] if all(k in m for m in accs[1:])
              and not any((m[k].get("prepass") or "").strip().lower().startswith(("si", "n/a")) and not (m[k].get("esito") or "").strip() for m in accs)]
        sa = [k for k in ka if len({(m[k].get("esito") or "").strip().lower() == "gap" for m in accs}) == 1]
        amb = [k for k in ka if len({(m[k].get("ambito") or "").strip().lower() for m in accs}) == 1]
        res["matrice_accessi"] = {"righe": len(ka), "stesso_giudizio": len(sa), "stesso_ambito": len(amb)}
    out = a.out
    out.mkdir(parents=True, exist_ok=True)
    if res.get("matrice_entita"):   # unione della matrice: gap se almeno un giro lo dice, con la provenienza
        with (out / "entita.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["entita", "dati", "fonte", "domanda", "prepass", "esito", "gap_id", "note"])
            for k, r in mats[0].items():
                es = [(lab, (m.get(k, {}).get("esito") or "").strip().lower()) for lab, m in zip(labels, mats)]
                g = [lab for lab, e in es if e == "gap"]
                w.writerow([r["entita"], r["dati"], r["fonte"], r["domanda"], r["prepass"], "gap" if g else (es[0][1] or ""), "",
                            ("gap per " + ", ".join(g) + "; " if g and len(g) < len(es) else "") + " | ".join(f"{lab}: {e or '-'}" for lab, e in es)])
    if res.get("matrice_accessi"):   # unione: gap se almeno un giro lo dice; ambito il più ampio dichiarato
        ordine = {"nessuno": 0, "propri": 1, "gruppo": 2, "tutti": 3}
        with (out / "accessi.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["entita", "dati", "ruolo", "prepass", "ambito", "esito", "gap_id", "note"])
            for k, r in accs[0].items():
                es = [(lab, (m.get(k, {}).get("esito") or "").strip().lower(), (m.get(k, {}).get("ambito") or "").strip().lower())
                      for lab, m in zip(labels, accs)]
                g = [lab for lab, e, _ in es if e == "gap"]
                am_ = max((x for _, _, x in es if x in ordine), key=ordine.get, default="")
                w.writerow([r["entita"], r["dati"], r["ruolo"], r["prepass"], am_, "gap" if g else (es[0][1] or ""), "",
                            ("gap per " + ", ".join(g) + "; " if g and len(g) < len(es) else "")
                            + " | ".join(f"{lab}: {e or '-'}/{x or '-'}" for lab, e, x in es)])
    gaps_mode = all("_gap" in f for f in merged) and merged
    if gaps_mode:
        with (out / "gaps.csv").open("w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=GAPS_FIELDS + ["unione"])
            w.writeheader()
            for f in merged:
                row = dict(f["_gap"]); row["id"] = f["id"].replace("UNI-", "GDPR-")
                row["priorita"] = f["severita"]
                row["unione"] = f["limiti"].strip()   # da quali giri viene, e se severità o stati erano discordanti
                w.writerow({k: row.get(k, "") for k in GAPS_FIELDS + ["unione"]})
    else:
        (out / "findings").mkdir(exist_ok=True)
        (out / "findings" / "findings.json").write_text(json.dumps(merged, indent=1, ensure_ascii=False), encoding="utf-8")
    (out / "unione-giri.json").write_text(json.dumps(res, indent=1, ensure_ascii=False), encoding="utf-8")
    if union_cl:
        checklist.write(out, union_cl)
    md = [f"# Unione di {len(labels)} giri", "",
          f"- Finding per giro: {', '.join(f'{k} {v}' for k, v in per.items())}",
          f"- Cause distinte dopo l'unione: **{len(report_groups)}**; viste da tutti i giri: **{n_all}**; accordo: **{acc:.0%}**",
          f"- Viste da un solo giro: {', '.join(f'{k} {v}' for k, v in uniq.items())}", "",
          "Un accordo basso significa che un singolo giro ha perso parte di ciò che un altro ha trovato: l'elenco unito è più completo "
          "di ciascun giro, ma non è esaustivo. Una causa vista da un solo giro non è meno vera: è stata cercata da un giro solo.", "",
          "| ID | Titolo | Visto in | Severità |", "|---|---|---|---|"]
    md += [f"| {g['id']} | {g['titolo'][:90]} | {', '.join(g['visto_in'])} | {' / '.join(g['severita'])} |" for g in report_groups]
    if possibili:
        md += ["", "## Possibile stessa causa (non uniti: da decidere a mano)"] + [f"- {p['a']} ↔ {p['b']} ({p['punteggio']}: {', '.join(p['motivi'])})" for p in possibili]
    if union_cl:
        never = [r for r in union_cl if (r.get("esito") or "").strip().lower() in ("", "non esaminato")]
        md += ["", "## Checklist unita", f"Aree esaminate da almeno un giro: {sum(1 for r in union_cl if (r.get('esito') or '').strip().lower() in ('esaminato', 'parziale'))} su {len(union_cl)}."]
        if never:
            md += ["Aree non esaminate da nessun giro:"] + [f"- {r['id']} {r['area']}" for r in never]
    (out / "unione-giri.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(f"giri: {len(labels)} · finding: {', '.join(f'{k} {v}' for k, v in per.items())} · cause distinte: {len(report_groups)} · "
          f"viste da tutti: {n_all} · accordo: {acc:.0%}")
    if res.get("matrice_entita"):
        me = res["matrice_entita"]
        print(f"matrice per entità: stesso giudizio (gap o no) su {me['stesso_giudizio']}/{me['righe']} righe aperte "
              f"({me['stesso_giudizio'] / max(1, me['righe']):.0%}) · " + ", ".join(f"{q} {v[0]}/{v[1]}" for q, v in sorted(me['per_domanda'].items())))
    if res.get("matrice_informativa"):
        mi = res["matrice_informativa"]
        print(f"matrice dell'informativa: stesso giudizio (gap o no) su {mi['stesso_giudizio']}/{mi['righe']} voci aperte ({mi['stesso_giudizio'] / max(1, mi['righe']):.0%})")
    if res.get("matrice_accessi"):
        ma = res["matrice_accessi"]
        print(f"matrice dei ruoli e degli accessi: stesso giudizio (gap o no) su {ma['stesso_giudizio']}/{ma['righe']} coppie aperte "
              f"({ma['stesso_giudizio'] / max(1, ma['righe']):.0%}) · stesso ambito {ma['stesso_ambito']}/{ma['righe']}")
    print(f"finding con un corrispondente in un altro giro: {res['con_corrispondente']:.0%} (stima alta: conta anche i giri che dividono "
          "o raggruppano le cause in modo diverso; da leggere insieme all'accordo)")
    durate = []
    for lab, d in zip(labels, a.audits):   # durata di ogni giro, se chiuso con check_delivery (registro-tool/tempi.json)
        try:
            ch = json.loads((Path(d) / "registro-tool" / "tempi.json").read_text(encoding="utf-8")).get("chiusure") or []
            durate.append(f"{lab} {ch[-1]['minuti_dall_inizio']:.0f} min")
        except (OSError, ValueError, LookupError, TypeError):
            pass
    if durate:
        print("durata dei giri (dall'inizio alla chiusura): " + ", ".join(durate))
    if possibili:
        print(f"possibile stessa causa (non uniti, da decidere a mano): {len(possibili)}")
    print(f"scritto: {out}/{'gaps.csv' if gaps_mode else 'findings/findings.json'}, unione-giri.md, unione-giri.json" + (", checklist-rapido.csv" if union_cl else ""))
    import subprocess
    v = subprocess.run([sys.executable, str(HERE / "validate_findings.py"), str(out / "findings" / "findings.json")], capture_output=True, text=True) \
        if (HERE / "validate_findings.py").exists() and not gaps_mode else None
    if v is not None and v.returncode != 0:
        last = (v.stdout.strip().splitlines() or ["errori"])[-1]
        print(f"ATTENZIONE: l'elenco unito non supera la validazione ({last}): gli errori vengono dai giri originali; correggili lì e rifai l'unione.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
