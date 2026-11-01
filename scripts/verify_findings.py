#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Passaggio di revisione indipendente sui finding: cerca falsi positivi e incoerenze prima del report.

Uso:
    python3 verify_findings.py findings/findings.json [--repo <cartella-del-codice>] [--md revisione.md]

Controlli meccanici (sola lettura):
  - i riferimenti «path:riga» esistono nel repository e la riga è nel file (con --repo);
  - severità alta/critica con stato «ipotesi da validare» o «non verificabile»: va giustificata;
  - «confermato da codice o configurazione» senza riferimenti a file;
  - finding con stesso file e categoria o titoli molto simili: possibili duplicati;
  - mancano retest, limiti o mitigazione temporanea su finding alti;
  - CVSS senza versione; testo di impatto «reale» che afferma un danno senza test eseguito;
  - finding alti o critici senza la «smentita» (tentativo di confutazione da parte di un verificatore diverso
    dall'autore, vedi references/refutation-pass.md), o con esito «resiste» senza tentativi descritti.
Per ogni finding stampa anche le domande del revisore (raggiungibilità, mitigazioni a monte, ambiente) da
rispondere a mano o con un secondo passaggio: vedi references/review-pass.md. Non sostituisce la validazione.
"""
import argparse
import difflib
import json
import re
import sys
from pathlib import Path

QUESTIONS = ["È raggiungibile da chi? In quale ambiente (produzione, staging, solo locale)?",
             "Esiste una mitigazione a monte (proxy, WAF, middleware, rete) che il codice letto non mostra?",
             "La prova dimostra davvero la conclusione, o solo la presenza di un pattern?",
             "Lo stato dichiarato è quello raggiunto? Un test non eseguito non può essere «riprodotto».",
             "Severità e impatto reale dipendono da dati o condizioni non verificati?"]


def brief(f):
    """Brief per il verificatore: l'affermazione e i riferimenti, NON la motivazione dell'autore."""
    def is_secret(x):
        txt = " ".join(str(x.get(k) or "") for k in ("titolo", "categoria")).lower()
        return "CWE-798" in (x.get("cwe") or []) or any(w in txt for w in ("segret", "secret", "password", "credenzial", ".env", "token", "chiave"))
    refs = "\n".join(f"- `{r}`" for r in f["prova"].get("riferimenti_file", [])) or "- (nessun riferimento a file)"
    return (f"# Smentita di {f['id']}\n\n"
            "Il tuo compito è **dimostrare che questo finding è sbagliato, esagerato o non raggiungibile**. "
            "Non sei l'autore: non cercare conferme. Se non riesci a smentirlo, dillo e spiega cosa hai provato.\n\n"
            f"## Affermazione\n{f['titolo']}\n\n- Asset: {f['asset']}\n- Attore dichiarato: {f['attore']}\n"
            f"- Severità dichiarata: {f['severita']} · stato dichiarato: {f['stato']}\n\n## Dove guardare\n{refs}\n\n"
            "## Ipotesi di smentita da provare (almeno quelle pertinenti)\n"
            "1. Il codice è raggiungibile in produzione o è solo test, esempio, dead code, build di sviluppo?\n"
            "2. Un controllo a monte (middleware, proxy, WAF, rete, flag di ambiente) blocca già il percorso?\n"
            "3. L'attore dichiarato ha davvero quel punto di ingresso e quei privilegi?\n"
            "4. L'impatto richiede condizioni non verificate (dati presenti, configurazione, versione distribuita)?\n"
            "5. La severità è quella giusta per probabilità × impatto, o è un rafforzamento mascherato da vulnerabilità?\n"
            "6. Lo stato dichiarato è quello raggiunto? Una lettura del codice non è un test.\n"
            + ("7. (segreti) Il valore è un segnaposto o un esempio (CHANGE_ME, COPY_FROM_…, GENERATE_…, your-…, solo maiuscole e "
               "underscore, parole da dizionario)? Verificalo guardando la forma del valore senza trascriverlo: in un audit reale un "
               "file .env versionato con soli segnaposto era stato classificato «alta» e la smentita non l'aveva visto.\n"
               "8. (segreti) Il valore è quello di produzione o di uno sviluppo locale? È ancora valido, o è già stato ruotato?\n"
               if is_secret(f) else "")
            + "\n## Cosa restituire\nEsito (`resiste` / `declassato` / `respinto`), le ipotesi provate con come le hai verificate, "
            "e chi sei. Copia il risultato nel campo `smentita` del finding.\n")


def is_secret_finding(x):
    txt = " ".join(str(x.get(k) or "") for k in ("titolo", "categoria")).lower()
    return "CWE-798" in (x.get("cwe") or []) or any(w in txt for w in ("segret", "secret", "password", "credenzial", ".env", "token", "chiave"))


def placeholder_refs(repo, refs):
    """Riferimenti file:righe in cui TUTTI i valori assegnati a nomi da segreto sono segnaposto. Non restituisce mai valori."""
    import re
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import secret_triage as st
    out = []
    for ref in refs:
        path, _, rng = ref.partition(":")
        p = repo / path
        if not p.is_file():
            continue
        allx = p.read_text(encoding="utf-8", errors="replace").splitlines()
        envfile = re.search(r"(^|/)\.env(\.[\w.-]+)?$", path) is not None
        if re.fullmatch(r"\d+(-\d+)?", rng or ""):
            a_, _, b_ = rng.partition("-")
            lines = allx[int(a_) - 1:int(b_ or a_)]
        elif envfile:
            lines = allx
        else:
            continue
        vals = [m.group(2).strip().strip("\"'") for ln in lines for m in [re.match(r"\s*(?:export\s+)?([A-Za-z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|KEY|PWD)[A-Za-z0-9_]*)\s*[=:]\s*(.+)", ln, re.I)] if m]
        for ln in lines:
            for m in st.CONN.finditer(ln):
                vals.append(m.group(3))
        if not vals and envfile and lines is not allx:   # riga citata senza assegnazioni (es. un commento): guarda tutto il file .env
            return placeholder_refs(repo, [path])
        if vals and all(re.fullmatch(r"[A-Z0-9_]+", v) and "_" in v or any(w in v.lower() for w in st.PLACEHOLDER) for v in vals if v):
            out.append(ref)
    return out


def main():
    import i18n
    i18n.install()  # --lang en per i messaggi in inglese
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", type=Path)
    ap.add_argument("--repo", type=Path)
    ap.add_argument("--md", type=Path)
    ap.add_argument("--brief-dir", type=Path, help="scrive un brief per il verificatore per ogni finding alto o critico")
    a = ap.parse_args()
    fs = json.loads(a.findings.read_text(encoding="utf-8"))
    issues = {f["id"]: [] for f in fs}
    for f in fs:
        i = issues[f["id"]]
        refs = f["prova"].get("riferimenti_file", [])
        if f["stato"] == "confermato da codice o configurazione" and not refs and f["prova"].get("tipo") not in ("documento", "configurazione"):
            i.append("stato «confermato da codice o configurazione» senza riferimenti a file")
        repo_refs = [r for r in refs if not r.startswith("audit:") and not re.search(r"(?i)storia git|@[0-9a-f]{7,40}\b", r)]
        if f["stato"] in ("confermato da codice o configurazione", "riprodotto dinamicamente") and repo_refs \
                and not any(re.search(r":\d+", r) for r in repo_refs):
            i.append("riferimenti senza numero di riga: citare almeno la riga del problema (file:riga)")
        if a.repo:
            for ref in refs:
                if ref.startswith("audit:"):
                    continue   # artefatto della cartella di audit (registro delle richieste, output di uno scanner): non è nel repository
                if re.search(r"(?i)storia git|git history|@[0-9a-f]{7,40}\b", ref):
                    continue   # file che esiste solo nella storia: si cita come «percorso@commit» o «percorso (storia Git)»
                path, _, rng = ref.partition(":")
                p = a.repo / path
                if not p.exists():
                    i.append(f"riferimento inesistente: {ref}")
                    continue
                line = rng.split("-")[0].split(",")[0]
                if line.isdigit() and p.is_file():
                    n = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
                    if int(line) > n:
                        i.append(f"riga {line} oltre la fine di {path} ({n} righe)")
            # finding sui segreti che citano righe con soli segnaposto (due giri reali su quattro ci sono cascati)
            if is_secret_finding(f):
                ph = placeholder_refs(a.repo, refs)
                if ph:
                    i.append(f"i valori alle righe citate sembrano segnaposto ({', '.join(ph[:3])}): verificare che il segreto sia reale prima di segnalarlo")
        if f["severita"] in ("alta", "critica"):
            if f["stato"] in ("ipotesi da validare", "non verificabile"):
                i.append(f"severità {f['severita']} con stato «{f['stato']}»: giustificare o declassare")
            if not f["intervento"].get("mitigazione_temporanea"):
                i.append("finding alto senza mitigazione temporanea")
            sm = f.get("smentita")
            if not sm:
                i.append("finding alto senza smentita: farlo confutare da un verificatore diverso dall'autore (brief con --brief-dir)")
            elif sm.get("esito") == "non eseguita":
                i.append("smentita non eseguita: dichiararlo nel report come limite")
            elif re.search(r"\bstess[oa]\b|\bio\b|\bme\b", sm.get("verificatore", "").lower()):
                i.append("smentita fatta dall'autore stesso: non è indipendente, usare «non eseguita» oppure un verificatore diverso")
            elif re.search(r"passaggio|revisione", sm.get("verificatore", "").lower()) and not re.search(r"sessione|agente|persona|collega|conversazione", sm.get("verificatore", "").lower()):
                i.append("smentita da un «secondo passaggio» senza dire chi l'ha fatto: vale solo se fatta in una sessione nuova o da un altro agente o persona; scriverlo nel campo verificatore, altrimenti «non eseguita»")
            elif sm.get("esito") == "resiste" and not sm.get("tentativi"):
                i.append("smentita «resiste» senza tentativi descritti")
            elif sm.get("esito") in ("declassato", "respinto") and f["severita"] in ("alta", "critica") and f["stato"] != "non verificabile":
                i.append(f"smentita «{sm['esito']}» ma il finding è ancora {f['severita']}: allineare severità e stato")
        if not f.get("retest"):
            i.append("manca il retest")
        if f.get("cvss") and not (f["cvss"].get("versione") if isinstance(f["cvss"], dict) else True):
            i.append("CVSS senza versione")
        if f["stato"] != "riprodotto dinamicamente" and not f["prova"].get("test_eseguito"):
            real = f["impatto"]["reale"].lower()
            if real and not any(k in real for k in ("non dimostrat", "nessun test", "non eseguit", "non verificat", "non valutat", "nessun dato", "nessuna esecuzione", "sintetic", "dimostrativ")):
                i.append("l'impatto «reale» afferma un effetto senza test eseguito: riformulare come potenziale o dichiarare il limite")
    for x in range(len(fs)):
        for y in range(x + 1, len(fs)):
            A, B = fs[x], fs[y]
            r = difflib.SequenceMatcher(None, A["titolo"].lower(), B["titolo"].lower()).ratio()
            same = set(A["prova"].get("riferimenti_file", [])) & set(B["prova"].get("riferimenti_file", []))
            if r > 0.85 or (same and A["categoria"] == B["categoria"]):
                issues[A["id"]].append(f"possibile duplicato di {B['id']}")
                issues[B["id"]].append(f"possibile duplicato di {A['id']}")
    if a.brief_dir:
        a.brief_dir.mkdir(parents=True, exist_ok=True)
        for f in fs:
            if f["severita"] in ("alta", "critica"):
                (a.brief_dir / f"smentita-{f['id']}.md").write_text(brief(f), encoding="utf-8")
    L = ["# Revisione dei finding", ""]
    total = 0
    for f in fs:
        i = issues[f["id"]]
        total += len(i)
        L.append(f"## {f['id']} · {f['titolo']} ({f['severita']}, {f['stato']})")
        L += [f"- ⚠ {x}" for x in i] or ["- controlli meccanici superati"]
        L += ["", "Domande del revisore:"] + [f"  - {q}" for q in QUESTIONS] + [""]
    out = "\n".join(L)
    if a.md:
        keep = ""
        if a.md.exists():   # le risposte scritte a mano sotto «## Risposte» sopravvivono a una nuova esecuzione
            prev = a.md.read_text(encoding="utf-8")
            if "\n## Risposte" in prev:
                keep = prev[prev.index("\n## Risposte"):]
        a.md.write_text(out.rstrip("\n") + "\n" + (keep if keep else "\n## Risposte\n(motivare qui i rilievi che restano: questa sezione non viene sovrascritta)\n"), encoding="utf-8")
    for f in fs:
        for x in issues[f["id"]]:
            print(f"{f['id']}: {x}")
    print(f"\nfinding: {len(fs)}  rilievi del revisore: {total}" + (f"  -> {a.md}" if a.md else ""))
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
