#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Samuele Cucurnia e Pietro Previtali
"""Genera un report PDF in formato aziendale dalla cartella di audit.

Uso:
    python3 build_report_pdf.py <cartella-audit> [--out report.pdf] [--meta meta.json]
                                [--sintetico] [--lang it|en] [--previous findings-precedente.json] [--nis2]

Opzioni:
  --sintetico   versione breve per la direzione: copertina, sintesi, quadro, piano (senza dettagli e matrici)
  --lang en     etichette e titoli fissi in inglese (il contenuto dei file di audit resta nella sua lingua)
  --previous    aggiunge il confronto con un audit precedente (risolti, nuovi, cambiati)
  --nis2        aggiunge la mappatura INDICATIVA dei finding sulle misure dell'art. 21 NIS2

Legge, se presenti (tutti opzionali, il PDF include solo le sezioni con dati):
  findings/findings.json        finding validati (appsec-sentinel)
  documentary-matrix.csv        audit documentale
  coverage-matrix.csv, endpoint-matrix.csv   copertura con denominatori reali
  gdpr-matrix.csv, processing-map.csv        valutazione privacy (gdpr-sentinel)
  meta.json                     titolo, cliente, asset, versione, data, autore, modalità,
                                classificazione, sintesi[], non_verificato[], domande_aperte[], note_copertura,
                                domande[] ({id, destinatario, domanda}), piano[] ({fase, azione, responsabile})

Richiede `reportlab` (pip install reportlab). Per i caratteri accentati e i simboli usa
DejaVu Sans se disponibile; altrimenti Helvetica con sostituzioni sicure.
Il PDF non contiene segreti: riporta solo ciò che è nei file di audit, che devono già
essere redatti. Rileggi sempre il PDF prima di consegnarlo.
"""
import argparse
import csv
import json
import re
import sys
from collections import Counter
from datetime import date
from pathlib import Path
from xml.sax.saxutils import escape

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.pdfgen import canvas as rl_canvas
    from reportlab.platypus import (BaseDocTemplate, Flowable, Frame, PageBreak,
                                    PageTemplate, Paragraph, Spacer, Table, TableStyle)
    from reportlab.platypus.tableofcontents import TableOfContents
except ImportError:
    sys.exit("Serve reportlab: pip install reportlab")

H = colors.HexColor
NAVY, NAVY2, SLATE, LIGHT, PALE, MIST = H("#0f172a"), H("#1e293b"), H("#64748b"), H("#e2e8f0"), H("#f1f5f9"), H("#f8fafc")
TEAL, TEAL_D, TEAL_L = H("#14b8a6"), H("#0f766e"), H("#5eead4")
AMBER, AMBER_D, AMBER_L = H("#f59e0b"), H("#b45309"), H("#fcd34d")
GREEN = H("#16a34a")
SEV = {"critica": H("#991b1b"), "alta": H("#dc2626"), "media": H("#d97706"), "bassa": H("#2563eb"), "informativa": H("#64748b")}
LANG = "it"
TR = {
    "Indice": "Contents", "Sintesi per il proprietario": "Executive summary", "Da fare per primo": "Do first", "Quadro dei finding": "Findings overview",
    "Dettaglio dei finding": "Finding details", "Audit documentale": "Documentary audit", "Valutazione privacy (GDPR/ePrivacy)": "Privacy assessment (GDPR/ePrivacy)",
    "Mappa dei trattamenti": "Processing map", "Domande per titolare, DPO, legale e fornitori": "Questions for controller, DPO, legal and suppliers",
    "Copertura e limiti": "Coverage and limits", "Due giri indipendenti": "Two independent runs", "Gap privacy": "Privacy gaps",
    "Cause distinte": "Distinct causes", "Viste da entrambi": "Seen by both", "Viste da un solo giro": "Seen by one run", "entrambi": "both", "Matrici di copertura": "Coverage matrices", "Piano di intervento proposto": "Proposed action plan",
    "Metodo e avvertenze": "Method and disclaimers", "Non verificato": "Not verified", "Domande aperte per il proprietario": "Open questions for the owner",
    "Inventario e copertura": "Inventory and coverage", "Endpoint censiti": "Endpoints inventoried", "Controlli (ASVS, NIST, ACN)": "Controls (ASVS, NIST, ACN)",
    "Subito": "Now", "Prossime settimane": "Next weeks", "Pianificato": "Planned", "Confronto con l'audit precedente": "Comparison with the previous audit",
    "Mappatura indicativa sulle misure NIS2 (art. 21)": "Indicative mapping to NIS2 measures (art. 21)",
    "ID": "ID", "Severità": "Severity", "Titolo": "Title", "Stato": "Status", "Documento": "Document", "Rilievo e azione": "Finding and action",
    "Ctrl": "Ctrl", "Area": "Area", "Gap": "Gap", "Trattamento": "Processing", "Dati e interessati": "Data and subjects", "Destinatario": "Recipient",
    "Domanda": "Question", "Area o percorso": "Area or path", "Verifica": "Check", "Esaminato": "Examined", "Note": "Notes", "Endpoint": "Endpoint",
    "Metodo": "Method", "Identità e ruolo": "Identity and role", "Azione": "Action", "Test": "Test", "Finding": "Finding", "Fonte e sezione": "Source and section",
    "Requisito": "Requirement", "Applicabile": "Applicable", "Gap o compensazione": "Gap or compensation", "Intervento": "Action",
    "Responsabile proposto": "Proposed owner", "Quando": "When", "Lettera": "Letter", "Misura": "Measure", "Finding collegati": "Linked findings",
    "Stato e confidenza": "Status and confidence", "Riferimenti": "References", "Prova": "Evidence", "File": "Files", "Atteso / osservato": "Expected / observed",
    "Impatto": "Impact", "Perché questa severità": "Why this severity", "Correzione": "Fix", "Retest": "Retest", "Limiti": "Limits", "Smentita": "Refutation attempt",
    "Oggetto": "Subject", "Versione esaminata": "Version examined", "Modalità": "Mode", "Data": "Date", "Preparato da": "Prepared by", "Classificazione": "Classification",
    "Provato": "Proven", "Ignoto": "Unknown", "Riscontrato": "Found", "Ipotesi": "Hypothesis", "Non verificabile": "Not verifiable", "FINDING": "FINDINGS",
    "Critica": "Critical", "Alta": "High", "Media": "Medium", "Bassa": "Low", "Informativa": "Informational",
    "critica": "critical", "alta": "high", "media": "medium", "bassa": "low", "informativa": "informational",
    "Atteso:": "Expected:", "Osservato:": "Observed:", "Reale:": "Actual:", "Potenziale:": "Potential:", "Condizioni:": "Conditions:", "su": "of",
    "Confronto tra ciò che i documenti affermano e ciò che risulta da codice e configurazione, più completezza e aggiornamento dei documenti.":
        "What the documents claim compared with what code and configuration show, plus completeness and currency of the documents.",
    "Analisi tecnica e documentale: non è un parere legale e non esprime giudizi di conformità. Le decisioni spettano a titolare, DPO e legale.":
        "Technical and documentary analysis: not legal advice and no compliance verdict. Decisions belong to the controller, DPO and legal counsel.",
    "Ogni punto non verificabile o incoerente ha la sua domanda, con il destinatario e il materiale necessario.":
        "Each unverifiable or inconsistent point has its own question, with the recipient and the material needed.",
    "La copertura riguarda solo ciò che è stato inventariato: non prova l'assenza di problemi non censiti.":
        "Coverage concerns only what was inventoried: it does not prove the absence of problems that were not listed.",
    "Il dettaglio da cui derivano i conteggi: cosa è stato esaminato, quali endpoint sono censiti e con quale test.":
        "The detail behind the counts: what was examined, which endpoints are inventoried and with which test.",
    "Gli stati dichiarati sono quelli effettivamente raggiunti: «confermato da codice o configurazione» non equivale a «riprodotto dinamicamente».":
        "Stated statuses are those actually reached: 'confirmed from code or configuration' is not 'dynamically reproduced'.",
    "I tempi dipendono da impatto e obblighi del titolare; non sono scadenze di legge. Dopo ogni correzione va eseguito il retest indicato nel finding.":
        "Timing depends on impact and the owner's obligations; these are not legal deadlines. After each fix run the retest given in the finding.",
    "Le priorità derivano dal rischio per gli interessati, non da scadenze di legge.": "Priorities follow the risk to data subjects, not legal deadlines.",
    "«Test: no» significa che l'endpoint è stato censito dal codice ma non provato. Gli stati dei finding collegati dicono cosa è dimostrato.":
        "'Test: no' means the endpoint was inventoried from code but not tried. Linked finding statuses say what is proven.",
    "Valutazione eseguita con le skill appsec-sentinel e gdpr-sentinel (Apache-2.0). Ogni finding ha uno stato che dice cosa è stato dimostrato. Non è un penetration test completo, non certifica sicurezza o conformità e non sostituisce il parere di DPO e legale. Segreti e dati personali non sono riportati. Le fonti normative e gli standard vanno riverificati prima di citarli.":
        "Assessment performed with the appsec-sentinel and gdpr-sentinel skills (Apache-2.0). Each finding has a status saying what was proven. This is not a full penetration test, does not certify security or compliance and does not replace DPO and legal advice. Secrets and personal data are not reported. Regulatory sources and standards must be re-verified before quoting.",
    "Documento riservato. Non costituisce certificazione né parere legale.": "Confidential document. Not a certification nor legal advice.",
    "riprodotto dinamicamente": "dynamically reproduced", "confermato da codice o configurazione": "confirmed from code or configuration",
    "ipotesi da validare": "hypothesis to validate", "non verificabile": "not verifiable", "riscontrato": "found",
    "confermato da codice/config": "confirmed from code/config", "confermato da codice": "confirmed from code",
    "confidenza": "confidence",
    "sì": "yes", "si": "yes", "parziale": "partial", "no": "no", "applicabile": "applicable", "non applicabile": "not applicable",
    "Threat model": "Threat model", "Test dinamici eseguiti": "Dynamic tests performed", "Controllo atteso": "Expected control", "Esito": "Result",
    "Flussi, confini di fiducia e percorsi di attacco considerati (da report/threat-model.md). È la mappa che ha guidato l'esame, non un elenco di vulnerabilità.":
        "Flows, trust boundaries and attack paths considered (from report/threat-model.md). It is the map that guided the review, not a list of vulnerabilities.",
    "Il threat model continua nel file report/threat-model.md.": "The threat model continues in report/threat-model.md.",
    "Le prove fatte davvero sull'istanza autorizzata, come registrate nella matrice degli endpoint: identità usata, esito osservato e finding collegato. Un endpoint che non compare qui non è stato provato.":
        "The tests actually run against the authorized instance, as recorded in the endpoint matrix: identity used, observed result and linked finding. An endpoint not listed here was not tested.",
    "Risolti": "Resolved", "Nuovi": "New", "Cambiati": "Changed", "Ancora aperti": "Still open",
}


def T(s):
    return TR.get(s, s) if LANG == "en" else s


def V(s):
    """Valore macchina (stato, confidenza) mostrato nella lingua del report; i file di audit restano con i valori canonici."""
    if LANG != "en":
        return s
    k = str(s).strip()
    return TR.get(k, TR.get(k.lower(), s))


ORDER = {"critica": 0, "alta": 1, "media": 2, "bassa": 3, "informativa": 4}
FONT_DIRS = ["/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu", "/Library/Fonts", "/System/Library/Fonts/Supplemental",
             "C:/Windows/Fonts"]
SAFE = {"→": "->", "≠": "!=", "✓": "OK", "•": "-", "–": "-", "—": "-", "’": "'", "“": '"', "”": '"'}
UNICODE = False
BASE, BOLD = "Helvetica", "Helvetica-Bold"
PAGE_W, PAGE_H = A4
LM = 20 * mm
CW = 170 * mm


def setup_fonts():
    global UNICODE, BASE, BOLD
    for d in FONT_DIRS:
        reg, bold = Path(d) / "DejaVuSans.ttf", Path(d) / "DejaVuSans-Bold.ttf"
        if reg.exists() and bold.exists():
            pdfmetrics.registerFont(TTFont("DejaVu", str(reg)))
            pdfmetrics.registerFont(TTFont("DejaVu-Bold", str(bold)))
            pdfmetrics.registerFontFamily("DejaVu", normal="DejaVu", bold="DejaVu-Bold", italic="DejaVu", boldItalic="DejaVu-Bold")
            UNICODE, BASE, BOLD = True, "DejaVu", "DejaVu-Bold"
            return


def clean(s):
    s = T("" if s is None else str(s))
    if not UNICODE:
        for a, b in SAFE.items():
            s = s.replace(a, b)
    return s


def P(text, style):
    return Paragraph(escape(clean(text)).replace("\n", "<br/>"), style)


def read_csv(path):
    if not path.exists():
        return None
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:   # una riga con più colonne dell'intestazione (virgola non tra virgolette) finisce sotto None: unirla all'ultima
        extra = r.pop(None, None)
        if extra:
            last = list(r.keys())[-1] if r else None
            if last:
                r[last] = ", ".join([r[last] or ""] + [x for x in extra if x])
    return [r for r in rows if not (next(iter(r.values()), "") or "").strip().upper().startswith("ESEMPIO")]


def shield(c, cx, cy, s, fill, stroke, width=5):
    """Scudo con spunta, stesso disegno del banner dei repository."""
    def pt(x, y):
        return cx + x * s, cy - y * s
    c.saveState()
    p = c.beginPath()
    p.moveTo(*pt(0, -60)); p.lineTo(*pt(52, -38)); p.lineTo(*pt(52, 8))
    p.curveTo(*pt(52, 38), *pt(26, 56), *pt(0, 68)); p.curveTo(*pt(-26, 56), *pt(-52, 38), *pt(-52, 8))
    p.lineTo(*pt(-52, -38)); p.close()
    c.setFillColor(fill); c.setStrokeColor(stroke); c.setLineWidth(width * s); c.setLineJoin(1)
    c.drawPath(p, stroke=1, fill=1)
    k = c.beginPath(); k.moveTo(*pt(-22, 6)); k.lineTo(*pt(-6, 22)); k.lineTo(*pt(26, -16))
    c.setStrokeColor(stroke); c.setLineWidth(9 * s); c.setLineCap(1); c.setLineJoin(1)
    c.drawPath(k, stroke=1, fill=0)
    c.restoreState()


class Pill(Flowable):
    """Etichetta arrotondata (severità, stato)."""
    def __init__(self, text, bg, fg=colors.white, size=7, pad=2.6 * mm, h=4.6 * mm, maxw=None):
        super().__init__()
        self.text, self.bg, self.fg, self.size, self.pad, self.h = clean(text).upper(), bg, fg, size, pad, h
        self.w = pdfmetrics.stringWidth(self.text, BOLD, size) + 2 * pad
        if maxw and self.w > maxw:  # si restringe per stare nella cella
            self.size = size * (maxw - 2 * pad * 0.6) / (self.w - 2 * pad * 0.6)
            self.pad = pad * 0.6
            self.w = maxw

    def wrap(self, aw, ah):
        return self.w, self.h

    def draw(self):
        c = self.canv
        c.setFillColor(self.bg); c.roundRect(0, 0, self.w, self.h, self.h / 2, stroke=0, fill=1)
        c.setFillColor(self.fg); c.setFont(BOLD, self.size)
        c.drawCentredString(self.w / 2, self.h / 2 - self.size * 0.35, self.text)


class SectionHead(Flowable):
    """Titolo di sezione con numero in riquadro colore accento e filetto."""
    n = 0

    def __init__(self, text, accent, number=True):
        super().__init__()
        self.text, self.accent = clean(text), accent
        if number:
            SectionHead.n += 1
            self.num = SectionHead.n
        else:
            self.num = None
        self.height = 14 * mm

    def wrap(self, aw, ah):
        return CW, self.height

    def draw(self):
        c, x = self.canv, 0
        if self.num:
            c.setFillColor(self.accent); c.roundRect(0, 3 * mm, 9 * mm, 9 * mm, 2 * mm, stroke=0, fill=1)
            c.setFillColor(NAVY); c.setFont(BOLD, 11); c.drawCentredString(4.5 * mm, 5.9 * mm, str(self.num))
            x = 13 * mm
        c.setFillColor(NAVY); c.setFont(BOLD, 17); c.drawString(x, 5 * mm, self.text)
        c.setStrokeColor(LIGHT); c.setLineWidth(0.8); c.line(0, 0.6 * mm, CW, 0.6 * mm)
        c.setStrokeColor(self.accent); c.setLineWidth(2); c.line(0, 0.6 * mm, 22 * mm, 0.6 * mm)


class Callout(Flowable):
    """Riquadro evidenziato con barra laterale colorata."""
    def __init__(self, title, lines, accent, style, tstyle):
        super().__init__()
        self.accent = accent
        self.inner = [Paragraph(escape(clean(title)).upper(), tstyle)] + [Paragraph(l, style) for l in lines]

    def wrap(self, aw, ah):
        self.w = CW
        self.hs = [p.wrap(CW - 14 * mm, ah)[1] for p in self.inner]
        self.height = sum(self.hs) + 9 * mm + 1.2 * mm * len(self.hs)
        return self.w, self.height

    def draw(self):
        c = self.canv
        c.setFillColor(MIST); c.setStrokeColor(LIGHT); c.setLineWidth(0.6)
        c.roundRect(0, 0, self.w, self.height, 2 * mm, stroke=1, fill=1)
        c.setFillColor(self.accent); c.roundRect(0, 0, 2.2 * mm, self.height, 1.1 * mm, stroke=0, fill=1)
        y = self.height - 4.5 * mm
        for p, h in zip(self.inner, self.hs):
            p.drawOn(c, 7 * mm, y - h); y -= h + 1.2 * mm


class SevChart(Flowable):
    """Ciambella con la distribuzione dei finding per severità, più legenda."""
    def __init__(self, counts, total):
        super().__init__()
        self.counts, self.total = counts, total

    def wrap(self, aw, ah):
        return CW, 40 * mm

    def draw(self):
        c = self.canv
        cx, cy, r = 20 * mm, 20 * mm, 17 * mm
        ang = 90.0
        for k in SEV:
            n = self.counts.get(k, 0)
            if not n:
                continue
            ext = -360.0 * n / self.total
            c.setFillColor(SEV[k]); c.setStrokeColor(colors.white); c.setLineWidth(1.4)
            c.wedge(cx - r, cy - r, cx + r, cy + r, ang, ext, stroke=1, fill=1)
            ang += ext
        c.setFillColor(colors.white); c.circle(cx, cy, r * 0.62, stroke=0, fill=1)
        c.setFillColor(NAVY); c.setFont(BOLD, 18); c.drawCentredString(cx, cy - 1 * mm, str(self.total))
        c.setFillColor(SLATE); c.setFont(BASE, 6.5); c.drawCentredString(cx, cy - 5.2 * mm, clean("FINDING"))
        x0, w = 50 * mm, 24 * mm
        for i, k in enumerate(SEV):
            col, row = i % 3 if False else 0, i
            y = 33 * mm - i * 6.6 * mm
            n = self.counts.get(k, 0)
            c.setFillColor(SEV[k]); c.roundRect(x0, y - 1 * mm, 4 * mm, 4 * mm, 1 * mm, stroke=0, fill=1)
            c.setFillColor(NAVY2); c.setFont(BASE, 9); c.drawString(x0 + 7 * mm, y, clean(k.capitalize()))
            c.setFont(BOLD, 9); c.drawString(x0 + 38 * mm, y, str(n))
            c.setFillColor(LIGHT); c.roundRect(x0 + 48 * mm, y - 0.2 * mm, 62 * mm, 2.4 * mm, 1.2 * mm, stroke=0, fill=1)
            if n:
                c.setFillColor(SEV[k]); c.roundRect(x0 + 48 * mm, y - 0.2 * mm, max(2.4 * mm, 62 * mm * n / self.total), 2.4 * mm, 1.2 * mm, stroke=0, fill=1)


class StatCards(Flowable):
    """Riquadri numerici (denominatori reali) con barra di avanzamento."""
    def __init__(self, items):
        super().__init__()
        self.items = items

    def wrap(self, aw, ah):
        return CW, 27 * mm

    def draw(self):
        c = self.canv
        n = len(self.items)
        gap = 4 * mm
        w = (CW - gap * (n - 1)) / n
        for i, (label, val, tot, col) in enumerate(self.items):
            x = i * (w + gap)
            c.setFillColor(colors.white); c.setStrokeColor(LIGHT); c.setLineWidth(0.7)
            c.roundRect(x, 0, w, 25 * mm, 2.5 * mm, stroke=1, fill=1)
            c.setFillColor(col); c.roundRect(x, 22.4 * mm, w, 2.6 * mm, 1.2 * mm, stroke=0, fill=1)
            c.setFillColor(NAVY); c.setFont(BOLD, 21); c.drawString(x + 4 * mm, 12.5 * mm, str(val))
            c.setFillColor(SLATE); c.setFont(BASE, 9); c.drawString(x + 4 * mm + pdfmetrics.stringWidth(str(val), BOLD, 21) + 1.5 * mm, 12.5 * mm, f"{T('su')} {tot}")
            c.setFont(BASE, 7.2); c.drawString(x + 4 * mm, 6.8 * mm, clean(label)[:44])
            c.setFillColor(LIGHT); c.roundRect(x + 4 * mm, 2.6 * mm, w - 8 * mm, 1.8 * mm, 0.9 * mm, stroke=0, fill=1)
            if tot and val:
                c.setFillColor(col); c.roundRect(x + 4 * mm, 2.6 * mm, max(1.8 * mm, (w - 8 * mm) * val / tot), 1.8 * mm, 0.9 * mm, stroke=0, fill=1)


class Numbered(rl_canvas.Canvas):
    """Canvas a due passate: permette «Pagina X di Y»."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for st in self._saved:
            self.__dict__.update(st)
            if self._pageNumber > 1:
                self.setFont(BASE, 7.5); self.setFillColor(SLATE)
                self.drawRightString(PAGE_W - LM, 9.5 * mm, (f"Page {self._pageNumber - 1} of {total - 1}" if LANG == "en" else f"Pagina {self._pageNumber - 1} di {total - 1}"))
            super().showPage()
        super().save()


class Doc(BaseDocTemplate):
    def afterFlowable(self, fl):
        if isinstance(fl, SectionHead) and fl.num:
            self.notify("TOCEntry", (0, fl.text, self.page - 1))


def build(audit: Path, out: Path, meta_path: Path, lang="it", short=False, previous=None, nis2=False):
    global LANG
    LANG = lang
    setup_fonts()
    SectionHead.n = 0
    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    fpath = audit / "findings" / "findings.json"
    findings = json.loads(fpath.read_text(encoding="utf-8")) if fpath.exists() else []
    findings.sort(key=lambda f: (ORDER.get(f.get("severita"), 9), f.get("id", "")))
    doc_m = read_csv(audit / "documentary-matrix.csv")
    cov = read_csv(audit / "coverage-matrix.csv")
    ep = read_csv(audit / "endpoint-matrix.csv")
    gdpr = read_csv(audit / "gdpr-matrix.csv")
    pmap = read_csv(audit / "processing-map.csv")
    gaps = [r for r in (read_csv(audit / "gaps.csv") or []) if (r.get("id") or "").strip() and not r["id"].startswith("ESEMPIO")]
    gaps.sort(key=lambda r: ({"alta": 0, "media": 1, "bassa": 2}.get((r.get("priorita") or "").strip().lower(), 9), r.get("id", "")))
    uj = audit / "unione-giri.json"
    unione = json.loads(uj.read_text(encoding="utf-8")) if uj.exists() else None

    title = meta.get("titolo", "Report di audit")
    classif = meta.get("classificazione", "RISERVATO")
    when = meta.get("data", date.today().isoformat())
    # Tema: teal = sicurezza, ambra = privacy (stessi colori dei repository)
    privacy_only = (bool(gdpr) or bool(gaps)) and not findings
    tema = meta.get("tema") or ("privacy" if privacy_only else "sicurezza")
    ACC, ACC_D, ACC_L = (AMBER, AMBER_D, AMBER_L) if tema == "privacy" else (TEAL, TEAL_D, TEAL_L)
    SEC, PRIV = TEAL, AMBER
    if findings and gdpr:
        tools = "appsec-sentinel  ·  gdpr-sentinel"
    else:
        tools = "gdpr-sentinel" if privacy_only else "appsec-sentinel"

    h2 = ParagraphStyle("h2", fontName=BOLD, fontSize=11.5, leading=15, textColor=NAVY, spaceBefore=12, spaceAfter=5)
    body = ParagraphStyle("b", fontName=BASE, fontSize=9.2, leading=13.4, textColor=NAVY2, alignment=TA_LEFT)
    lead = ParagraphStyle("lead", parent=body, fontSize=10, leading=14.5, textColor=SLATE, spaceAfter=4)
    small = ParagraphStyle("s", parent=body, fontSize=8, leading=10.8, textColor=SLATE)
    cell = ParagraphStyle("c", parent=body, fontSize=8.3, leading=10.8)
    cellb = ParagraphStyle("cb", parent=cell, fontName=BOLD)
    lab = ParagraphStyle("lab", parent=cell, fontName=BOLD, fontSize=7, leading=9.5, textColor=SLATE)
    white = ParagraphStyle("w", parent=cell, textColor=colors.white, fontName=BOLD)
    whiteh = ParagraphStyle("wh", parent=white, fontSize=7.6, leading=10)
    callt = ParagraphStyle("ct", parent=cell, fontName=BOLD, fontSize=7.4, textColor=ACC_D, leading=10)
    bullet = ParagraphStyle("bl", parent=body, leftIndent=12, bulletIndent=1, spaceAfter=2.5, bulletColor=ACC)
    tocs = [ParagraphStyle("toc0", fontName=BASE, fontSize=10.5, leading=22, textColor=NAVY, leftIndent=0, rightIndent=0)]

    def bl(text):
        return Paragraph(escape(clean(text)), bullet, bulletText="\u25A0" if UNICODE else "-")

    def header_footer(canv, d):
        canv.saveState()
        canv.setFillColor(NAVY); canv.rect(0, PAGE_H - 7 * mm, PAGE_W, 7 * mm, stroke=0, fill=1)
        canv.setFillColor(ACC); canv.rect(0, PAGE_H - 7 * mm, 38 * mm, 1.1 * mm, stroke=0, fill=1)
        shield(canv, LM + 2 * mm, PAGE_H - 3.5 * mm, 0.036, NAVY, ACC_L, width=7)
        canv.setFont(BOLD, 7); canv.setFillColor(colors.white); canv.drawString(LM + 7 * mm, PAGE_H - 4.4 * mm, tools.upper())
        canv.setFont(BASE, 7); canv.setFillColor(LIGHT); canv.drawRightString(PAGE_W - LM, PAGE_H - 4.4 * mm, clean(classif).upper())
        canv.setFont(BASE, 7.8); canv.setFillColor(SLATE); canv.drawString(LM, PAGE_H - 14 * mm, clean(title))
        canv.setStrokeColor(LIGHT); canv.setLineWidth(0.6); canv.line(LM, 14 * mm, PAGE_W - LM, 14 * mm)
        canv.setFillColor(ACC); canv.rect(LM, 14 * mm - 0.3 * mm, 12 * mm, 0.9 * mm, stroke=0, fill=1)
        canv.setFont(BASE, 7.5); canv.setFillColor(SLATE)
        canv.drawString(LM, 9.5 * mm, clean(meta.get("autore", "")))
        canv.restoreState()

    def cover(canv, d):
        canv.saveState()
        p = canv.beginPath(); p.rect(0, 0, PAGE_W, PAGE_H); canv.clipPath(p, stroke=0, fill=0)
        canv.linearGradient(0, PAGE_H, PAGE_W, 0, (NAVY, NAVY2, ACC_D if tema == "privacy" else TEAL_D), (0, 0.6, 1))
        canv.setFillColor(colors.white); canv.setFillAlpha(0.07)
        for gx in range(0, 220, 9):
            for gy in range(0, 300, 9):
                canv.circle(gx * mm + 1 * mm, gy * mm + 1 * mm, 0.28 * mm, stroke=0, fill=1)
        canv.setFillColor(ACC)
        canv.setFillAlpha(0.10); canv.circle(158 * mm, 214 * mm, 58 * mm, stroke=0, fill=1)
        canv.setFillAlpha(0.14); canv.circle(158 * mm, 214 * mm, 43 * mm, stroke=0, fill=1)
        canv.setFillAlpha(1)
        shield(canv, 158 * mm, 214 * mm, 0.70, NAVY, ACC_L, width=5)
        canv.setFillColor(ACC); canv.rect(0, 0, 4 * mm, PAGE_H, stroke=0, fill=1)
        canv.setFont(BOLD, 8.5); canv.setFillColor(ACC_L)
        canv.drawString(20 * mm, 268 * mm, tools.upper())
        canv.setFont(BASE, 8.5); canv.setFillColor(H("#94a3b8")); canv.drawRightString(190 * mm, 268 * mm, clean(classif).upper())
        canv.setStrokeColor(colors.white); canv.setStrokeAlpha(0.15); canv.setLineWidth(0.5); canv.line(20 * mm, 264 * mm, 190 * mm, 264 * mm)
        canv.setStrokeAlpha(1)
        canv.setFillColor(ACC); canv.roundRect(20 * mm, 148 * mm, 24 * mm, 1.8 * mm, 0.9 * mm, stroke=0, fill=1)
        canv.setFillColor(ACC_L); canv.setFont(BOLD, 10)
        canv.drawString(20 * mm, 154 * mm, clean(meta.get("tipo", "REPORT DI AUDIT")).upper())
        canv.setFillColor(colors.white); canv.setFont(BOLD, 30)
        y = 134 * mm
        line = ""
        for w in clean(title).split():
            if canv.stringWidth(line + " " + w, BOLD, 30) > 165 * mm:
                canv.drawString(20 * mm, y, line.strip()); y -= 12.5 * mm; line = w
            else:
                line += " " + w
        canv.drawString(20 * mm, y, line.strip())
        canv.setFont(BASE, 12.5); canv.setFillColor(LIGHT)
        canv.drawString(20 * mm, y - 12 * mm, clean(meta.get("sottotitolo", "")))
        labels = ("Riscontrato", "Ipotesi", "Non verificabile") if privacy_only else ("Esaminato", "Provato", "Ignoto")
        px = 20 * mm
        for lbl, col in zip(labels, (ACC, GREEN if not privacy_only else H("#38bdf8"), AMBER if not privacy_only else H("#94a3b8"))):
            wpill = canv.stringWidth(lbl, BOLD, 8.5) + 9 * mm
            canv.setFillColor(col); canv.roundRect(px, y - 28 * mm, wpill, 6.6 * mm, 3.3 * mm, stroke=0, fill=1)
            canv.setFillColor(NAVY); canv.setFont(BOLD, 8.5); canv.drawCentredString(px + wpill / 2, y - 25.7 * mm, lbl)
            px += wpill + 3 * mm
        rows = [("Oggetto", meta.get("oggetto", "")), ("Versione esaminata", meta.get("versione", "")), ("Modalità", meta.get("modalita", "")),
                ("Data", when), ("Preparato da", meta.get("autore", "")), ("Classificazione", classif)]
        rows = [(k, v) for k, v in rows if v]
        ph = 8 * mm * len(rows) + 8 * mm
        canv.setFillColor(colors.white); canv.setFillAlpha(0.06); canv.roundRect(20 * mm, 24 * mm, 170 * mm, ph, 3 * mm, stroke=0, fill=1)
        canv.setFillAlpha(1)
        yy = 24 * mm + ph - 9 * mm
        for i, (k, v) in enumerate(rows):
            canv.setFont(BASE, 7.5); canv.setFillColor(ACC_L); canv.drawString(26 * mm, yy, clean(k).upper())
            fs = 10.5
            while canv.stringWidth(clean(v), BASE, fs) > 116 * mm and fs > 7:
                fs -= 0.5
            canv.setFont(BASE, fs); canv.setFillColor(colors.white); canv.drawString(68 * mm, yy, clean(v))
            if i < len(rows) - 1:
                canv.setStrokeColor(colors.white); canv.setStrokeAlpha(0.10); canv.setLineWidth(0.4); canv.line(26 * mm, yy - 3.2 * mm, 184 * mm, yy - 3.2 * mm); canv.setStrokeAlpha(1)
            yy -= 8 * mm
        canv.setFont(BASE, 7.2); canv.setFillColor(H("#94a3b8"))
        canv.drawString(20 * mm, 16 * mm, clean(meta.get("avvertenza_copertina", "Documento riservato. Non costituisce certificazione né parere legale."))[:150])
        canv.restoreState()

    docp = Doc(str(out), pagesize=A4, title=clean(title), author=clean(meta.get("autore", "")),
               leftMargin=LM, rightMargin=LM, topMargin=24 * mm, bottomMargin=20 * mm)
    frame = Frame(LM, 20 * mm, CW, 251 * mm, id="f", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)
    docp.addPageTemplates([PageTemplate(id="cover", frames=[Frame(0, 0, 20, 20, id="x", leftPadding=0, rightPadding=0, topPadding=0, bottomPadding=0)], onPage=cover, autoNextPageTemplate="body"),
                           PageTemplate(id="body", frames=[frame], onPage=header_footer)])
    S = [Spacer(1, 1), PageBreak()]  # la copertina è disegnata da onPage

    def table(data, widths, head=True, zebra=True, extra=None, accent=None):
        t = Table(data, colWidths=widths, repeatRows=1 if head else 0)
        st = [("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6),
              ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
              ("LINEBELOW", (0, 0), (-1, -1), 0.4, LIGHT)]
        if head:
            st += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("LINEBELOW", (0, 0), (-1, 0), 1.6, accent or ACC),
                   ("ROUNDEDCORNERS", [3, 3, 0, 0])]
        if zebra:
            st += [("ROWBACKGROUNDS", (0, 1 if head else 0), (-1, -1), [colors.white, MIST])]
        t.setStyle(TableStyle(st + (extra or [])))
        return t

    def hd(*names):
        return [P(T(n).upper(), whiteh) for n in names]

    def sev_pill(k):
        return Pill(k, SEV.get(k, SLATE))

    # Indice
    if not short:
        toc = TableOfContents(); toc.levelStyles = tocs
        toc.dotsMinLevel = 0
        S += [SectionHead("Indice", ACC, number=False), Spacer(1, 6), toc, PageBreak()]

    # Sintesi
    S.append(SectionHead("Sintesi per il proprietario", ACC))
    if meta.get("sintesi"):
        S.append(Spacer(1, 4))
    for line in meta.get("sintesi", []):
        S.append(bl(line))
    if findings:
        cnt = Counter(f["severita"] for f in findings)
        S += [Spacer(1, 8), SevChart(cnt, len(findings)), Spacer(1, 2),
              P((f"{len(findings)} findings in total. Status: " if LANG == "en" else f"{len(findings)} finding in totale. Stato: ") + ", ".join(f"{n} {s}" for s, n in Counter(V(f['stato']) for f in findings).items()) + ".", small), Spacer(1, 8)]
        first = [x for x in findings if x["severita"] in ("critica", "alta")][:4] or findings[:3]
        S.append(Callout("Da fare per primo", [f"<b>{escape(f['id'])}</b> · {escape(clean(f['titolo']))}. <i>{escape(clean(f['intervento'].get('mitigazione_temporanea', '')))}</i>" for f in first], ACC, cell, callt))

    # Quadro e dettaglio finding
    if findings:
        S += [PageBreak(), SectionHead("Quadro dei finding", SEC), Spacer(1, 6)]
        data = [hd("ID", "Severità", "Titolo", "Stato")]
        for f in findings:
            data.append([P(f["id"], cellb), sev_pill(f["severita"]), P(f["titolo"], cell), P(V(f["stato"]), cell)])
        S.append(table(data, [21 * mm, 25 * mm, 81 * mm, 43 * mm], accent=SEC))
        S += [Spacer(1, 5), P("Gli stati dichiarati sono quelli effettivamente raggiunti: «confermato da codice o configurazione» non equivale a «riprodotto dinamicamente».", small)]
        if previous and Path(previous).exists():
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            try:
                from compare_audits import compare
                cmp = compare(json.loads(Path(previous).read_text(encoding="utf-8")), findings)
                S += [PageBreak(), SectionHead("Confronto con l'audit precedente", SEC),
                      StatCards([(T("Risolti"), len(cmp["risolti"]), len(cmp["risolti"]) + len(cmp["invariati"]) + len(cmp["cambiati"]), GREEN),
                                 (T("Nuovi"), len(cmp["nuovi"]), len(findings), SEV["alta"]),
                                 (T("Cambiati"), len(cmp["cambiati"]), len(findings), H("#38bdf8"))]), Spacer(1, 8)]
                data = [hd("ID", "Stato", "Titolo", "Note")]
                for key, lab_, col in (("risolti", "Risolti", GREEN), ("nuovi", "Nuovi", SEV["alta"]), ("cambiati", "Cambiati", H("#0ea5e9")), ("invariati", "Ancora aperti", SLATE)):
                    for f in cmp[key]:
                        data.append([P(f["id"], cellb), Pill(T(lab_), col, maxw=25 * mm), P(f["titolo"], cell), P("; ".join(f.get("cambi", [])), cell)])
                S += [table(data, [20 * mm, 27 * mm, 85 * mm, 38 * mm], accent=SEC), Spacer(1, 4),
                      P("«Risolto» significa assente nel nuovo audit, non verificato: vale l'esito del retest indicato nel finding.", small)]
            except ImportError:
                pass

        if not short:
            S += [PageBreak(), SectionHead("Dettaglio dei finding", SEC), Spacer(1, 6)]
        for f in ([] if short else findings):
            col = SEV[f["severita"]]
            head = Table([[P(f["id"], white), P(f["titolo"], ParagraphStyle("ht", parent=white, fontSize=9.2, leading=12)), sev_pill(f["severita"])]],
                         colWidths=[20 * mm, 122 * mm, 28 * mm])
            head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("LINEBEFORE", (0, 0), (0, 0), 4, col),
                                      ("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
                                      ("LEFTPADDING", (0, 0), (0, 0), 10), ("ROUNDEDCORNERS", [3, 3, 0, 0])]))
            imp, itv = f.get("impatto", {}), f.get("intervento", {})
            rows = [("Stato e confidenza", f"{V(f['stato'])} · {T('confidenza')} {V(f['confidenza'])}"),
                    ("Prova", f["prova"]["descrizione"]),
                    ("File", ", ".join(f["prova"].get("riferimenti_file", []))),
                    ("Atteso / osservato", f"{T('Atteso:')} {f['atteso']}\n{T('Osservato:')} {f['osservato']}"),
                    ("Impatto", f"{T('Reale:')} {imp.get('reale', '')}\n{T('Potenziale:')} {imp.get('potenziale', '')}\n{T('Condizioni:')} {imp.get('condizioni_limitanti', '')}"),
                    ("Perché questa severità", f["motivazione_severita"]),
                    ("Correzione", itv.get("correzione", "")), ("Subito", itv.get("mitigazione_temporanea", "")),
                    ("Retest", f["retest"]), ("Limiti", f["limiti"])]
            sm = f.get("smentita")
            if sm:
                rows.append(("Smentita", f"{sm['esito']} · {sm['verificatore']}. " + "; ".join(sm.get("tentativi", []))))
            if f.get("cwe"):
                rows.insert(1, ("Riferimenti", ", ".join(f["cwe"]) + ("  ·  " + "; ".join(f.get("riferimenti_standard", [])) if f.get("riferimenti_standard") else "")))
            body_t = Table([[P(T(k).upper(), lab), P(v, cell)] for k, v in rows if v], colWidths=[34 * mm, 136 * mm])
            body_t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LIGHT), ("BACKGROUND", (0, 0), (0, -1), MIST),
                                        ("LINEBEFORE", (0, 0), (0, -1), 4, col), ("BOX", (0, 0), (-1, -1), 0.6, LIGHT),
                                        ("LEFTPADDING", (0, 0), (0, -1), 10), ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
            head.keepWithNext = True
            S += [head, body_t, Spacer(1, 11)]

    # Audit documentale
    if doc_m and not short:
        S += [PageBreak(), SectionHead("Audit documentale", SEC),
              P("Confronto tra ciò che i documenti affermano e ciò che risulta da codice e configurazione, più completezza e aggiornamento dei documenti.", lead), Spacer(1, 4)]
        cs = Counter(r["stato"] for r in doc_m)
        S.append(P(("Outcome: " if LANG == "en" else "Esito: ") + ", ".join(f"{n} {s}" for s, n in cs.most_common()) + (f" of {len(doc_m)} items reviewed." if LANG == "en" else f" su {len(doc_m)} voci esaminate."), small))
        S.append(Spacer(1, 5))
        colmap = {"incoerente": SEV["alta"], "duplicato": SEV["media"], "obsoleto": SEV["media"], "mancante": SEV["media"], "non verificabile": SEV["informativa"], "coerente": GREEN}
        data = [hd("ID", "Documento", "Stato", "Rilievo e azione")]
        for r in doc_m:
            data.append([P(r["id"], cellb), P(r["documento"] + (f" ({r['data_o_versione']})" if r.get("data_o_versione") not in ("", "—", None) else ""), cell),
                         Pill(r["stato"], colmap.get(r["stato"], SLATE), maxw=25 * mm), P(f"{r['rilievo']}. Azione: {r['azione_proposta']}", cell)])
        S.append(table(data, [13 * mm, 50 * mm, 27 * mm, 80 * mm], accent=SEC))

    # Privacy
    if gdpr:
        S += [PageBreak(), SectionHead("Valutazione privacy (GDPR/ePrivacy)", PRIV),
              P("Analisi tecnica e documentale: non è un parere legale e non esprime giudizi di conformità. Le decisioni spettano a titolare, DPO e legale.", lead), Spacer(1, 4)]
        pcol = {"riscontrato": SEV["alta"], "ipotesi": SEV["media"], "non verificabile": SEV["informativa"], "confermato da codice o configurazione": H("#0369a1")}
        data = [hd("Ctrl", "Area", "Stato", "Gap")]
        for r in gdpr:
            data.append([P(r["controllo"], cellb), P(r["area"], cell), P(r["stato"], ParagraphStyle("st", parent=cell, fontName=BOLD, textColor=pcol.get(r["stato"].strip().lower(), NAVY2))), P(r.get("gap", ""), cell)])
        S.append(table(data, [12 * mm, 45 * mm, 35 * mm, 78 * mm], accent=PRIV))
        if pmap:
            S += [P("Mappa dei trattamenti", h2)]
            data = [hd("ID", "Trattamento", "Dati e interessati", "Gap")]
            for r in pmap:
                data.append([P(r["id"], cellb), P(r["trattamento"], cell), P(r["dati_e_interessati"], cell), P(r["gap"], cell)])
            S.append(table(data, [12 * mm, 40 * mm, 55 * mm, 63 * mm], accent=PRIV))

    # Domande con destinatario
    if meta.get("domande"):
        S += [PageBreak(), SectionHead("Domande per titolare, DPO, legale e fornitori", PRIV),
              P("Ogni punto non verificabile o incoerente ha la sua domanda, con il destinatario e il materiale necessario.", lead), Spacer(1, 4)]
        data = [hd("ID", "Destinatario", "Domanda")]
        for q in meta["domande"]:
            data.append([P(q.get("id", ""), cellb), P(q.get("destinatario", ""), cell), P(q.get("domanda", ""), cell)])
        S.append(table(data, [14 * mm, 34 * mm, 122 * mm], accent=PRIV))

    # Gap privacy strutturati (gaps.csv)
    if gaps:
        S += [PageBreak(), SectionHead("Gap privacy", PRIV),
              P("Un gap per riga, con il punto del codice o del documento da cui emerge. La priorità riflette il rischio per gli interessati, non un giudizio di conformità.", lead), Spacer(1, 4)]
        pc = {"alta": SEV["alta"], "media": SEV["media"], "bassa": SEV["bassa"]}
        data = [hd("ID", "Ctrl", "Priorità", "Gap e riferimenti")]
        for r in gaps:
            pr = (r.get("priorita") or "").strip().lower()
            txt = f"<b>{escape(clean(r.get('titolo', '')))}</b><br/>{escape(clean(r.get('riferimenti', '')))}"
            if (r.get("norma") or "").strip():
                txt += f"<br/><i>{escape(clean(r['norma']))}</i>"
            data.append([P(r["id"], cellb), P(r.get("controllo", ""), cell), Pill(T(pr or "?"), pc.get(pr, SLATE), maxw=22 * mm), Paragraph(txt, cell)])
        S.append(table(data, [23 * mm, 11 * mm, 22 * mm, 114 * mm], accent=PRIV))

    # Due giri indipendenti (comando doppio / unisci)
    if unione and unione.get("gruppi"):
        giri = unione.get("giri", [])
        S += [PageBreak(), SectionHead("Due giri indipendenti", ACC),
              P("La valutazione è stata eseguita due volte, da due analisi indipendenti che non hanno visto il lavoro l'una dell'altra, e i risultati sono stati uniti per causa. "
                "Una causa vista da un solo giro non è meno vera: è stata cercata da un giro solo. L'accordo dice quanto i due giri si somigliano, non che l'elenco sia completo.", lead), Spacer(1, 6),
              StatCards([(T("Cause distinte"), unione["cause_distinte"], unione["cause_distinte"], ACC),
                         (T("Viste da entrambi"), unione["viste_da_tutti"], unione["cause_distinte"], GREEN),
                         (T("Viste da un solo giro"), unione["cause_distinte"] - unione["viste_da_tutti"], unione["cause_distinte"], SEV["media"])]), Spacer(1, 8)]
        data = [hd("ID", "Titolo", "Visto da", "Severità")]
        for g in unione["gruppi"]:
            who = T("entrambi") if len(g.get("giri", [])) == len(giri) else ", ".join(g.get("giri", []))
            sv = " / ".join(T(s) for s in g.get("severita", []))
            data.append([P(g["id"].replace("UNI-", "GDPR-") if privacy_only else g["id"], cellb), P(g["titolo"], cell), P(who, cell),
                         P(sv + (" ⚠" if len(g.get("severita", [])) > 1 and UNICODE else (" (!)" if len(g.get("severita", [])) > 1 else "")), cell)])
        S.append(table(data, [23 * mm, 93 * mm, 26 * mm, 28 * mm], accent=ACC))
        S += [Spacer(1, 4), P("Severità con due valori: i giri le hanno valutate in modo diverso; nel report vale la più alta finché non viene decisa a mano.", small)]
        if unione.get("possibili_stessa_causa"):
            S += [Spacer(1, 3), P(f"Coppie «possibile stessa causa» lasciate separate e da decidere a mano: {len(unione['possibili_stessa_causa'])}.", small)]

    # Threat model e test dinamici (standard e completo): due giri reali avevano entrambi i file ma il PDF non li mostrava
    tm = audit / "report" / "threat-model.md"
    if tm.exists() and tm.stat().st_size > 200 and not short:
        S += [PageBreak(), SectionHead("Threat model", ACC),
              P("Flussi, confini di fiducia e percorsi di attacco considerati (da report/threat-model.md). È la mappa che ha guidato l'esame, non un elenco di vulnerabilità.", lead), Spacer(1, 4)]
        righe, intab = tm.read_text(encoding="utf-8", errors="replace").splitlines(), []
        for line in righe[:160]:
            t = line.strip()
            if not t or t.startswith("```") or set(t) <= set("|-: "):
                continue
            if t.startswith("|"):
                cells = [c.strip() for c in t.strip("|").split("|")]
                S.append(bl(" · ".join(c for c in cells if c)))
            elif t.startswith("#"):
                S.append(P(t.lstrip("#").strip(), h2))
            elif t[:2] in ("- ", "* ") or re.match(r"\d+[.)] ", t):
                S.append(bl(re.sub(r"^(?:[-*]|\d+[.)])\s+", "", t).replace("**", "").replace("`", "")))
            else:
                S.append(P(t.replace("**", "").replace("`", ""), body))
        if len(righe) > 160:
            S.append(P("Il threat model continua nel file report/threat-model.md.", small))
    done = [r for r in ep if (r.get("test_eseguito") or "").strip().lower() in {"si", "sì", "yes"}] if ep else []
    if done and not short:
        S += [PageBreak(), SectionHead("Test dinamici eseguiti", ACC),
              P("Le prove fatte davvero sull'istanza autorizzata, come registrate nella matrice degli endpoint: identità usata, esito osservato e finding collegato. Un endpoint che non compare qui non è stato provato.", lead), Spacer(1, 4)]
        data = [hd("Endpoint", "Metodo", "Identità e ruolo", "Controllo atteso", "Esito", "Finding")]
        for r in done:
            data.append([P(r["endpoint"], cellb), P(r.get("metodo", ""), cell), P(f"{r.get('identita', '')} / {r.get('ruolo', '')}", cell),
                         P(r.get("controllo_atteso", ""), cell), P(r.get("esito", ""), cell), P(r.get("finding_id", ""), cell)])
        S.append(table(data, [38 * mm, 18 * mm, 28 * mm, 25 * mm, 43 * mm, 18 * mm]))

    # Copertura
    S += [PageBreak(), SectionHead("Copertura e limiti", ACC),
          P("La copertura riguarda solo ciò che è stato inventariato: non prova l'assenza di problemi non censiti.", lead), Spacer(1, 6)]
    cards = []
    if cov:
        yes = lambda v: (v or "").strip().lower() in {"si", "sì", "yes"}
        part = lambda v: (v or "").strip().lower() in {"parziale", "partial"}
        cards += [("Voci inventariate esaminate per intero", sum(yes(r["esaminato"]) for r in cov), len(cov), ACC),
                  ("Voci esaminate in parte", sum(part(r["esaminato"]) for r in cov), len(cov), H("#38bdf8"))]
    if ep:
        eps = {(r["endpoint"], r["metodo"]) for r in ep}
        tested = {(r["endpoint"], r["metodo"]) for r in ep if (r.get("test_eseguito") or "").strip().lower() in {"si", "sì", "yes"}}
        cards.append(("Endpoint con almeno un test eseguito", len(tested), len(eps), H("#a78bfa")))
    if cards:
        S += [StatCards(cards), Spacer(1, 8)]
    for line in meta.get("note_copertura", []):
        S.append(bl(line))
    if meta.get("non_verificato"):
        S.append(P("Non verificato", h2))
        for line in meta["non_verificato"]:
            S.append(bl(line))
    if meta.get("domande_aperte"):
        S.append(P("Domande aperte per il proprietario", h2))
        for line in meta["domande_aperte"]:
            S.append(bl(line))

    # Matrici (tabelle complete, non solo i conteggi)
    ctl = read_csv(audit / "controls-matrix.csv")
    ctl = [r for r in (ctl or []) if not any((v or "").strip().lower().startswith("esempio") for v in r.values())]
    if (cov or ep or ctl) and not short:
        S += [PageBreak(), SectionHead("Matrici di copertura", ACC),
              P("Il dettaglio da cui derivano i conteggi: cosa è stato esaminato, quali endpoint sono censiti e con quale test.", lead)]
        ok = lambda v: (v or "").strip().lower() in {"si", "sì", "yes"}
        def yn(v, tot=("si", "parziale", "no")):
            k = (v or "").strip().lower().replace("sì", "si")
            return Pill(k or "n/d", {"si": GREEN, "parziale": H("#0ea5e9"), "no": SLATE}.get(k, SLATE), maxw=15 * mm)
        if cov:
            S.append(P("Inventario e copertura", h2))
            data = [hd("Area o percorso", "Verifica", "Esaminato", "Note")]
            for r in cov:
                note = r.get("note", "") if ok(r["esaminato"]) else (r.get("motivo_esclusione", "") + (". " if r.get("motivo_esclusione") and r.get("note") else "") + r.get("note", ""))
                data.append([P(r["area_o_percorso"], cellb), P(r.get("modalita_verifica", ""), cell), yn(r["esaminato"]), P(note, cell)])
            S.append(table(data, [42 * mm, 34 * mm, 23 * mm, 71 * mm]))
        if ep:
            S.append(P("Endpoint censiti", h2))
            data = [hd("Endpoint", "Metodo", "Identità e ruolo", "Azione", "Test", "Finding")]
            for r in ep:
                data.append([P(r["endpoint"], cellb), P(r["metodo"], cell), P(f"{r.get('identita', '')} / {r.get('ruolo', '')}", cell),
                             P(f"{r.get('azione', '')} ({r.get('oggetto', '')})", cell), yn(r.get("test_eseguito", "no")), P(r.get("finding_id", ""), cell)])
            S.append(table(data, [46 * mm, 19 * mm, 29 * mm, 34 * mm, 19 * mm, 23 * mm]))
            S += [Spacer(1, 4), P("«Test: no» significa che l'endpoint è stato censito dal codice ma non provato. Gli stati dei finding collegati dicono cosa è dimostrato.", small)]
        if ctl:
            S.append(P("Controlli (ASVS, NIST, ACN)", h2))
            data = [hd("Fonte e sezione", "Requisito", "Applicabile", "Stato", "Gap o compensazione")]
            for r in ctl:
                data.append([P(f"{r['fonte']} {r['sezione']}", cellb), P(r["requisito"], cell), P(r["applicabile"], cell), P(r["stato"], cell), P(r.get("gap_o_compensazione", ""), cell)])
            S.append(table(data, [30 * mm, 50 * mm, 20 * mm, 26 * mm, 44 * mm]))

    # Mappatura NIS2 (indicativa)
    if nis2 and findings and not short:
        NIS = [("a", "Analisi dei rischi e politiche di sicurezza dei sistemi informatici", ("documentale", "configurazione", "infrastruttura")),
               ("b", "Gestione degli incidenti", ("log", "monitor", "incident")),
               ("c", "Continuità operativa, backup, ripristino", ("backup", "continuit", "ripristino", "porte")),
               ("d", "Sicurezza della catena di approvvigionamento", ("supply", "dipendenz", "componenti")),
               ("e", "Sicurezza di acquisizione, sviluppo e manutenzione, gestione delle vulnerabilità", ("componenti", "vulnerab", "codice", "input", "api", "obsolet", "configurazione")),
               ("g", "Igiene informatica di base e formazione", ("segreti", "obsolet", "configurazione", "predefinit")),
               ("h", "Crittografia e cifratura", ("crittograf", "cifr", "tls", "segreti")),
               ("i", "Controllo degli accessi, gestione degli attivi, sicurezza delle risorse umane", ("access", "autorizz", "segreti", "credenziali", "oggetto", "amministrativ")),
               ("j", "Autenticazione a più fattori e comunicazioni sicure", ("mfa", "autenticazione"))]
        S += [PageBreak(), SectionHead("Mappatura indicativa sulle misure NIS2 (art. 21)", ACC),
              P("Collegamento di massima tra i finding e le misure dell'art. 21, paragrafo 2, della direttiva NIS2. È una lettura tecnica per orientare il piano: non stabilisce se il soggetto rientra nell'ambito NIS2 né valuta la conformità. Verificare lettere e obblighi sul testo normativo e sulla baseline ACN applicabile.", lead), Spacer(1, 4)]
        data = [hd("Lettera", "Misura", "Finding collegati")]
        for letter, name, keys in NIS:
            linked = [f["id"] for f in findings if any(k in (f["categoria"] + " " + f["titolo"]).lower() for k in keys)]
            data.append([P(f"({letter})", cellb), P(name, cell), P(", ".join(linked) if linked else "nessun finding collegato (non significa misura adeguata)", cell)])
        S.append(table(data, [18 * mm, 90 * mm, 62 * mm]))

    # Piano
    if findings:
        S += [PageBreak(), SectionHead("Piano di intervento proposto", ACC)]
        fasi = [("Subito", ["critica", "alta"]), ("Prossime settimane", ["media"]), ("Pianificato", ["bassa", "informativa"])]
        for nome, sevs in fasi:
            fs = [f for f in findings if f["severita"] in sevs]
            if not fs:
                continue
            S.append(P(nome, h2))
            data = [hd("ID", "Intervento", "Responsabile proposto")]
            for f in fs:
                data.append([P(f["id"], cellb), P(f["intervento"].get("correzione", ""), cell), P(f["intervento"].get("responsabile_proposto", ""), cell)])
            S.append(table(data, [19 * mm, 118 * mm, 33 * mm]))
        S += [Spacer(1, 6), P("I tempi dipendono da impatto e obblighi del titolare; non sono scadenze di legge. Dopo ogni correzione va eseguito il retest indicato nel finding.", small)]

    if not findings and meta.get("piano"):
        S += [PageBreak(), SectionHead("Piano di intervento proposto", ACC), Spacer(1, 6)]
        data = [hd("Quando", "Azione", "Responsabile proposto")]
        for r in meta["piano"]:
            data.append([P(r.get("fase", ""), cellb), P(r.get("azione", ""), cell), P(r.get("responsabile", ""), cell)])
        S.append(table(data, [30 * mm, 100 * mm, 40 * mm]))
        S += [Spacer(1, 6), P("Le priorità derivano dal rischio per gli interessati, non da scadenze di legge.", small)]

    S += [Spacer(1, 10), Callout("Metodo e avvertenze", [escape(clean(
        "Valutazione eseguita con le skill appsec-sentinel e gdpr-sentinel (Apache-2.0). Ogni finding ha uno stato che dice cosa è stato dimostrato. "
        "Non è un penetration test completo, non certifica sicurezza o conformità e non sostituisce il parere di DPO e legale. Segreti e dati personali non sono riportati. "
        "Le fonti normative e gli standard vanno riverificati prima di citarli."))], ACC, small, callt)]
    docp.multiBuild(S, canvasmaker=Numbered)
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("audit", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--meta", type=Path)
    ap.add_argument("--sintetico", action="store_true")
    ap.add_argument("--lang", choices=("it", "en"), default="it")
    ap.add_argument("--previous", type=Path)
    ap.add_argument("--nis2", action="store_true")
    a = ap.parse_args()
    if not a.audit.is_dir():
        sys.exit(f"cartella non trovata: {a.audit}")
    out = a.out or a.audit / "report" / "report.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    build(a.audit, out, a.meta or a.audit / "meta.json", lang=a.lang, short=a.sintetico, previous=a.previous, nis2=a.nis2)
    print(f"creato: {out}")


if __name__ == "__main__":
    main()
