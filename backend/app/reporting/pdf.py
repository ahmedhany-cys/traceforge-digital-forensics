"""Render a report dictionary (see builder.py) to PDF with ReportLab.

All dynamic text is XML-escaped before being handed to ReportLab's Paragraph
mini-markup, so evidence content cannot inject markup into the document.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape  # nosec B406 - used for output escaping, not XML parsing

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether, PageBreak, Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle,
)

NAVY = colors.HexColor("#0f172a")
SLATE = colors.HexColor("#334155")
MUTED = colors.HexColor("#64748b")
LINE = colors.HexColor("#cbd5e1")
ACCENT = colors.HexColor("#0e7490")
SEV_COLORS = {"critical": "#b91c1c", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#64748b"}

_base = getSampleStyleSheet()
S = {
    "title": ParagraphStyle("t", parent=_base["Title"], fontName="Helvetica-Bold", fontSize=22, leading=27, textColor=NAVY, alignment=TA_LEFT),
    "subtitle": ParagraphStyle("st", parent=_base["Normal"], fontSize=12, leading=16, textColor=SLATE),
    "h1": ParagraphStyle("h1", parent=_base["Heading1"], fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=NAVY, spaceBefore=10, spaceAfter=6),
    "h2": ParagraphStyle("h2", parent=_base["Heading2"], fontName="Helvetica-Bold", fontSize=11.5, leading=15, textColor=ACCENT, spaceBefore=8, spaceAfter=4),
    "body": ParagraphStyle("b", parent=_base["Normal"], fontSize=9, leading=12.5, textColor=colors.black),
    "small": ParagraphStyle("s", parent=_base["Normal"], fontSize=7.5, leading=9.5, textColor=colors.black),
    "muted": ParagraphStyle("m", parent=_base["Normal"], fontSize=8, leading=10.5, textColor=MUTED),
    "cell": ParagraphStyle("c", parent=_base["Normal"], fontSize=7.3, leading=9.2),
    "cellb": ParagraphStyle("cb", parent=_base["Normal"], fontName="Helvetica-Bold", fontSize=7.3, leading=9.2, textColor=colors.white),
    "mono": ParagraphStyle("mono", parent=_base["Code"], fontName="Courier", fontSize=7.2, leading=9, textColor=colors.black),
    "banner": ParagraphStyle("ban", parent=_base["Normal"], fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=colors.HexColor("#92400e")),
}


def esc(value: Any) -> str:
    return escape("" if value is None else str(value))


def P(text: Any, style: str = "body") -> Paragraph:
    return Paragraph(esc(text), S[style])


def sev(value: str) -> Paragraph:
    color = SEV_COLORS.get(value, "#334155")
    return Paragraph(f'<font color="{color}"><b>{esc(value).upper()}</b></font>', S["cell"])


def table(headers: list[str], rows: list[list[Any]], widths: list[float]) -> Table:
    data = [[Paragraph(esc(h), S["cellb"]) for h in headers]]
    for r in rows:
        data.append([c if isinstance(c, Paragraph) else Paragraph(esc(c), S["cell"]) for c in r])
    t = Table(data, colWidths=[w * mm for w in widths], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE),
        ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    return t


def kv(rows: list[tuple[str, Any]]) -> Table:
    data = [[Paragraph(f"<b>{esc(k)}</b>", S["cell"]), Paragraph(esc(v), S["cell"])] for k, v in rows]
    t = Table(data, colWidths=[42 * mm, 132 * mm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.25, LINE),
                           ("LEFTPADDING", (0, 0), (-1, -1), 3), ("TOPPADDING", (0, 0), (-1, -1), 2),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    return t


def _size(n: Any) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "-"
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return str(n)


def render_pdf(report: dict[str, Any]) -> bytes:
    meta, content, snap = report["metadata"], report["content"], report["integrity_snapshot"]
    case = content["case"]
    buf = BytesIO()

    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(NAVY)
        canvas.rect(0, A4[1] - 12 * mm, A4[0], 12 * mm, fill=1, stroke=0)
        canvas.setFillColor(colors.white)
        canvas.setFont("Helvetica-Bold", 9)
        canvas.drawString(15 * mm, A4[1] - 7.5 * mm, "TRACEFORGE  |  Digital Forensic Investigation Report")
        canvas.setFont("Helvetica", 8)
        canvas.drawRightString(A4[0] - 15 * mm, A4[1] - 7.5 * mm, f"{case['case_number']}  |  {meta['report_id']}")
        canvas.setFillColor(MUTED)
        canvas.setFont("Helvetica", 7)
        footer = "SIMULATED DATA – training scenario" if case.get("synthetic_data") else "Confidential – investigation material"
        canvas.drawString(15 * mm, 9 * mm, f"{footer}   |   content SHA-256 {report['content_sha256'][:16]}…")
        canvas.drawRightString(A4[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=20 * mm,
                            bottomMargin=16 * mm, title=f"TraceForge report {case['case_number']}",
                            author="TraceForge", subject=case["title"])
    story: list[Any] = []

    # ---- cover -----------------------------------------------------------
    story += [Spacer(1, 14 * mm), Paragraph("Digital Forensic Investigation Report", S["title"]),
              Spacer(1, 3 * mm), P(f"{case['case_number']} — {case['title']}", "subtitle"), Spacer(1, 6 * mm)]
    if case.get("synthetic_data"):
        banner = Table([[Paragraph("SIMULATED EVIDENCE – This report was generated from a synthetic training dataset. "
                                   "All organisations, people, hosts, addresses and events are fictional.", S["banner"])]],
                       colWidths=[180 * mm])
        banner.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fef3c7")),
                                    ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#f59e0b")),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5),
                                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
        story += [banner, Spacer(1, 6 * mm)]
    story.append(kv([
        ("Organisation", case["organization"]), ("Case status", case["status"]), ("Priority", case["priority"]),
        ("Lead investigator", case["lead_investigator"] or "-"), ("Report ID", meta["report_id"]),
        ("Generated (UTC)", meta["generated_at_utc"]), ("Generated by", meta["generated_by"]), ("Tool", meta["tool"]),
        ("Content SHA-256", report["content_sha256"]),
        ("Ledger head hash", snap["ledger"]["head_hash"]),
    ]))
    story += [Spacer(1, 4 * mm), P("The content SHA-256 covers every analytical section of this report. Regenerating the "
                                  "report from the same stored investigation data produces the same value. The ledger head "
                                  "hash should be recorded independently to make later rewriting of the audit trail detectable.", "muted")]

    # ---- executive summary ------------------------------------------------
    sm = content["summary"]
    story += [PageBreak(), Paragraph("1. Incident description and summary", S["h1"]), P(case["description"]), Spacer(1, 3 * mm)]
    story.append(table(["Metric", "Value"], [
        ["Evidence items", sm["evidence_items"]],
        ["Findings by classification", ", ".join(f"{k}: {v}" for k, v in sm["findings_by_classification"].items())],
        ["Suspicious/confirmed findings by severity", ", ".join(f"{k}: {v}" for k, v in sm["findings_by_severity"].items())],
        ["Timeline events", sm["timeline_events"]], ["Correlated sequences (hypotheses)", sm["correlations"]],
        ["Indicators", f"{sm['iocs']} ({', '.join(f'{k}: {v}' for k, v in sm['iocs_by_assessment'].items())})"],
    ], [70, 110]))
    if content["correlations"]:
        story += [Paragraph("Correlated sequences", S["h2"])]
        story.append(table(["Rule", "Sequence", "Severity", "Confidence", "Window (UTC)"],
                           [[c["rule_id"], c["title"], sev(c["severity"]), c["confidence"],
                             f"{(c['start_utc'] or '')[:19]} → {(c['end_utc'] or '')[11:19]}"] for c in content["correlations"]],
                           [20, 82, 18, 20, 40]))

    story += [Paragraph("2. Analyst conclusions", S["h1"]),
              P("Conclusions are written by the investigator and distinguish confirmed facts from hypotheses.", "muted"),
              Spacer(1, 2 * mm), Preformatted(content["analyst_conclusions"] or "(no conclusions recorded)", S["mono"], maxLineLength=118)]

    # ---- evidence ---------------------------------------------------------
    story += [PageBreak(), Paragraph("3. Evidence inventory", S["h1"])]
    story.append(table(["Evidence ID", "Original filename", "Type", "Size", "SHA-256 / MD5", "Acquired (UTC)"],
                       [[e["evidence_id"], e["original_filename"], e["artifact_type"], _size(e["size_bytes"]),
                         Paragraph(f'{esc(e["sha256"])}<br/><font color="#64748b">md5 {esc(e["md5"])}</font>', S["cell"]),
                         f"{(e['acquired_at_utc'] or '')[:19]}\nby {e['acquired_by']}"] for e in content["evidence_inventory"]],
                       [27, 38, 21, 15, 54, 25]))
    story += [Paragraph("4. Integrity verification", S["h1"]),
              P(f"Every evidence item was re-hashed while generating this report. Ledger verification: "
                f"{'VALID' if snap['ledger']['valid'] else 'INVALID'} ({snap['ledger']['records_checked']} records checked).")]
    story.append(table(["Evidence ID", "File", "Result", "Observed SHA-256", "Checks"],
                       [[c["evidence_id"], c["filename"], sev("info") if c["result"] == "match" else sev("critical"),
                         c["observed_sha256"] or "-", c["checks_performed"]] for c in snap["evidence"]],
                       [27, 40, 16, 85, 12]))
    if not snap["ledger"]["valid"]:
        story.append(P(f"Ledger problems: {snap['ledger']['problems'][:5]}"))
    story += [Paragraph("5. Acquisition records (from the audit ledger)", S["h1"])]
    story.append(table(["Seq", "Timestamp (UTC)", "Actor", "Evidence", "Record hash"],
                       [[a["ledger_seq"], a["timestamp_utc"][:23], a["actor"], a["evidence_id"], a["record_hash"]]
                        for a in content["acquisition_records"]], [10, 36, 20, 30, 84]))

    # ---- malware ----------------------------------------------------------
    story += [PageBreak(), Paragraph("6. Malware static analysis", S["h1"]),
              P("Samples were never executed. Indicators are classified as suspicious, informational or inconclusive, "
                "each with the reasoning used.", "muted")]
    for m in content["malware_analysis"]:
        a = m.get("assessment") or {}
        pe = m.get("pe") or {}
        f = m.get("file") or {}
        block = [Paragraph(f"{esc(m['filename'])} ({esc(m['evidence_id'])})", S["h2"]),
                 kv([("Assessment", f"{a.get('label', '-')}: {a.get('summary', '')}"),
                     ("SHA-256", m["sha256"]), ("Type", f.get("detected_type")),
                     ("File entropy", f"{f.get('entropy')} ({f.get('entropy_assessment')})"),
                     ("Compile timestamp", f"{pe.get('compile_timestamp')} (forgeable; context only)"),
                     ("Machine / subsystem", f"{pe.get('machine')} / {pe.get('subsystem')}"),
                     ("Entry point", f"{pe.get('entry_point')} in {pe.get('entry_section')}"),
                     ("Imphash", pe.get("imphash"))])]
        story.append(KeepTogether(block))
        if m.get("sections"):
            story.append(Spacer(1, 2 * mm))
            story.append(table(["Section", "Virtual size", "Raw size", "Entropy", "Flags", "Notes"],
                               [[s["name"], s["virtual_size"], s["raw_size"], s["entropy"], " ".join(s["flags"]), ", ".join(s["notes"])]
                                for s in m["sections"]], [20, 22, 20, 16, 52, 50]))
        if m.get("indicators"):
            story.append(Spacer(1, 2 * mm))
            story.append(table(["ID", "Indicator", "Class", "Severity", "Rationale"],
                               [[i["id"], i["title"], i["classification"], sev(i["severity"]), i["rationale"]] for i in m["indicators"]],
                               [13, 45, 20, 15, 87]))
        if m.get("yara_matches"):
            story.append(Spacer(1, 2 * mm))
            story.append(table(["YARA rule", "Severity", "Explanation"],
                               [[f"{y['rule']} ({y['id']})", sev(y["severity"]), y["explanation"]] for y in m["yara_matches"]], [55, 15, 110]))

    story += [Paragraph("7. YARA matches across all evidence", S["h1"])]
    story.append(table(["File", "Rule", "Severity", "Explanation"],
                       [[y["filename"], f"{y['rule']} ({y['id']})", sev(y["severity"]), y["explanation"]] for y in content["yara_matches"]],
                       [38, 45, 15, 82]))

    # ---- windows ----------------------------------------------------------
    win = content["windows_events"]
    story += [PageBreak(), Paragraph("8. Windows event findings", S["h1"])]
    story.append(table(["Event ID", "Meaning", "Count"], [[c["event_id"], c["description"], c["count"]] for c in win["event_id_counts"]], [20, 120, 20]))
    story.append(Spacer(1, 3 * mm))
    story.append(table(["Time (UTC)", "Rule", "Severity", "Class", "Description"],
                       [[(f["event_time_utc"] or "")[:19], f"{f['rule_id']}\n{f['title']}", sev(f["severity"]), f["classification"], f["description"]]
                        for f in win["findings"] if f["classification"] != "informational"], [27, 40, 15, 20, 78]))

    br = content["browser_artifacts"]
    story += [Paragraph("9. Browser artifacts", S["h1"]), Paragraph("Downloads", S["h2"])]
    story.append(table(["Start (UTC)", "Target path", "Source URL / referrer", "Size", "Danger type"],
                       [[(d["timestamp_utc"] or "")[:19], d["target_path"], f"{d['url']}\nref: {d['referrer']}", _size(d["total_bytes"]), d["danger_type"]]
                        for d in br["downloads"]], [27, 45, 70, 16, 22]))
    story += [Paragraph("Visits", S["h2"])]
    story.append(table(["Time (UTC)", "URL", "Title", "Transition"],
                       [[(v["timestamp_utc"] or "")[:19], v["url"], v["title"], v["transition"]] for v in br["visits"]], [27, 75, 60, 18]))
    if br["findings"]:
        story += [Paragraph("Browser findings", S["h2"])]
        story.append(table(["Rule", "Severity", "Description", "Rationale"],
                           [[f"{f['rule_id']}\n{f['title']}", sev(f["severity"]), f["description"], f["rationale"]] for f in br["findings"]], [40, 15, 60, 65]))

    if content["network_and_file_findings"]:
        story += [Paragraph("10. Network and file activity findings", S["h1"])]
        story.append(table(["Time (UTC)", "Rule", "Severity", "Description"],
                           [[(f["event_time_utc"] or "")[:19], f"{f['rule_id']}\n{f['title']}", sev(f["severity"]), f["description"]]
                            for f in content["network_and_file_findings"]], [27, 48, 15, 90]))

    # ---- IOCs -------------------------------------------------------------
    story += [PageBreak(), Paragraph("11. Indicators of compromise", S["h1"]),
              P("Assessment is 'observed' unless a watchlist entry or a medium+ severity finding/correlation references the "
                "indicator. Extraction alone does not imply maliciousness.", "muted")]
    story.append(table(["Type", "Indicator", "Namespace", "Assessment", "Reason", "Seen"],
                       [[i["type"], i["value"], i["classification"], i["assessment"], i["reason"], i["occurrences"]] for i in content["iocs"]],
                       [14, 55, 22, 22, 58, 9]))

    # ---- correlations -----------------------------------------------------
    story += [PageBreak(), Paragraph("12. Reconstructed sequences (hypotheses)", S["h1"])]
    for c in content["correlations"]:
        story += [Paragraph(f"{esc(c['rule_id'])} – {esc(c['title'])}", S["h2"]),
                  P(f"Severity {c['severity']} · confidence {c['confidence']} · classification {c['classification']}", "muted")]
        story.append(table(["Step", "Time (UTC)", "Event", "Link"],
                           [[s["name"], (s["timestamp_utc"] or "")[:19], s["summary"],
                             "; ".join(s["links"]) if s["links"] else ("anchor" if s["link_strength"] == "root" else "host + time window only")]
                            for s in c["steps"]], [24, 27, 79, 50]))
        for cav in c["caveats"]:
            story.append(P(f"• {cav}", "muted"))

    story += [Paragraph("13. Investigation timeline", S["h1"])]
    story.append(table(["Time (UTC)", "Source", "Sev.", "Event"],
                       [[t["timestamp_utc"][:23] + ("*" if t["timezone_assumed"] else ""), f"{t['source_type']}\n{t['event_type']}", sev(t["severity"]), t["summary"]]
                        for t in content["timeline"]], [30, 30, 13, 107]))
    story.append(P("* timezone assumed for the source value", "muted"))

    cf = content["classified_findings"]
    story += [PageBreak(), Paragraph("14. Findings by classification", S["h1"]),
              P(f"Confirmed rule matches: {len(cf['confirmed'])} · Suspicious observations: {len(cf['suspicious'])} · "
                f"Informational: {len(cf['informational'])} · Inconclusive: {len(cf['inconclusive'])} · Hypotheses: {len(cf['hypotheses'])}")]
    story += [Paragraph("Confirmed rule matches", S["h2"]),
              P("A rule's condition is provably satisfied by the evidence; significance depends on the rule.", "muted")]
    story.append(table(["Rule", "Severity", "Evidence", "Description"],
                       [[f"{f['rule_id']}\n{f['title']}", sev(f["severity"]), f["evidence_name"], f["description"]] for f in cf["confirmed"]], [52, 15, 35, 78]))
    story += [Paragraph("Suspicious observations", S["h2"]),
              P("Evidence consistent with malicious activity that also has benign explanations (stated per rule).", "muted")]
    story.append(table(["Rule", "Severity", "Evidence", "Description"],
                       [[f"{f['rule_id']}\n{f['title']}", sev(f["severity"]), f["evidence_name"], f["description"]] for f in cf["suspicious"]], [52, 15, 35, 78]))

    lim = content["limitations"]
    story += [Paragraph("15. Limitations and uncertainties", S["h1"])]
    for item in lim["case_specific"]:
        story.append(P(f"• {item}"))
    story.append(Spacer(1, 2 * mm))
    for item in lim["standard"]:
        story.append(P(f"• {item}"))

    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()
