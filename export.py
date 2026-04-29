#!/usr/bin/env python3

import os
import datetime
import mysql.connector
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_CENTER

SEVERITY_COLORS = {
    "critical": "#c0392b",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#27ae60",
    "unknown":  "#7f8c8d",
}

RISK_COLORS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
    "UNKNOWN":  "#7f8c8d",
}


def get_connection():
    return mysql.connector.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        user=os.environ.get("DB_USER", "metatron"),
        password=os.environ.get("DB_PASSWORD", "123"),
        database=os.environ.get("DB_NAME", "metatron")
    )


def fetch_session(sl_no: int) -> dict:
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()
    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    exploits = c.fetchall()
    c.execute("SELECT * FROM summary WHERE sl_no = %s", (sl_no,))
    summary = c.fetchone()
    conn.close()
    return {"history": history, "vulns": vulns, "fixes": fixes,
            "exploits": exploits, "summary": summary}


def fetch_all_history():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def export_pdf(data: dict, output_dir: str) -> str:
    h        = data["history"]
    sl       = h[0]
    tgt      = h[1]
    date     = str(h[2])
    risk     = data["summary"][4] if data["summary"] else "UNKNOWN"
    ai       = data["summary"][3] if data["summary"] else ""

    os.makedirs(output_dir, exist_ok=True)
    safe = tgt.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    filename = os.path.join(output_dir, f"metatron_SL{sl}_{safe}.pdf")
    doc      = SimpleDocTemplate(filename, pagesize=A4,
                                  topMargin=15*mm, bottomMargin=15*mm,
                                  leftMargin=15*mm, rightMargin=15*mm)

    title_style  = ParagraphStyle("t",  fontSize=22, fontName="Helvetica-Bold",
                                   textColor=colors.HexColor("#c0392b"), spaceAfter=4)
    sub_style    = ParagraphStyle("s",  fontSize=10, fontName="Helvetica",
                                   textColor=colors.HexColor("#555555"), spaceAfter=2)
    h1_style     = ParagraphStyle("h1", fontSize=13, fontName="Helvetica-Bold",
                                   textColor=colors.HexColor("#2c3e50"),
                                   spaceBefore=10, spaceAfter=4)
    body_style   = ParagraphStyle("b",  fontSize=9,  fontName="Helvetica",
                                   textColor=colors.black, leading=13)
    code_style   = ParagraphStyle("c",  fontSize=7.5, fontName="Courier",
                                   textColor=colors.HexColor("#2c3e50"),
                                   backColor=colors.HexColor("#f4f4f4"),
                                   leading=11, leftIndent=6, rightIndent=6,
                                   spaceBefore=2, spaceAfter=2)
    footer_style = ParagraphStyle("f",  fontSize=7,
                                   textColor=colors.HexColor("#aaaaaa"),
                                   alignment=TA_CENTER)
    story = []

    story.append(Paragraph("METATRON", title_style))
    story.append(Paragraph("AI Penetration Testing Report", sub_style))
    story.append(HRFlowable(width="100%", thickness=1.5,
                             color=colors.HexColor("#c0392b"), spaceAfter=8))

    risk_color = colors.HexColor(RISK_COLORS.get(risk.upper(), "#7f8c8d"))
    meta = [["Target", tgt], ["Scan Date", date],
            ["Session", f"SL# {sl}"], ["Risk Level", risk],
            ["Generated", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")]]
    mt = Table(meta, colWidths=[35*mm, 130*mm])
    mt.setStyle(TableStyle([
        ("FONTNAME",       (0,0), (-1,-1), "Helvetica"),
        ("FONTSIZE",       (0,0), (-1,-1), 9),
        ("FONTNAME",       (0,0), (0,-1),  "Helvetica-Bold"),
        ("TEXTCOLOR",      (0,0), (0,-1),  colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",      (1,3), (1,3),   risk_color),
        ("FONTNAME",       (1,3), (1,3),   "Helvetica-Bold"),
        ("ROWBACKGROUNDS", (0,0), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
        ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
        ("PADDING",        (0,0), (-1,-1), 5),
    ]))
    story.append(mt)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Vulnerabilities", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["vulns"]:
        vd = [["#", "Vulnerability", "Severity", "Port", "Service"]]
        for v in data["vulns"]:
            vd.append([str(v[0]), str(v[2] or "-"),
                       str(v[3] or "-").upper(), str(v[4] or "-"), str(v[5] or "-")])
        vt  = Table(vd, colWidths=[10*mm, 72*mm, 24*mm, 18*mm, 28*mm], repeatRows=1)
        vts = [
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 8),
            ("BACKGROUND",     (0,0), (-1,0),  colors.HexColor("#2c3e50")),
            ("TEXTCOLOR",      (0,0), (-1,0),  colors.white),
            ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
            ("PADDING",        (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
        ]
        for i, v in enumerate(data["vulns"], 1):
            sc = colors.HexColor(SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d"))
            vts.append(("TEXTCOLOR", (2,i), (2,i), sc))
            vts.append(("FONTNAME",  (2,i), (2,i), "Helvetica-Bold"))
        vt.setStyle(TableStyle(vts))
        story.append(vt)
        story.append(Spacer(1, 6))

        story.append(Paragraph("Vulnerability Details", h1_style))
        story.append(HRFlowable(width="100%", thickness=0.5,
                                 color=colors.HexColor("#dddddd"), spaceAfter=6))
        for v in data["vulns"]:
            sc  = colors.HexColor(SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d"))
            lbl = ParagraphStyle("vl", fontSize=9, fontName="Helvetica-Bold", textColor=sc)
            story.append(Paragraph(f"[{(v[3] or 'UNKNOWN').upper()}] {v[2]}", lbl))
            if v[6]:
                story.append(Paragraph(str(v[6]), body_style))
            story.append(Spacer(1, 4))
    else:
        story.append(Paragraph("No vulnerabilities recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Fixes & Mitigations", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["fixes"]:
        for f in data["fixes"]:
            story.append(Paragraph(f"Fix for vuln id={f[2]}:", body_style))
            story.append(Paragraph(str(f[3] or "-"), code_style))
            story.append(Spacer(1, 3))
    else:
        story.append(Paragraph("No fixes recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("Exploits Attempted", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if data["exploits"]:
        ed = [["#", "Exploit", "Tool", "Result"]]
        for e in data["exploits"]:
            ed.append([str(e[0]), str(e[2] or "-")[:60],
                       str(e[3] or "-")[:30], str(e[5] or "-")[:30]])
        et = Table(ed, colWidths=[10*mm, 80*mm, 40*mm, 28*mm])
        et.setStyle(TableStyle([
            ("FONTNAME",       (0,0), (-1,0),  "Helvetica-Bold"),
            ("FONTSIZE",       (0,0), (-1,-1), 8),
            ("BACKGROUND",     (0,0), (-1,0),  colors.HexColor("#2c3e50")),
            ("TEXTCOLOR",      (0,0), (-1,0),  colors.white),
            ("GRID",           (0,0), (-1,-1), 0.3, colors.HexColor("#dddddd")),
            ("PADDING",        (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#f9f9f9"), colors.white]),
        ]))
        story.append(et)
    else:
        story.append(Paragraph("No exploits recorded.", body_style))

    story.append(Spacer(1, 6))
    story.append(Paragraph("AI Analysis Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=6))
    if ai:
        for line in str(ai).split("\n"):
            line = line.strip()
            if line:
                story.append(Paragraph(line, body_style))
                story.append(Spacer(1, 2))
    else:
        story.append(Paragraph("No AI analysis recorded.", body_style))

    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5,
                             color=colors.HexColor("#dddddd"), spaceAfter=4))
    story.append(Paragraph(
        "Generated by METATRON — AI Penetration Testing Assistant | "
        "github.com/sooryathejas/METATRON | For authorized use only.",
        footer_style))

    doc.build(story)
    return filename


def export_html(data: dict, output_dir: str) -> str:
    h    = data["history"]
    sl   = h[0]
    tgt  = h[1]
    date = str(h[2])
    risk = data["summary"][4] if data["summary"] else "UNKNOWN"
    ai   = data["summary"][3] if data["summary"] else ""
    rc   = RISK_COLORS.get(risk.upper(), "#7f8c8d")

    os.makedirs(output_dir, exist_ok=True)
    safe = tgt.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    filename = os.path.join(output_dir, f"metatron_SL{sl}_{safe}.html")
    vuln_rows = ""
    for v in data["vulns"]:
        sc = SEVERITY_COLORS.get((v[3] or "unknown").lower(), "#7f8c8d")
        vuln_rows += (f"<tr><td>{v[0]}</td>"
                      f"<td><strong>{v[2]}</strong><br><small>{v[6] or ''}</small></td>"
                      f"<td><span style='color:{sc};font-weight:bold'>"
                      f"{(v[3] or 'unknown').upper()}</span></td>"
                      f"<td>{v[4] or '-'}</td><td>{v[5] or '-'}</td></tr>")

    fix_rows = ""
    for f in data["fixes"]:
        fix_rows += (f"<tr><td>{f[0]}</td><td>vuln #{f[2]}</td>"
                     f"<td><code>{f[3] or '-'}</code></td>"
                     f"<td>{f[4] or 'ai'}</td></tr>")

    exp_rows = ""
    for e in data["exploits"]:
        exp_rows += (f"<tr><td>{e[0]}</td><td>{e[2] or '-'}</td>"
                     f"<td>{e[3] or '-'}</td>"
                     f"<td><code>{str(e[4] or '-')[:80]}</code></td>"
                     f"<td>{e[5] or '-'}</td></tr>")

    ai_html = "".join(f"<p>{line}</p>"
                      for line in str(ai).split("\n") if line.strip())

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Metatron Report — {tgt}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',sans-serif;background:#0d0d0d;color:#e0e0e0;padding:30px}}
.container{{max-width:960px;margin:auto}}
.header{{border-left:5px solid #c0392b;padding-left:16px;margin-bottom:30px}}
.header h1{{font-size:2.2em;color:#c0392b}}
.header p{{color:#888;font-size:.95em}}
.meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:30px}}
.meta-card{{background:#1a1a1a;border:1px solid #333;border-radius:6px;padding:14px}}
.meta-card .label{{font-size:.75em;color:#888;text-transform:uppercase;margin-bottom:4px}}
.meta-card .value{{font-size:1.1em;font-weight:bold}}
.risk{{color:{rc}}}
section{{margin-bottom:30px}}
section h2{{font-size:1.2em;color:#c0392b;border-bottom:1px solid #333;
            padding-bottom:8px;margin-bottom:14px}}
table{{width:100%;border-collapse:collapse;font-size:.88em}}
th{{background:#1e1e1e;color:#aaa;text-align:left;padding:10px;
    font-size:.8em;text-transform:uppercase;border-bottom:2px solid #333}}
td{{padding:10px;border-bottom:1px solid #222;vertical-align:top}}
tr:hover td{{background:#1a1a1a}}
code{{background:#1e1e1e;padding:2px 6px;border-radius:3px;
      font-family:monospace;font-size:.85em;color:#e74c3c}}
.ai-box{{background:#111;border:1px solid #333;border-radius:6px;
         padding:16px;font-size:.9em;line-height:1.7;color:#ccc}}
.ai-box p{{margin-bottom:8px}}
.footer{{text-align:center;color:#444;font-size:.78em;
         margin-top:40px;border-top:1px solid #222;padding-top:16px}}
a{{color:#555}}
</style>
</head>
<body>
<div class="container">

<div class="header">
  <h1>🔱 METATRON</h1>
  <p>AI Penetration Testing Report</p>
</div>

<div class="meta-grid">
  <div class="meta-card">
    <div class="label">Target</div>
    <div class="value">{tgt}</div>
  </div>
  <div class="meta-card">
    <div class="label">Session</div>
    <div class="value">SL# {sl}</div>
  </div>
  <div class="meta-card">
    <div class="label">Scan Date</div>
    <div class="value">{date}</div>
  </div>
  <div class="meta-card">
    <div class="label">Risk Level</div>
    <div class="value risk">{risk}</div>
  </div>
</div>

<section>
  <h2>Vulnerabilities</h2>
  {'<table><thead><tr><th>#</th><th>Vulnerability</th><th>Severity</th><th>Port</th><th>Service</th></tr></thead><tbody>' + vuln_rows + '</tbody></table>' if data["vulns"] else '<p style="color:#888">None recorded.</p>'}
</section>

<section>
  <h2>Fixes &amp; Mitigations</h2>
  {'<table><thead><tr><th>#</th><th>Vuln</th><th>Fix</th><th>Source</th></tr></thead><tbody>' + fix_rows + '</tbody></table>' if data["fixes"] else '<p style="color:#888">None recorded.</p>'}
</section>

<section>
  <h2>Exploits Attempted</h2>
  {'<table><thead><tr><th>#</th><th>Exploit</th><th>Tool</th><th>Payload</th><th>Result</th></tr></thead><tbody>' + exp_rows + '</tbody></table>' if data["exploits"] else '<p style="color:#888">None recorded.</p>'}
</section>

<section>
  <h2>AI Analysis Summary</h2>
  <div class="ai-box">
    {ai_html if ai_html else '<p style="color:#888">None recorded.</p>'}
  </div>
</section>

<div class="footer">
  Generated by METATRON &mdash;
  <a href="https://github.com/sooryathejas/METATRON">github.com/sooryathejas/METATRON</a>
  &mdash; For authorized use only.
</div>

</div>
</body>
</html>"""

    with open(filename, "w") as f:
        f.write(html)
    return filename


def export_menu(data: dict):
    if not data["history"]:
        print("[!] No session data to export.")
        return

    h   = data["history"]
    sl  = h[0]
    tgt = h[1]

    print(f"\n\033[33m{'─'*20} EXPORT SL#{sl} — {tgt} {'─'*20}\033[0m")
    print("  [1] PDF report")
    print("  [2] HTML report")
    print("  [3] Both")
    print("  [4] Back")
    print(f"\033[90m{'─'*60}\033[0m")

    choice     = input("\033[36mExport format: \033[0m").strip()
    output_dir = os.path.expanduser("~/METATRON/reports")
    os.makedirs(output_dir, exist_ok=True)

    if choice == "1":
        p = export_pdf(data, output_dir)
        print(f"\033[92m[+] PDF saved: {p}\033[0m")
    elif choice == "2":
        p = export_html(data, output_dir)
        print(f"\033[92m[+] HTML saved: {p}\033[0m")
    elif choice == "3":
        p1 = export_pdf(data, output_dir)
        p2 = export_html(data, output_dir)
        print(f"\033[92m[+] PDF  : {p1}\033[0m")
        print(f"\033[92m[+] HTML : {p2}\033[0m")
    elif choice == "4":
        return
    else:
        print("\033[93m[!] Invalid choice.\033[0m")


if __name__ == "__main__":
    print("\n\033[91m    METATRON — Standalone Report Exporter\033[0m")
    print("\033[90m    ─────────────────────────────────────\033[0m\n")

    rows = fetch_all_history()
    if not rows:
        print("[!] No sessions found in database.")
        exit()

    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─" * 65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()

    sl_input = input("\033[36mEnter SL# to export: \033[0m").strip()
    if not sl_input.isdigit():
        print("[!] Invalid SL#.")
        exit()

    data = fetch_session(int(sl_input))
    if not data["history"]:
        print(f"[!] SL# {sl_input} not found.")
        exit()

    export_menu(data)
