"""
Enigma Phase 3: Quantum Mechanics for CS — ProfTeam Master Research PDF Generator
"""
import sys, os
sys.path.insert(0, r"C:\Users\jbro1\Desktop\Sworder721\Tools\BifrostPDF")
from bifrost_pdf import BifrostPDF, BifrostTheme as T

CHECKPOINT_DIR = r"C:\Users\jbro1\Desktop\Enigma\research\.profteam_checkpoints\profteam_quantum_mechanics_20260322"
OUTPUT_PATH = r"C:\Users\jbro1\Desktop\Enigma\research\Enigma_Phase3_Quantum_Mechanics.pdf"

def read_agent(letter):
    with open(os.path.join(CHECKPOINT_DIR, f"Agent_{letter}_results.md"), "r", encoding="utf-8") as f:
        return f.read()

def extract_sections(content):
    sections = []
    title, body = "", []
    for line in content.split("\n"):
        if line.startswith("## ") and "table of contents" not in line.lower():
            if title: sections.append((title, "\n".join(body)))
            title, body = line[3:].strip(), []
        else: body.append(line)
    if title: sections.append((title, "\n".join(body)))
    return sections

def extract_code_blocks(text):
    blocks, in_b, cur, lang = [], False, [], ""
    for line in text.split("\n"):
        if line.strip().startswith("```") and not in_b:
            in_b, lang, cur = True, line.strip()[3:].strip(), []
        elif line.strip() == "```" and in_b:
            in_b = False; blocks.append((lang, cur))
        elif in_b: cur.append(line)
    return blocks

def extract_tables(text):
    tables, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        line = lines[i].strip()
        if "|" in line and i+1 < len(lines) and "---" in lines[i+1]:
            headers = [h.strip() for h in line.split("|") if h.strip()]
            rows, i = [], i + 2
            while i < len(lines) and "|" in lines[i]:
                row = [c.strip() for c in lines[i].split("|") if c.strip()]
                if row: rows.append(row)
                i += 1
            tables.append((headers, rows))
        else: i += 1
    return tables

def add_agent_section(pdf, letter, title, focus, sec_num):
    content = read_agent(letter)
    sections = extract_sections(content)
    pdf.page_break()
    key = f"sec:agent_{letter.lower()}"
    pdf.toc_entry(0, f"{sec_num}. {title}", key)
    pdf.label(key)
    pdf.section(f"{sec_num}. {title}")
    pdf.body(f"Agent {letter}: {focus}")
    pdf.spacer(4)
    for sub_title, sub_body in sections:
        sub_idx = sections.index((sub_title, sub_body))
        pdf.subsection(f"{sec_num}.{sub_idx} {sub_title}")
        code_blocks = extract_code_blocks(sub_body)
        tables = extract_tables(sub_body)
        in_code, in_table = False, False
        for line in sub_body.split("\n"):
            if line.strip().startswith("```"): in_code = not in_code; continue
            if in_code: continue
            if "|" in line and line.strip().startswith("|"): in_table = True; continue
            if in_table and "|" not in line: in_table = False
            if in_table: continue
            s = line.strip()
            if not s: continue
            if s.startswith("### "): pdf.body(s[4:], color=T.CYAN)
            elif s.startswith("**") and s.endswith("**"): pdf.body(s.strip("*"), color=T.GOLD)
            elif s.startswith("- "): pdf.bullet(s[2:])
            elif s.startswith("> "): pdf.body(s[2:], color=T.SILVER, indent=20)
            else: pdf.body(s)
        for lang, code_lines in code_blocks:
            t = "Python" if lang == "python" else (lang.capitalize() if lang else "Code")
            d = code_lines[:50]
            if len(code_lines) > 50: d.append(f"... ({len(code_lines)-50} more lines)")
            pdf.code(d, title=t, line_numbers=True)
        for headers, rows in tables:
            mc = min(len(headers), 6)
            if mc > 0 and rows:
                pdf.table(headers[:mc], [r[:mc] for r in rows[:12]])
        pdf.spacer(6)

def main():
    pdf = BifrostPDF(
        title="Enigma Phase 3: Quantum Mechanics",
        subtitle="ProfTeam Master Research // Implementation Reference",
        output_path=OUTPUT_PATH,
        footer="ENIGMA // Phase 3 Quantum Mechanics // ProfTeam // CONFIDENTIAL"
    )
    pdf.title_page(
        topics=["Qubit Representation & Dirac Notation", "Quantum Gates (Matrix Representations)",
                "Superposition & Entanglement", "Quantum Circuits & Measurement (Qiskit)",
                "Quantum Fourier Transform (QFT)", "Quantum Teleportation & Noise Models"],
        context={"Project": "Enigma -- Quantum Security Expert Track",
                 "Phase": "3 of 8 -- Quantum Mechanics for CS",
                 "Research Agents": "6 parallel (A-F)",
                 "Foundation": "Phases 1-2 complete (2,728 LOC, 65/65 tests)",
                 "Deliverables": "10 circuits + teleportation + QFT",
                 "Classification": "CONFIDENTIAL"})
    pdf.page_break()
    pdf.toc_entry(0, "Executive Summary", "sec:summary")
    pdf.label("sec:summary")
    pdf.section("Executive Summary")
    pdf.body("Phase 3 builds quantum computing literacy -- just enough to understand "
             "Shor's algorithm (Phase 4) and why lattice crypto resists quantum attacks (Phase 5). "
             "All implementations use Qiskit 2.3+ with Aer simulator.")
    pdf.spacer(4)
    pdf.gold_box("Phase 3 Deliverables", [
        "1. Qiskit notebook: 10 fundamental quantum circuits",
        "2. Quantum teleportation protocol (from scratch + verified)",
        "3. QFT implementation with state evolution visualization"])
    pdf.spacer(4)
    pdf.cyan_box("Key Connections to Later Phases", [
        "QFT -> Shor's algorithm (Phase 4) -- QFT is Shor's core subroutine",
        "Entanglement -> QKD protocols BB84/E91 (Phase 7)",
        "Noise models -> why error correction matters for practical QC",
        "Gate operations -> understanding Shor's qubit requirements (~20M physical)"])
    pdf.spacer(4)
    pdf.table(
        headers=["Agent", "Topic", "Sources", "Confidence", "Lines"],
        rows=[["A", "Qubit Representation", "Nielsen & Chuang, Qiskit docs", "VERIFIED", "1142"],
              ["B", "Quantum Gates", "Standard QM, Qiskit API", "VERIFIED", "774"],
              ["C", "Superposition & Entanglement", "Nielsen & Chuang, Preskill", "VERIFIED", "~800"],
              ["D", "Circuits & Measurement", "Qiskit 1.0+ API", "VERIFIED", "1278"],
              ["E", "QFT", "Nielsen & Chuang, Shor 1994", "VERIFIED", "806"],
              ["F", "Teleportation & Noise", "Bennett 1993, IBM hardware data", "VERIFIED", "920"]])
    pdf.spacer(4)
    agents = [
        ("A", "Qubit Representation & Notation", "Dirac notation, state vectors, tensor products, Born rule, Bloch sphere"),
        ("B", "Quantum Gates", "11 single-qubit gates, 5 two-qubit, Toffoli, CR_k for QFT, numpy code"),
        ("C", "Superposition & Entanglement", "Bell states, no-cloning, GHZ/W, Schmidt decomposition"),
        ("D", "Quantum Circuits & Measurement", "10 fundamental circuits, Qiskit 1.0+ API, 5 execution methods"),
        ("E", "Quantum Fourier Transform", "QFT math, circuit construction, inverse QFT, Shor connection"),
        ("F", "Teleportation & Noise", "Teleportation protocol, 5 noise channels, error correction, hardware")]
    for i, (letter, title, focus) in enumerate(agents, start=3):
        add_agent_section(pdf, letter, title, focus, i)
    pdf.render_toc()
    pdf.end_section()
    pdf.save()
    print(f"\nGenerated: {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
