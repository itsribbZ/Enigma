"""Enigma Phase 4: Quantum Threat Model — ProfTeam Master Research PDF"""
import sys, os
sys.path.insert(0, r"C:\Users\jbro1\Desktop\Sworder721\Tools\BifrostPDF")
from bifrost_pdf import BifrostPDF, BifrostTheme as T

CHECKPOINT_DIR = r"C:\Users\jbro1\Desktop\Enigma\research\.profteam_checkpoints\profteam_quantum_threats_20260322"
OUTPUT_PATH = r"C:\Users\jbro1\Desktop\Enigma\research\Enigma_Phase4_Quantum_Threats.pdf"

def read_agent(letter):
    with open(os.path.join(CHECKPOINT_DIR, f"Agent_{letter}_results.md"), "r", encoding="utf-8") as f:
        return f.read()

def extract_sections(content):
    sections, title, body = [], "", []
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
        if line.strip().startswith("```") and not in_b: in_b, lang, cur = True, line.strip()[3:].strip(), []
        elif line.strip() == "```" and in_b: in_b = False; blocks.append((lang, cur))
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
    pdf.label(key); pdf.section(f"{sec_num}. {title}")
    pdf.body(f"Agent {letter}: {focus}"); pdf.spacer(4)
    for sub_title, sub_body in sections:
        pdf.subsection(f"{sec_num}.{sections.index((sub_title, sub_body))} {sub_title}")
        for lang, code_lines in extract_code_blocks(sub_body):
            t = "Python" if lang == "python" else (lang.capitalize() if lang else "Code")
            d = code_lines[:50]
            if len(code_lines) > 50: d.append(f"... ({len(code_lines)-50} more lines)")
            pdf.code(d, title=t, line_numbers=True)
        for headers, rows in extract_tables(sub_body):
            mc = min(len(headers), 6)
            if mc > 0 and rows: pdf.table(headers[:mc], [r[:mc] for r in rows[:12]])
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
            else: pdf.body(s)
        pdf.spacer(6)

def main():
    pdf = BifrostPDF(title="Enigma Phase 4: Quantum Threat Model",
        subtitle="ProfTeam Master Research // Implementation Reference", output_path=OUTPUT_PATH,
        footer="ENIGMA // Phase 4 Quantum Threats // CONFIDENTIAL")
    pdf.title_page(topics=["Shor's Algorithm (RSA/ECC Breaking)", "Grover's Algorithm (AES Implications)",
        "Quantum Threat Assessment Template"], context={"Project": "Enigma -- Quantum Security Expert Track",
        "Phase": "4 of 8 -- Quantum Threat Model", "Agents": "3 parallel (A-C)",
        "Foundation": "Phases 1-3 (3,108 LOC, 78/78 tests)", "Classification": "CONFIDENTIAL"})
    pdf.page_break()
    pdf.toc_entry(0, "Executive Summary", "sec:summary"); pdf.label("sec:summary")
    pdf.section("Executive Summary")
    pdf.body("Phase 4 is where Phase 2 (classical crypto) and Phase 3 (quantum mechanics) converge. "
             "Understanding exactly HOW quantum computers break RSA and ECC -- and what they can't break.")
    pdf.spacer(4)
    pdf.red_box("What Quantum BREAKS (Shor)", ["RSA -- factoring N=pq becomes polynomial",
        "ECDSA/ECDH -- discrete log on elliptic curves broken", "DH/DSA/ElGamal -- all DLP-based crypto",
        "Ed25519 -- also DLP-based, also broken", "Timeline: ~20M physical qubits needed (2035-2045)"])
    pdf.spacer(4)
    pdf.green_box("What SURVIVES Quantum", ["AES-256 -- 128-bit post-quantum security (Grover halves)",
        "SHA-256 -- preimage still 128-bit, collision unclear", "ML-KEM (Kyber) -- lattice-based, quantum-safe",
        "ML-DSA (Dilithium) -- lattice signatures, quantum-safe", "SLH-DSA (SPHINCS+) -- hash-based, quantum-safe"])
    pdf.spacer(4)
    agents = [("A", "Shor's Algorithm", "Factoring simulation, quantum order finding, RSA/ECC implications"),
              ("B", "Grover's Algorithm", "n-qubit search, AES key-space analysis, security level comparison"),
              ("C", "Quantum Threat Assessment", "HNDL, Mosca's inequality, NIST PQC, CISO template")]
    for i, (letter, title, focus) in enumerate(agents, start=2):
        add_agent_section(pdf, letter, title, focus, i)
    pdf.render_toc(); pdf.end_section(); pdf.save()
    print(f"\nGenerated: {OUTPUT_PATH}")

if __name__ == "__main__": main()
