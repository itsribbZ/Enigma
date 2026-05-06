"""Enigma Phase 5: PQC Standards — ProfTeam Master Research PDF"""
import sys, os
sys.path.insert(0, r"C:\Users\jbro1\Desktop\Sworder721\Tools\BifrostPDF")
from bifrost_pdf import BifrostPDF, BifrostTheme as T
CHECKPOINT_DIR = r"C:\Users\jbro1\Desktop\Enigma\research\.profteam_checkpoints\profteam_pqc_standards_20260322"
OUTPUT_PATH = r"C:\Users\jbro1\Desktop\Enigma\research\Enigma_Phase5_PQC_Standards.pdf"
def read_agent(l):
    with open(os.path.join(CHECKPOINT_DIR, f"Agent_{l}_results.md"), "r", encoding="utf-8") as f: return f.read()
def extract_sections(c):
    s, t, b = [], "", []
    for line in c.split("\n"):
        if line.startswith("## ") and "table of contents" not in line.lower():
            if t: s.append((t, "\n".join(b)))
            t, b = line[3:].strip(), []
        else: b.append(line)
    if t: s.append((t, "\n".join(b)))
    return s
def extract_code(text):
    bl, ib, cu, la = [], False, [], ""
    for line in text.split("\n"):
        if line.strip().startswith("```") and not ib: ib, la, cu = True, line.strip()[3:].strip(), []
        elif line.strip() == "```" and ib: ib = False; bl.append((la, cu))
        elif ib: cu.append(line)
    return bl
def extract_tables(text):
    tb, ls, i = [], text.split("\n"), 0
    while i < len(ls):
        l = ls[i].strip()
        if "|" in l and i+1 < len(ls) and "---" in ls[i+1]:
            h = [x.strip() for x in l.split("|") if x.strip()]
            r, i = [], i+2
            while i < len(ls) and "|" in ls[i]:
                row = [x.strip() for x in ls[i].split("|") if x.strip()]
                if row: r.append(row)
                i += 1
            tb.append((h, r))
        else: i += 1
    return tb
def add_section(pdf, letter, title, focus, sn):
    content = read_agent(letter); sections = extract_sections(content)
    pdf.page_break(); k = f"sec:{letter.lower()}"; pdf.toc_entry(0, f"{sn}. {title}", k)
    pdf.label(k); pdf.section(f"{sn}. {title}"); pdf.body(f"Agent {letter}: {focus}"); pdf.spacer(4)
    for st, sb in sections:
        pdf.subsection(f"{sn}.{sections.index((st,sb))} {st}")
        for la, cl in extract_code(sb):
            t = "Python" if la == "python" else (la.capitalize() if la else "Code")
            d = cl[:50]; (d.append(f"... ({len(cl)-50} more)") if len(cl) > 50 else None)
            pdf.code(d, title=t, line_numbers=True)
        for h, r in extract_tables(sb):
            mc = min(len(h), 6)
            if mc > 0 and r: pdf.table(h[:mc], [x[:mc] for x in r[:12]])
        ic, it = False, False
        for line in sb.split("\n"):
            if line.strip().startswith("```"): ic = not ic; continue
            if ic: continue
            if "|" in line and line.strip().startswith("|"): it = True; continue
            if it and "|" not in line: it = False
            if it: continue
            s = line.strip()
            if not s: continue
            if s.startswith("### "): pdf.body(s[4:], color=T.CYAN)
            elif s.startswith("**") and s.endswith("**"): pdf.body(s.strip("*"), color=T.GOLD)
            elif s.startswith("- "): pdf.bullet(s[2:])
            else: pdf.body(s)
        pdf.spacer(6)
def main():
    pdf = BifrostPDF(title="Enigma Phase 5: PQC Standards", subtitle="ProfTeam Master Research // Implementation Reference",
        output_path=OUTPUT_PATH, footer="ENIGMA // Phase 5 PQC Standards // CONFIDENTIAL")
    pdf.title_page(topics=["LWE Encryption (from math)", "ML-KEM vs RSA Benchmark", "PQC Migration Guide"],
        context={"Project": "Enigma -- Quantum Security", "Phase": "5 of 8 -- PQC Standards",
                 "Agents": "3 (A-C)", "Foundation": "Phases 1-4 (3,573 LOC, 89/89 tests)", "Classification": "CONFIDENTIAL"})
    pdf.page_break(); pdf.toc_entry(0, "Executive Summary", "sec:sum"); pdf.label("sec:sum")
    pdf.section("Executive Summary")
    pdf.body("Phase 5 implements the DEFENSE against quantum attacks. LWE encryption from scratch, "
             "benchmarking ML-KEM against classical crypto, and a protocol-level PQC migration guide.")
    pdf.spacer(4)
    pdf.green_box("NIST PQC Standards (Finalized Aug 2024)", ["FIPS 203: ML-KEM (Kyber) -- key encapsulation (replaces RSA/ECDH)",
        "FIPS 204: ML-DSA (Dilithium) -- digital signatures (replaces RSA/ECDSA)",
        "FIPS 205: SLH-DSA (SPHINCS+) -- hash-based signatures (conservative backup)",
        "FN-DSA (FALCON) -- compact lattice signatures (forthcoming)"])
    pdf.spacer(4)
    for i, (l, t, f) in enumerate([("A","LWE & Lattice Cryptography","Regev encryption, Ring/Module-LWE, ML-KEM, quantum resistance"),
        ("B","ML-KEM vs RSA Benchmark","Performance comparison, liboqs, hybrid key exchange"),
        ("C","PQC Migration Guide","FIPS 203/204/205, protocol migration, enterprise framework")], start=2):
        add_section(pdf, l, t, f, i)
    pdf.render_toc(); pdf.end_section(); pdf.save(); print(f"\nGenerated: {OUTPUT_PATH}")
if __name__ == "__main__": main()
