"""
Enigma Phase 2: Classical Cryptography — ProfTeam Master Research PDF Generator
Compiles all 7 agent research outputs into one implementation-ready reference.
"""

import sys
import os

sys.path.insert(0, r"C:\Users\jbro1\Desktop\Sworder721\Tools\BifrostPDF")
from bifrost_pdf import BifrostPDF, BifrostTheme as T

CHECKPOINT_DIR = r"C:\Users\jbro1\Desktop\Enigma\research\.profteam_checkpoints\profteam_classical_crypto_20260321"
OUTPUT_PATH = r"C:\Users\jbro1\Desktop\Enigma\research\Enigma_Phase2_Classical_Cryptography.pdf"


def read_agent(letter):
    path = os.path.join(CHECKPOINT_DIR, f"Agent_{letter}_results.md")
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def extract_sections(content):
    sections = []
    current_title = ""
    current_body = []
    for line in content.split("\n"):
        if line.startswith("## ") and "table of contents" not in line.lower():
            if current_title:
                sections.append((current_title, "\n".join(current_body)))
            current_title = line[3:].strip()
            current_body = []
        else:
            current_body.append(line)
    if current_title:
        sections.append((current_title, "\n".join(current_body)))
    return sections


def extract_code_blocks(text):
    blocks = []
    in_block = False
    current = []
    lang = ""
    for line in text.split("\n"):
        if line.strip().startswith("```") and not in_block:
            in_block = True
            lang = line.strip()[3:].strip()
            current = []
        elif line.strip() == "```" and in_block:
            in_block = False
            blocks.append((lang, current))
        elif in_block:
            current.append(line)
    return blocks


def extract_tables(text):
    tables = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if "|" in line and i + 1 < len(lines) and "---" in lines[i + 1]:
            headers = [h.strip() for h in line.split("|") if h.strip()]
            rows = []
            i += 2
            while i < len(lines) and "|" in lines[i]:
                row = [c.strip() for c in lines[i].split("|") if c.strip()]
                if row:
                    rows.append(row)
                i += 1
            tables.append((headers, rows))
        else:
            i += 1
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

        in_code = False
        in_table = False
        for line in sub_body.split("\n"):
            if line.strip().startswith("```"):
                in_code = not in_code
                continue
            if in_code:
                continue
            if "|" in line and line.strip().startswith("|"):
                in_table = True
                continue
            if in_table and "|" not in line:
                in_table = False
            if in_table:
                continue
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("### "):
                pdf.body(stripped[4:], color=T.CYAN)
            elif stripped.startswith("**") and stripped.endswith("**"):
                pdf.body(stripped.strip("*"), color=T.GOLD)
            elif stripped.startswith("- "):
                pdf.bullet(stripped[2:])
            elif stripped.startswith("> "):
                pdf.body(stripped[2:], color=T.SILVER, indent=20)
            else:
                pdf.body(stripped)

        for lang, code_lines in code_blocks:
            t = "Python" if lang == "python" else (lang.capitalize() if lang else "Code")
            display = code_lines[:50]
            if len(code_lines) > 50:
                display.append(f"... ({len(code_lines) - 50} more lines)")
            pdf.code(display, title=t, line_numbers=True)

        for headers, rows in tables:
            mc = min(len(headers), 6)
            if mc > 0 and rows:
                pdf.table(headers[:mc], [r[:mc] for r in rows[:12]])

        pdf.spacer(6)


def main():
    pdf = BifrostPDF(
        title="Enigma Phase 2: Classical Cryptography",
        subtitle="ProfTeam Master Research // Implementation Reference",
        output_path=OUTPUT_PATH,
        footer="ENIGMA // Phase 2 Classical Cryptography // ProfTeam // CONFIDENTIAL"
    )

    pdf.title_page(
        topics=[
            "RSA (Keygen, PKCS#1, OAEP, PSS)",
            "AES (SubBytes, MixColumns, CBC/CTR/GCM)",
            "ECC (secp256k1, P-256, ECDH, ECDSA)",
            "SHA-256 + HMAC + Merkle Trees",
            "Digital Signatures (RSA-PSS, ECDSA, Ed25519)",
            "TLS 1.2/1.3 Protocol Analysis",
            "CryptoPals Sets 1-4 (32 Challenges)"
        ],
        context={
            "Project": "Enigma -- Quantum Security Expert Track",
            "Phase": "2 of 8 -- Classical Cryptography",
            "Research Agents": "7 parallel (A-G)",
            "Foundation": "Phase 1 modular_math.py (665 LOC, 14/14 tests)",
            "Deliverables": "RSA/AES/ECC/SHA-256 + CryptoPals + TLS Analyzer",
            "Classification": "CONFIDENTIAL"
        }
    )

    # Executive Summary
    pdf.page_break()
    pdf.toc_entry(0, "Executive Summary", "sec:summary")
    pdf.label("sec:summary")
    pdf.section("Executive Summary")
    pdf.body(
        "Phase 2 builds directly on Phase 1's modular_math.py (665 lines, 22 functions, "
        "14/14 tests passing). This document compiles research from 7 parallel agents "
        "covering every classical cryptographic system needed for the Enigma roadmap. "
        "The three Phase 2 deliverables are: (1) from-scratch Python implementations of "
        "RSA, AES, ECDH, and SHA-256; (2) CryptoPals Sets 1-4 proving attack capability; "
        "(3) a TLS handshake analyzer tool."
    )
    pdf.spacer(4)

    pdf.gold_box("Phase 2 Deliverables", [
        "1. RSA/AES/ECC/SHA-256 implementations (from scratch, not libraries)",
        "2. CryptoPals Sets 1-4 (32 challenges -- proves BREAKING ability)",
        "3. TLS handshake analyzer (capture + decode real HTTPS)",
    ])
    pdf.spacer(4)

    pdf.cyan_box("Phase 1 Foundation (Already Built)", [
        "extended_gcd, mod_inverse, mod_exp, euler_totient",
        "GFp class (prime field arithmetic -- used by ECC)",
        "GF2n class (GF(2^8) -- used by AES SubBytes/MixColumns)",
        "build_aes_sbox() -- AES S-Box from GF(2^8) inversion",
        "miller_rabin, generate_prime -- used by RSA keygen",
        "tonelli_shanks -- used by ECC point decompression",
        "rsa_crt_decrypt -- CRT-optimized RSA decryption",
    ])
    pdf.spacer(4)

    # Dependency Map
    pdf.toc_entry(0, "Dependency Map", "sec:deps")
    pdf.label("sec:deps")
    pdf.section("Dependency Map")
    pdf.body("How Phase 2 systems depend on Phase 1 and each other:")
    pdf.spacer(4)

    pdf.table(
        headers=["System", "Phase 1 Dependencies", "Phase 2 Dependencies"],
        rows=[
            ["RSA", "generate_prime, euler_totient_pq, mod_inverse, mod_exp, rsa_crt_decrypt", "SHA-256 (for OAEP/PSS)"],
            ["AES", "GF2n, build_aes_sbox, xtime", "None (standalone)"],
            ["ECC", "GFp, mod_inverse, tonelli_shanks", "None (standalone)"],
            ["SHA-256", "None (standalone)", "None"],
            ["HMAC", "None", "SHA-256"],
            ["ECDH", "GFp, mod_inverse", "ECC point multiplication"],
            ["ECDSA", "GFp, mod_inverse", "ECC + SHA-256"],
            ["Ed25519", "None (own curve math)", "SHA-512"],
            ["TLS Analyzer", "None", "ALL of the above"],
            ["CryptoPals", "GF2n, build_aes_sbox", "AES, SHA-1, HMAC, XOR utils"],
        ]
    )
    pdf.spacer(4)

    pdf.green_box("Implementation Order", [
        "1. SHA-256 + HMAC (no deps, needed by everything)",
        "2. AES core (uses Phase 1 GF2n/S-Box)",
        "3. AES modes (CBC, CTR, GCM -- uses AES core)",
        "4. RSA (uses Phase 1 prime gen + SHA-256 for padding)",
        "5. ECC point math (uses Phase 1 GFp)",
        "6. ECDH + ECDSA (uses ECC + SHA-256)",
        "7. CryptoPals Sets 1-4 (uses AES, SHA-1, HMAC)",
        "8. TLS Analyzer (uses all of the above)",
    ])
    pdf.spacer(4)

    # Confidence Matrix
    pdf.toc_entry(0, "Confidence Matrix", "sec:confidence")
    pdf.label("sec:confidence")
    pdf.section("Confidence Matrix")
    pdf.table(
        headers=["Agent", "Topic", "Sources", "Confidence", "Lines"],
        rows=[
            ["A", "RSA", "RFC 8017, FIPS 186-4/5", "VERIFIED", "644"],
            ["B", "AES", "FIPS 197, SP 800-38A/D", "VERIFIED", "853"],
            ["C", "ECC", "SEC 2 v2, FIPS 186-5, RFC 6979", "VERIFIED", "983"],
            ["D", "SHA-256", "FIPS 180-4, RFC 2104/4231", "VERIFIED", "683"],
            ["E", "Signatures", "RFC 8017/8032, FIPS 186-4", "VERIFIED", "919"],
            ["F", "TLS/SSL", "RFC 5246/8446/5869", "VERIFIED", "644"],
            ["G", "CryptoPals", "CryptoPals.com, established attacks", "VERIFIED", "1348"],
        ]
    )
    pdf.spacer(4)

    # Agent Sections
    agents = [
        ("A", "RSA Implementation", "Keygen, PKCS#1 v1.5, OAEP, PSS, attack mitigations"),
        ("B", "AES Implementation", "SubBytes, ShiftRows, MixColumns, key expansion, CBC/CTR/GCM"),
        ("C", "Elliptic Curve Cryptography", "Point math, secp256k1, P-256, ECDH, ECDSA, Montgomery ladder"),
        ("D", "SHA-256 + HMAC", "SHA-256 from scratch, HMAC, SHA-1, Merkle trees, length extension"),
        ("E", "Digital Signatures", "RSA-PSS, ECDSA, Ed25519, X.509 chains, key management"),
        ("F", "TLS/SSL Protocol", "TLS 1.2/1.3 handshake, HKDF, cipher suites, analyzer, PQC detection"),
        ("G", "CryptoPals Sets 1-4", "32 challenges, byte-at-a-time ECB, CBC padding oracle, length extension"),
    ]

    for i, (letter, title, focus) in enumerate(agents, start=4):
        add_agent_section(pdf, letter, title, focus, i)

    # Key Attacks Summary
    pdf.page_break()
    sec_n = 4 + len(agents)
    pdf.toc_entry(0, f"{sec_n}. Critical Attacks (CryptoPals)", "sec:attacks")
    pdf.label("sec:attacks")
    pdf.section(f"{sec_n}. Critical Attacks (CryptoPals)")

    pdf.red_box("Attack 1: Byte-at-a-Time ECB Decryption (Challenge 12)", [
        "Recovers unknown plaintext from ECB oracle, ~256 queries/byte",
        "Exploits deterministic encryption + controlled prefix",
        "The most elegant chosen-plaintext attack",
    ])
    pdf.spacer(4)

    pdf.red_box("Attack 2: CBC Padding Oracle (Challenge 17)", [
        "Decrypts ANY CBC ciphertext with only a padding-validity oracle",
        "~4096 queries per block -- practical against real servers",
        "Most important attack in modern crypto history (POODLE, etc.)",
    ])
    pdf.spacer(4)

    pdf.red_box("Attack 3: SHA-1 Length Extension (Challenge 29)", [
        "Forges MACs without knowing the secret key",
        "Exploits Merkle-Damgard construction (hash(key||msg) is broken)",
        "Why HMAC exists -- HMAC prevents this attack",
    ])
    pdf.spacer(4)

    pdf.render_toc()
    pdf.end_section()
    pdf.save()
    print(f"\nGenerated: {OUTPUT_PATH}")
    print(f"Agents: 7 | Total research lines: ~6,074")


if __name__ == "__main__":
    main()
