"""
ENIGMA (Ψ) — Quantum Security Platform

Full-featured GUI for quantum security analysis, cryptography demos,
and post-quantum migration planning. Built from scratch.

Theme: Deep navy, silver, gold — professional and elegant.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
import json
import time
from datetime import datetime

# Add all phase directories to path
_base = os.path.dirname(os.path.abspath(__file__))
for _phase in ['phase1_math', 'phase2_classical', 'phase3_quantum',
               'phase4_threats', 'phase5_pqc', 'phase6_scanner',
               'phase7_qkd', 'phase8_portfolio']:
    _p = os.path.join(_base, 'phases', _phase)
    if _p not in sys.path and os.path.isdir(_p):
        sys.path.insert(0, _p)

# ============================================================================
# ENIGMA THEME — Navy / Silver / Gold
# ============================================================================

BG = '#0A0E1A'       # Deep navy
BG2 = '#111827'      # Panel background
BG3 = '#1C2333'      # Input/header background
FG = '#E2E8F0'       # Silver-white text
FG2 = '#8892A8'      # Muted silver
ACCENT = '#D4AF37'   # Gold — primary accent
ACCENT2 = '#A89050'  # Muted gold
ICE = '#7EB8DA'      # Ice blue — secondary accent
RED = '#DC4A4A'      # Warm red
ORANGE = '#E8853D'   # Amber
GREEN = '#48BB78'    # Muted green
BLUE = '#5B9BD5'     # Steel blue

# Aliases for backward compat with tab code
CYAN = ICE
PURPLE = ACCENT
GOLD = ACCENT

PSI = '\u03A8'       # Greek capital Psi

FONT = ('Segoe UI', 10)
FONT_BOLD = ('Segoe UI', 10, 'bold')
FONT_BIG = ('Segoe UI', 14, 'bold')
FONT_HUGE = ('Segoe UI', 28, 'bold')
FONT_MONO = ('Consolas', 10)
FONT_MONO_SM = ('Consolas', 9)


class ToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{PSI} ENIGMA")
        self.root.geometry("1200x800")
        self.root.configure(bg=BG)
        self.root.minsize(1000, 650)

        # Set window icon
        ico_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'enigma.ico')
        if os.path.exists(ico_path):
            self.root.iconbitmap(ico_path)

        self._style()
        self._header()

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=True, padx=6, pady=(2, 6))

        self._tab_scanner()
        self._tab_crypto()
        self._tab_mlkem()
        self._tab_quantum()
        self._tab_threat()
        self._tab_qkd()

    # ================================================================
    # STYLES
    # ================================================================
    def _style(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure('.', background=BG, foreground=FG)
        s.configure('TFrame', background=BG)
        s.configure('TLabel', background=BG, foreground=FG, font=FONT)
        s.configure('TButton', background=BG2, foreground=ICE, font=FONT_BOLD, borderwidth=0)
        s.map('TButton', background=[('active', BG3)], foreground=[('active', FG)])
        s.configure('Go.TButton', background=ACCENT, foreground=BG, font=FONT_BOLD)
        s.map('Go.TButton', background=[('active', ACCENT2)], foreground=[('active', BG)])
        s.configure('TNotebook', background=BG, borderwidth=0)
        s.configure('TNotebook.Tab', background=BG2, foreground=FG2, font=FONT_BOLD, padding=[16, 6])
        s.map('TNotebook.Tab', background=[('selected', BG3)], foreground=[('selected', ACCENT)])
        s.configure('TEntry', fieldbackground=BG3, foreground=FG, insertcolor=ACCENT, borderwidth=0)
        s.configure('TCombobox', fieldbackground=BG3, foreground=FG)
        s.configure('TLabelframe', background=BG, foreground=ACCENT)
        s.configure('TLabelframe.Label', background=BG, foreground=ACCENT, font=FONT_BOLD)
        s.configure('Treeview', background=BG2, foreground=FG, fieldbackground=BG2, font=FONT_MONO_SM, borderwidth=0)
        s.configure('Treeview.Heading', background=BG3, foreground=ACCENT, font=FONT_BOLD)
        s.map('Treeview', background=[('selected', '#2A3040')])

    def _header(self):
        h = tk.Frame(self.root, bg=BG2, height=56)
        h.pack(fill='x')
        h.pack_propagate(False)

        # Psi symbol as logo
        tk.Label(h, text=PSI, font=('Times New Roman', 28, 'bold'),
                 fg=ACCENT, bg=BG2).pack(side='left', padx=(16, 4), pady=4)

        # Divider line
        div = tk.Frame(h, bg=ACCENT2, width=1, height=32)
        div.pack(side='left', padx=(4, 12), pady=12)

        # Title
        title_frame = tk.Frame(h, bg=BG2)
        title_frame.pack(side='left', pady=4)
        tk.Label(title_frame, text="ENIGMA", font=('Segoe UI', 16, 'bold'),
                 fg=FG, bg=BG2).pack(anchor='w')
        tk.Label(title_frame, text="Quantum Security Platform", font=('Segoe UI', 8),
                 fg=FG2, bg=BG2).pack(anchor='w')

        # Status
        self.status = tk.Label(h, text="Ready", font=('Segoe UI', 9), fg=GREEN, bg=BG2)
        self.status.pack(side='right', padx=16, pady=4)

        # Version badge
        tk.Label(h, text="v2.0", font=('Segoe UI', 8), fg=FG2, bg=BG2).pack(side='right')

    def _set_status(self, t, c=GREEN):
        self.status.configure(text=t, fg=c)

    def _make_output(self, parent):
        out = scrolledtext.ScrolledText(parent, bg=BG2, fg=FG, font=FONT_MONO,
            insertbackground=ACCENT, borderwidth=0, wrap='word',
            selectbackground='#2A3040', selectforeground=FG)
        out.pack(fill='both', expand=True, padx=8, pady=4)
        return out

    def _run_bg(self, fn, callback):
        def wrapper():
            try:
                result = fn()
                self.root.after(0, lambda: callback(result))
            except Exception as e:
                self.root.after(0, lambda: self._show_error(str(e)))
        threading.Thread(target=wrapper, daemon=True).start()

    def _show_error(self, msg):
        self._set_status("Error", RED)
        messagebox.showerror("Error", msg)

    # ================================================================
    # TAB 1: PQC SCANNER
    # ================================================================
    def _tab_scanner(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  PQC Scanner  ")

        ctrl = tk.Frame(tab, bg=BG)
        ctrl.pack(fill='x', padx=8, pady=6)
        tk.Label(ctrl, text="Path:", bg=BG, fg=FG, font=FONT).pack(side='left')
        self.scan_path = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self.scan_path, width=55).pack(side='left', padx=4, ipady=2)
        ttk.Button(ctrl, text="Browse", command=self._scan_browse).pack(side='left', padx=2)
        ttk.Button(ctrl, text="Scan", style='Go.TButton', command=self._scan_run).pack(side='left', padx=6)
        ttk.Button(ctrl, text="Export HTML", command=lambda: self._scan_export('html')).pack(side='right', padx=2)
        ttk.Button(ctrl, text="Export SARIF", command=lambda: self._scan_export('sarif')).pack(side='right', padx=2)

        # Dashboard
        dash = tk.Frame(tab, bg=BG)
        dash.pack(fill='x', padx=8)
        self.scan_score = tk.Label(dash, text="--", font=FONT_HUGE, fg=ICE, bg=BG)
        self.scan_score.pack(side='left')
        tk.Label(dash, text=" Risk", font=FONT, fg=FG2, bg=BG).pack(side='left', padx=(0, 20))
        self.scan_count = tk.Label(dash, text="--", font=FONT_BIG, fg=ACCENT, bg=BG)
        self.scan_count.pack(side='left')
        tk.Label(dash, text=" Findings", font=FONT, fg=FG2, bg=BG).pack(side='left')

        # Results tree
        cols = ('sev', 'algo', 'file', 'line', 'fix')
        self.scan_tree = ttk.Treeview(tab, columns=cols, show='headings', height=16)
        for c, w, t in [('sev', 70, 'Sev'), ('algo', 90, 'Algorithm'), ('file', 320, 'File'),
                        ('line', 45, 'Line'), ('fix', 280, 'PQC Replacement')]:
            self.scan_tree.heading(c, text=t)
            self.scan_tree.column(c, width=w)
        self.scan_tree.pack(fill='both', expand=True, padx=8, pady=4)
        for sev, col in [('CRITICAL', RED), ('HIGH', ORANGE), ('MEDIUM', '#D4AF37'), ('LOW', BLUE), ('INFO', FG2)]:
            self.scan_tree.tag_configure(sev, foreground=col)
        self._scan_result = None

    def _scan_browse(self):
        p = filedialog.askdirectory()
        if p: self.scan_path.set(p)

    def _scan_run(self):
        path = self.scan_path.get().strip()
        if not path: return messagebox.showwarning("", "Enter a path to scan.")
        self._set_status("Scanning...", GOLD)
        from pqc_scanner import PQCScanner
        def scan():
            s = PQCScanner()
            return s.scan(path)
        def done(r):
            r.compute_summary()
            self._scan_result = r
            sc = r.risk_score
            self.scan_score.configure(text=str(sc), fg=RED if sc > 50 else GREEN)
            self.scan_count.configure(text=str(len(r.findings)))
            self.scan_tree.delete(*self.scan_tree.get_children())
            for f in r.findings:
                rel = os.path.relpath(f.file, r.scan_path) if r.scan_path in f.file else f.file
                self.scan_tree.insert('', 'end', values=(f.severity.value, f.algorithm, rel, f.line, f.pqc_replacement), tags=(f.severity.value,))
            self._set_status(f"{len(r.findings)} findings", GREEN if sc < 20 else RED)
        self._run_bg(scan, done)

    def _scan_export(self, fmt):
        if not self._scan_result: return messagebox.showinfo("", "Run a scan first.")
        from pqc_scanner import format_html_report, format_sarif_report
        ext = '.html' if fmt == 'html' else '.sarif'
        p = filedialog.asksaveasfilename(defaultextension=ext, initialfile=f'pqc_report{ext}')
        if not p: return
        fn = format_html_report if fmt == 'html' else format_sarif_report
        with open(p, 'w', encoding='utf-8') as f: f.write(fn(self._scan_result))
        self._set_status(f"Exported {os.path.basename(p)}", GREEN)
        if fmt == 'html': os.startfile(p)

    # ================================================================
    # TAB 2: CRYPTO LAB
    # ================================================================
    def _tab_crypto(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Crypto Lab  ")

        ctrl = tk.Frame(tab, bg=BG)
        ctrl.pack(fill='x', padx=8, pady=6)

        self.crypto_algo = tk.StringVar(value='RSA')
        tk.Label(ctrl, text="Algorithm:", bg=BG, fg=FG).pack(side='left')
        ttk.Combobox(ctrl, textvariable=self.crypto_algo, width=14, state='readonly',
            values=['RSA', 'AES-GCM', 'ECDSA', 'Ed25519', 'SHA-256']).pack(side='left', padx=4)
        ttk.Button(ctrl, text="Run Demo", style='Go.TButton', command=self._crypto_run).pack(side='left', padx=6)

        self.crypto_out = self._make_output(tab)
        self.crypto_out.insert('end', "Select an algorithm and click Run Demo.\n\n"
            "Each demo generates keys, encrypts/signs, decrypts/verifies,\n"
            "and shows all intermediate values — built from scratch, no libraries.\n")

    def _crypto_run(self):
        algo = self.crypto_algo.get()
        self._set_status(f"Running {algo}...", GOLD)
        self.crypto_out.delete('1.0', 'end')

        def run():
            lines = []
            if algo == 'RSA':
                from rsa import generate_rsa_keypair, rsa_encrypt_oaep, rsa_decrypt_oaep, rsa_sign, rsa_verify
                t0 = time.perf_counter()
                pub, priv = generate_rsa_keypair(bits=1024)
                kg_ms = (time.perf_counter() - t0) * 1000
                lines.append(f"=== RSA-1024 (from scratch) ===\n")
                lines.append(f"Keygen: {kg_ms:.0f}ms")
                lines.append(f"n = {pub.n}")
                lines.append(f"e = {pub.e}")
                lines.append(f"d = {priv.d}\n")
                msg = b"Hello RSA from Enigma!"
                ct = rsa_encrypt_oaep(msg, pub)
                pt = rsa_decrypt_oaep(ct, priv)
                lines.append(f"Plaintext:  {msg}")
                lines.append(f"Ciphertext: {ct[:32].hex()}... ({len(ct)} bytes)")
                lines.append(f"Decrypted:  {pt}")
                lines.append(f"Match: {pt == msg}\n")
                sig = rsa_sign(msg, priv)
                ok = rsa_verify(msg, sig, pub)
                lines.append(f"Signature:  {sig[:32].hex()}... ({len(sig)} bytes)")
                lines.append(f"Verified:   {ok}")

            elif algo == 'AES-GCM':
                from aes import aes_gcm_encrypt, aes_gcm_decrypt
                key = os.urandom(32)
                nonce = os.urandom(12)
                aad = b"authenticated header"
                msg = b"Secret message encrypted with AES-256-GCM!"
                lines.append("=== AES-256-GCM (from scratch) ===\n")
                lines.append(f"Key:   {key.hex()}")
                lines.append(f"Nonce: {nonce.hex()}")
                lines.append(f"AAD:   {aad}\n")
                t0 = time.perf_counter()
                ct, tag = aes_gcm_encrypt(msg, key, nonce, aad)
                enc_ms = (time.perf_counter() - t0) * 1000
                lines.append(f"Plaintext:  {msg}")
                lines.append(f"Ciphertext: {ct.hex()}")
                lines.append(f"Auth Tag:   {tag.hex()}")
                lines.append(f"Encrypt:    {enc_ms:.1f}ms\n")
                pt = aes_gcm_decrypt(ct, key, nonce, tag, aad)
                lines.append(f"Decrypted:  {pt}")
                lines.append(f"Match: {pt == msg}\n")
                lines.append("Tamper test:")
                try:
                    bad = bytearray(ct); bad[0] ^= 0xFF
                    aes_gcm_decrypt(bytes(bad), key, nonce, tag, aad)
                    lines.append("  FAIL: tampered ciphertext accepted!")
                except ValueError:
                    lines.append("  PASS: tampered ciphertext rejected (auth tag mismatch)")

            elif algo == 'ECDSA':
                from ecc import ecdh_keygen, ecdsa_sign, ecdsa_verify, SECP256K1
                t0 = time.perf_counter()
                priv, pub = ecdh_keygen(SECP256K1)
                kg_ms = (time.perf_counter() - t0) * 1000
                lines.append("=== ECDSA secp256k1 (from scratch, RFC 6979) ===\n")
                lines.append(f"Keygen: {kg_ms:.0f}ms")
                lines.append(f"Private: {priv}")
                lines.append(f"Public:  ({pub[0]}, {pub[1]})\n")
                msg = b"Sign this with ECDSA!"
                r, s = ecdsa_sign(msg, priv, SECP256K1)
                ok = ecdsa_verify(msg, (r, s), pub, SECP256K1)
                lines.append(f"Message: {msg}")
                lines.append(f"r = {r}")
                lines.append(f"s = {s}")
                lines.append(f"Verified: {ok}\n")
                ok2 = ecdsa_verify(b"wrong msg", (r, s), pub, SECP256K1)
                lines.append(f"Wrong message verify: {ok2} (expected False)")

            elif algo == 'Ed25519':
                from ed25519 import keygen, sign, verify
                t0 = time.perf_counter()
                seed, pub = keygen()
                kg_ms = (time.perf_counter() - t0) * 1000
                lines.append("=== Ed25519 (RFC 8032, from scratch) ===\n")
                lines.append(f"Keygen: {kg_ms:.0f}ms")
                lines.append(f"Seed:   {seed.hex()}")
                lines.append(f"Public: {pub.hex()}\n")
                msg = b"Ed25519 signature demo!"
                sig = sign(seed, msg)
                ok = verify(pub, msg, sig)
                lines.append(f"Message:   {msg}")
                lines.append(f"Signature: {sig.hex()}")
                lines.append(f"Verified:  {ok}\n")
                ok2 = verify(pub, b"tampered", sig)
                lines.append(f"Wrong message: {ok2} (expected False)")

            elif algo == 'SHA-256':
                from sha256 import sha256_hex, sha1_hex, hmac_sha256
                lines.append("=== SHA-256 / SHA-1 / HMAC (from scratch) ===\n")
                for msg in [b"", b"abc", b"Hello Enigma!"]:
                    lines.append(f'SHA-256("{msg.decode()}")')
                    lines.append(f"  = {sha256_hex(msg)}\n")
                lines.append(f'SHA-1("abc") = {sha1_hex(b"abc")}\n')
                key = b"secret key"
                data = b"message to authenticate"
                mac = hmac_sha256(key, data)
                lines.append(f"HMAC-SHA256(key={key}, data={data})")
                lines.append(f"  = {mac.hex()}")

            return "\n".join(lines)

        def done(text):
            self.crypto_out.insert('end', text)
            self._set_status("Demo complete", GREEN)
        self._run_bg(run, done)

    # ================================================================
    # TAB 3: ML-KEM
    # ================================================================
    def _tab_mlkem(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  ML-KEM  ")

        ctrl = tk.Frame(tab, bg=BG)
        ctrl.pack(fill='x', padx=8, pady=6)
        tk.Label(ctrl, text="Security Level:", bg=BG, fg=FG).pack(side='left')
        self.kem_level = tk.StringVar(value='768')
        ttk.Combobox(ctrl, textvariable=self.kem_level, width=6, state='readonly',
            values=['512', '768', '1024']).pack(side='left', padx=4)
        ttk.Button(ctrl, text="Run KEM", style='Go.TButton', command=self._kem_run).pack(side='left', padx=6)

        self.kem_out = self._make_output(tab)
        self.kem_out.insert('end', "ML-KEM (FIPS 203) — Post-Quantum Key Encapsulation\n\n"
            "Select a security level and click Run KEM.\n"
            "Demonstrates: KeyGen -> Encaps -> Decaps -> Shared secret match.\n\n"
            "  ML-KEM-512:  128-bit security, 800-byte public key\n"
            "  ML-KEM-768:  192-bit security, 1184-byte public key\n"
            "  ML-KEM-1024: 256-bit security, 1568-byte public key\n")

    def _kem_run(self):
        level = int(self.kem_level.get())
        self._set_status(f"Running ML-KEM-{level}...", GOLD)
        self.kem_out.delete('1.0', 'end')

        def run():
            from ml_kem import ml_kem_keygen, ml_kem_encaps, ml_kem_decaps, ml_kem_serialize_ek, ml_kem_serialize_dk, KEY_SIZES
            lines = [f"=== ML-KEM-{level} (FIPS 203, from lattice math) ===\n"]

            t0 = time.perf_counter()
            ek, dk = ml_kem_keygen(level)
            kg_ms = (time.perf_counter() - t0) * 1000
            ek_bytes = ml_kem_serialize_ek(ek, level)
            dk_bytes = ml_kem_serialize_dk(dk, level)
            lines.append(f"KeyGen: {kg_ms:.0f}ms")
            lines.append(f"Public key:  {len(ek_bytes)} bytes (expected {KEY_SIZES[level]['ek']})")
            lines.append(f"Private key: {len(dk_bytes)} bytes (expected {KEY_SIZES[level]['dk']})")
            lines.append(f"Public key (first 64 bytes): {ek_bytes[:64].hex()}...\n")

            t0 = time.perf_counter()
            ct, K_alice = ml_kem_encaps(ek, level)
            enc_ms = (time.perf_counter() - t0) * 1000
            lines.append(f"Encaps: {enc_ms:.0f}ms")
            lines.append(f"Ciphertext: {len(ct)} bytes")
            lines.append(f"Shared secret (Alice): {K_alice.hex()}\n")

            t0 = time.perf_counter()
            K_bob = ml_kem_decaps(dk, ct, level)
            dec_ms = (time.perf_counter() - t0) * 1000
            lines.append(f"Decaps: {dec_ms:.0f}ms")
            lines.append(f"Shared secret (Bob):   {K_bob.hex()}\n")
            lines.append(f"Secrets match: {K_alice == K_bob}")
            lines.append(f"Secret length: {len(K_alice) * 8} bits (256-bit AES key)\n")

            # Tamper test
            bad_ct = bytearray(ct); bad_ct[0] ^= 0xFF
            K_bad = ml_kem_decaps(dk, bytes(bad_ct), level)
            lines.append("Implicit rejection test:")
            lines.append(f"  Tampered ciphertext decaps to: {K_bad.hex()}")
            lines.append(f"  Matches real secret: {K_bad == K_alice} (expected False)")
            lines.append(f"  (FO transform returns pseudorandom key on failure)")

            return "\n".join(lines)

        def done(text):
            self.kem_out.insert('end', text)
            self._set_status("ML-KEM complete", GREEN)
        self._run_bg(run, done)

    # ================================================================
    # TAB 4: QUANTUM CIRCUITS
    # ================================================================
    def _tab_quantum(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Quantum  ")

        ctrl = tk.Frame(tab, bg=BG)
        ctrl.pack(fill='x', padx=8, pady=6)
        tk.Label(ctrl, text="Circuit:", bg=BG, fg=FG).pack(side='left')
        self.qc_choice = tk.StringVar(value='Bell State')
        ttk.Combobox(ctrl, textvariable=self.qc_choice, width=22, state='readonly',
            values=['Bell State', 'GHZ (3-qubit)', 'Grover (target=11)',
                    'Bernstein-Vazirani (s=101)', 'Superposition']).pack(side='left', padx=4)
        tk.Label(ctrl, text="Shots:", bg=BG, fg=FG).pack(side='left', padx=(8, 2))
        self.qc_shots = tk.StringVar(value='2048')
        ttk.Entry(ctrl, textvariable=self.qc_shots, width=6).pack(side='left', ipady=2)
        self.qc_noise = tk.BooleanVar(value=True)
        tk.Checkbutton(ctrl, text="Noise", variable=self.qc_noise, bg=BG, fg=FG,
            selectcolor=BG3, activebackground=BG).pack(side='left', padx=6)
        ttk.Button(ctrl, text="Run Circuit", style='Go.TButton', command=self._qc_run).pack(side='left', padx=6)

        self.qc_out = self._make_output(tab)
        self.qc_out.insert('end', "Run quantum circuits on Qiskit Aer simulator.\n\n"
            "Enable 'Noise' for IBM Eagle/Heron noise model (realistic errors).\n"
            "Disable for ideal (noiseless) simulation.\n")

    def _qc_run(self):
        name = self.qc_choice.get()
        shots = int(self.qc_shots.get())
        noise = self.qc_noise.get()
        self._set_status(f"Running {name}...", GOLD)
        self.qc_out.delete('1.0', 'end')

        def run():
            from quantum_circuits import (circuit_bell_state, circuit_ghz, circuit_grover,
                circuit_bernstein_vazirani, circuit_superposition)
            from qiskit import transpile
            from qiskit_aer import AerSimulator

            circuit_map = {
                'Bell State': (circuit_bell_state, ['00', '11']),
                'GHZ (3-qubit)': (circuit_ghz, ['000', '111']),
                'Grover (target=11)': (lambda: circuit_grover('11'), ['11']),
                'Bernstein-Vazirani (s=101)': (lambda: circuit_bernstein_vazirani('101'), ['101']),
                'Superposition': (circuit_superposition, ['0', '1']),
            }
            fn, expected = circuit_map[name]
            qc = fn()

            if noise:
                from quantum_hardware import build_realistic_noise_model
                backend = AerSimulator(noise_model=build_realistic_noise_model())
                mode = "NOISY (IBM Eagle/Heron model)"
            else:
                backend = AerSimulator()
                mode = "IDEAL (noiseless)"

            t0 = time.perf_counter()
            tc = transpile(qc, backend)
            job = backend.run(tc, shots=shots)
            result = job.result()
            elapsed = (time.perf_counter() - t0) * 1000
            counts = result.get_counts()

            lines = [f"=== {name} — {mode} ===\n"]
            lines.append(f"Qubits: {qc.num_qubits} | Shots: {shots} | Time: {elapsed:.0f}ms\n")
            lines.append("Results:")

            sorted_counts = sorted(counts.items(), key=lambda x: -x[1])
            for outcome, count in sorted_counts:
                pct = count / shots * 100
                bar = "#" * int(pct / 2)
                marker = " <--" if outcome in expected else ""
                lines.append(f"  |{outcome}> {count:5d} ({pct:5.1f}%) {bar}{marker}")

            total_exp = sum(counts.get(o, 0) for o in expected)
            lines.append(f"\nSuccess rate: {total_exp/shots:.1%}")
            lines.append(f"Expected outcomes: {expected}")

            return "\n".join(lines)

        def done(text):
            self.qc_out.insert('end', text)
            self._set_status("Circuit complete", GREEN)
        self._run_bg(run, done)

    # ================================================================
    # TAB 5: THREAT ASSESSMENT
    # ================================================================
    def _tab_threat(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  Threats  ")

        # Mosca's inequality calculator
        frame = ttk.LabelFrame(tab, text="Mosca's Inequality Calculator")
        frame.pack(fill='x', padx=8, pady=6)
        inner = tk.Frame(frame, bg=BG)
        inner.pack(padx=8, pady=6)

        tk.Label(inner, text="Data shelf life (years):", bg=BG, fg=FG).grid(row=0, column=0, sticky='e', padx=4)
        self.mosca_shelf = tk.StringVar(value='10')
        ttk.Entry(inner, textvariable=self.mosca_shelf, width=6).grid(row=0, column=1, padx=4, ipady=2)

        tk.Label(inner, text="Migration time (years):", bg=BG, fg=FG).grid(row=1, column=0, sticky='e', padx=4)
        self.mosca_migrate = tk.StringVar(value='3')
        ttk.Entry(inner, textvariable=self.mosca_migrate, width=6).grid(row=1, column=1, padx=4, ipady=2)

        tk.Label(inner, text="CRQC timeline (years):", bg=BG, fg=FG).grid(row=2, column=0, sticky='e', padx=4)
        self.mosca_crqc = tk.StringVar(value='15')
        ttk.Entry(inner, textvariable=self.mosca_crqc, width=6).grid(row=2, column=1, padx=4, ipady=2)

        ttk.Button(inner, text="Calculate", style='Go.TButton', command=self._threat_calc).grid(row=0, column=2, rowspan=3, padx=12)

        self.threat_out = self._make_output(tab)
        self.threat_out.insert('end', "Mosca's Inequality: X + Y > Z means MIGRATE NOW\n\n"
            "  X = How long must data remain secret (shelf life)\n"
            "  Y = How long migration will take\n"
            "  Z = When will a cryptographically relevant quantum computer exist\n\n"
            "If X + Y > Z, an adversary can harvest your encrypted data today\n"
            "and decrypt it when quantum computers arrive (HNDL attack).\n")

    def _threat_calc(self):
        x = int(self.mosca_shelf.get())
        y = int(self.mosca_migrate.get())
        z = int(self.mosca_crqc.get())
        self.threat_out.delete('1.0', 'end')

        from quantum_threats import moscas_inequality, generate_threat_report
        result = moscas_inequality(x, y, z)

        lines = [f"=== Mosca's Inequality Analysis ===\n"]
        lines.append(f"  Data shelf life (X): {x} years")
        lines.append(f"  Migration time (Y):  {y} years")
        lines.append(f"  CRQC timeline (Z):   {z} years\n")
        lines.append(f"  X + Y = {x + y}")
        lines.append(f"  Z     = {z}\n")

        if result['is_urgent']:
            lines.append(f"  RESULT: URGENT — X + Y ({x+y}) > Z ({z})")
            lines.append(f"  {result['recommendation']}")
            lines.append(f"\n  You are {x+y-z} years BEHIND schedule.")
            lines.append(f"  Start PQC migration IMMEDIATELY.")
        else:
            lines.append(f"  RESULT: SAFE — X + Y ({x+y}) <= Z ({z})")
            lines.append(f"  Margin: {result['margin_years']} years")
            lines.append(f"  {result['recommendation']}")

        lines.append(f"\n{'='*50}\n")
        lines.append(generate_threat_report("Your Organization", x, y, z))
        self.threat_out.insert('end', "\n".join(lines))
        self._set_status("URGENT" if result['is_urgent'] else "Safe", RED if result['is_urgent'] else GREEN)

    # ================================================================
    # TAB 6: QKD SIMULATOR
    # ================================================================
    def _tab_qkd(self):
        tab = ttk.Frame(self.nb)
        self.nb.add(tab, text="  QKD  ")

        ctrl = tk.Frame(tab, bg=BG)
        ctrl.pack(fill='x', padx=8, pady=6)
        tk.Label(ctrl, text="Protocol:", bg=BG, fg=FG).pack(side='left')
        self.qkd_proto = tk.StringVar(value='BB84')
        ttk.Combobox(ctrl, textvariable=self.qkd_proto, width=8, state='readonly',
            values=['BB84', 'E91']).pack(side='left', padx=4)
        tk.Label(ctrl, text="Qubits:", bg=BG, fg=FG).pack(side='left', padx=(8, 2))
        self.qkd_n = tk.StringVar(value='500')
        ttk.Entry(ctrl, textvariable=self.qkd_n, width=6).pack(side='left', ipady=2)
        self.qkd_eve = tk.BooleanVar(value=False)
        tk.Checkbutton(ctrl, text="Eavesdropper (Eve)", variable=self.qkd_eve, bg=BG, fg=FG,
            selectcolor=BG3, activebackground=BG).pack(side='left', padx=8)
        ttk.Button(ctrl, text="Simulate", style='Go.TButton', command=self._qkd_run).pack(side='left', padx=6)

        self.qkd_out = self._make_output(tab)
        self.qkd_out.insert('end', "Quantum Key Distribution Simulator\n\n"
            "BB84: Bennett-Brassard 1984 — uses polarized photons\n"
            "E91: Ekert 1991 — uses entangled pairs + Bell inequality\n\n"
            "Toggle 'Eavesdropper' to see how Eve's intercept-resend\n"
            "attack is detected via QBER (Quantum Bit Error Rate).\n")

    def _qkd_run(self):
        proto = self.qkd_proto.get()
        n = int(self.qkd_n.get())
        eve = self.qkd_eve.get()
        self._set_status(f"Simulating {proto}...", GOLD)
        self.qkd_out.delete('1.0', 'end')

        def run():
            lines = []
            if proto == 'BB84':
                from qkd_protocols import bb84_simulate
                r = bb84_simulate(n_qubits=n, eve_present=eve)
                lines.append(f"=== BB84 Protocol ({'WITH Eve' if eve else 'NO Eve'}) ===\n")
                lines.append(f"Qubits sent:     {r.n_qubits}")
                lines.append(f"Matching bases:  {len(r.matching_indices)} ({len(r.matching_indices)/n:.0%} sifted)")
                lines.append(f"Final key bits:  {r.key_length}")
                lines.append(f"QBER:            {r.qber:.1%}")
                lines.append(f"Eve detected:    {r.eavesdropper_detected}\n")
                if eve:
                    lines.append("Eve performed intercept-resend attack.")
                    lines.append(f"QBER = {r.qber:.1%} (threshold: 11%)")
                    if r.eavesdropper_detected:
                        lines.append("DETECTED! Key discarded. Protocol secure.")
                    else:
                        lines.append("NOT detected (unlikely — try more qubits)")
                else:
                    lines.append("No eavesdropper. QBER should be ~0%.")
                    lines.append(f"Secure key generated: {r.key_length} bits")
                if r.key_length > 0:
                    key_preview = ''.join(str(b) for b in r.sifted_key_alice[:32])
                    lines.append(f"\nKey preview (first 32 bits): {key_preview}...")
            else:
                from qkd_protocols import e91_simulate
                r = e91_simulate(n_pairs=n)
                lines.append(f"=== E91 Protocol ({n} entangled pairs) ===\n")
                lines.append(f"CHSH value:  {r.chsh_value:.4f}")
                lines.append(f"Classical bound: 2.0")
                lines.append(f"Quantum max:     2.828 (2*sqrt(2))")
                lines.append(f"Key bits:    {r.key_length}\n")
                if r.chsh_value > 2.0:
                    lines.append(f"CHSH = {r.chsh_value:.2f} > 2.0: QUANTUM CORRELATIONS CONFIRMED")
                    lines.append("Bell inequality violated — entanglement is real.")
                    lines.append("No local hidden variable model can explain this.")
                else:
                    lines.append(f"CHSH = {r.chsh_value:.2f} <= 2.0: classical correlations only")
                    lines.append("Possible eavesdropper — try more pairs.")

            return "\n".join(lines)

        def done(text):
            self.qkd_out.insert('end', text)
            self._set_status("QKD complete", GREEN)
        self._run_bg(run, done)


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    root = tk.Tk()
    app = ToolkitApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()
