"""
Enigma — pqc-scanner GUI
Post-Quantum Cryptography Vulnerability Scanner

Standalone dark-themed GUI application. Scans codebases, TLS endpoints,
and certificates for quantum-vulnerable cryptography.

Bifrost theme: deep purple/cyan on dark background.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
import json
from datetime import datetime

# Add scanner to path
_scanner_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'phases', 'phase6_scanner')
if _scanner_dir not in sys.path:
    sys.path.insert(0, _scanner_dir)

from pqc_scanner import (
    PQCScanner, ScanResult, Severity,
    format_text_report, format_json_report, format_html_report,
    format_sarif_report, scan_certificate_file, scan_tls_endpoint,
    scan_certificates_in_path,
)

# ============================================================================
# BIFROST THEME COLORS
# ============================================================================

BG_DARK = '#0D0D1A'
BG_PANEL = '#1A1A2E'
BG_INPUT = '#16213E'
FG_WHITE = '#E8E8E8'
FG_GRAY = '#888899'
CYAN = '#00D4AA'
PURPLE = '#9B59B6'
GOLD = '#F1C40F'
RED = '#E74C3C'
ORANGE = '#FF8800'
YELLOW = '#FFCC00'
GREEN = '#2ECC71'
BLUE = '#3498DB'

SEVERITY_COLORS = {
    'CRITICAL': RED,
    'HIGH': ORANGE,
    'MEDIUM': YELLOW,
    'LOW': BLUE,
    'INFO': FG_GRAY,
}


# ============================================================================
# MAIN APPLICATION
# ============================================================================

class PQCScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("pqc-scanner // Enigma")
        self.root.geometry("1100x750")
        self.root.configure(bg=BG_DARK)
        self.root.minsize(900, 600)

        self.scanner = PQCScanner()
        self.last_result = None
        self.last_cert_findings = None

        self._configure_styles()
        self._build_ui()

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure('.', background=BG_DARK, foreground=FG_WHITE)
        style.configure('TFrame', background=BG_DARK)
        style.configure('TLabel', background=BG_DARK, foreground=FG_WHITE, font=('Segoe UI', 10))
        style.configure('TButton', background=BG_PANEL, foreground=CYAN,
                        font=('Segoe UI', 10, 'bold'), borderwidth=1, relief='flat')
        style.map('TButton',
                  background=[('active', BG_INPUT), ('pressed', PURPLE)],
                  foreground=[('active', FG_WHITE)])
        style.configure('Accent.TButton', background=PURPLE, foreground=FG_WHITE)
        style.map('Accent.TButton',
                  background=[('active', '#8E44AD'), ('pressed', CYAN)])
        style.configure('TNotebook', background=BG_DARK, borderwidth=0)
        style.configure('TNotebook.Tab', background=BG_PANEL, foreground=FG_GRAY,
                        font=('Segoe UI', 10, 'bold'), padding=[16, 6])
        style.map('TNotebook.Tab',
                  background=[('selected', BG_INPUT)],
                  foreground=[('selected', CYAN)])
        style.configure('TEntry', fieldbackground=BG_INPUT, foreground=FG_WHITE,
                        insertcolor=CYAN, borderwidth=1, relief='flat')
        style.configure('TLabelframe', background=BG_DARK, foreground=PURPLE)
        style.configure('TLabelframe.Label', background=BG_DARK, foreground=PURPLE,
                        font=('Segoe UI', 10, 'bold'))
        style.configure('Treeview', background=BG_PANEL, foreground=FG_WHITE,
                        fieldbackground=BG_PANEL, borderwidth=0, font=('Segoe UI', 9))
        style.configure('Treeview.Heading', background=BG_INPUT, foreground=CYAN,
                        font=('Segoe UI', 9, 'bold'))
        style.map('Treeview', background=[('selected', PURPLE)])

    def _build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG_PANEL, height=60)
        header.pack(fill='x')
        header.pack_propagate(False)

        tk.Label(header, text="pqc-scanner", font=('Segoe UI', 18, 'bold'),
                 fg=CYAN, bg=BG_PANEL).pack(side='left', padx=16, pady=10)
        tk.Label(header, text="Post-Quantum Cryptography Vulnerability Scanner",
                 font=('Segoe UI', 10), fg=FG_GRAY, bg=BG_PANEL).pack(side='left', pady=10)

        self.status_label = tk.Label(header, text="Ready", font=('Segoe UI', 10),
                                     fg=GREEN, bg=BG_PANEL)
        self.status_label.pack(side='right', padx=16, pady=10)

        # Notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=8, pady=(4, 8))

        self._build_code_scan_tab()
        self._build_tls_scan_tab()
        self._build_cert_scan_tab()

    # ================================================================
    # TAB 1: CODE SCAN
    # ================================================================

    def _build_code_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Code Scan  ")

        # Controls
        controls = tk.Frame(tab, bg=BG_DARK)
        controls.pack(fill='x', padx=12, pady=8)

        tk.Label(controls, text="Path:", font=('Segoe UI', 10),
                 fg=FG_WHITE, bg=BG_DARK).pack(side='left')

        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(controls, textvariable=self.path_var, width=60)
        path_entry.pack(side='left', padx=(6, 4), ipady=3)

        ttk.Button(controls, text="Browse", command=self._browse_path).pack(side='left', padx=2)
        ttk.Button(controls, text="Scan", style='Accent.TButton',
                   command=self._run_code_scan).pack(side='left', padx=(8, 4))

        # Severity filter
        tk.Label(controls, text="Min:", font=('Segoe UI', 9),
                 fg=FG_GRAY, bg=BG_DARK).pack(side='left', padx=(12, 2))
        self.severity_var = tk.StringVar(value='LOW')
        sev_menu = ttk.Combobox(controls, textvariable=self.severity_var, width=8,
                                values=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
                                state='readonly')
        sev_menu.pack(side='left')

        # Export buttons
        ttk.Button(controls, text="Export HTML", command=lambda: self._export('html')).pack(side='right', padx=2)
        ttk.Button(controls, text="Export SARIF", command=lambda: self._export('sarif')).pack(side='right', padx=2)
        ttk.Button(controls, text="Export JSON", command=lambda: self._export('json')).pack(side='right', padx=2)

        # Dashboard
        dash = tk.Frame(tab, bg=BG_DARK)
        dash.pack(fill='x', padx=12, pady=(0, 4))

        self.risk_label = tk.Label(dash, text="--", font=('Segoe UI', 36, 'bold'),
                                    fg=CYAN, bg=BG_DARK)
        self.risk_label.pack(side='left', padx=(0, 4))
        tk.Label(dash, text="Risk\nScore", font=('Segoe UI', 9),
                 fg=FG_GRAY, bg=BG_DARK).pack(side='left', padx=(0, 20))

        self.findings_label = tk.Label(dash, text="--", font=('Segoe UI', 24, 'bold'),
                                        fg=PURPLE, bg=BG_DARK)
        self.findings_label.pack(side='left', padx=(0, 4))
        tk.Label(dash, text="Findings", font=('Segoe UI', 9),
                 fg=FG_GRAY, bg=BG_DARK).pack(side='left', padx=(0, 20))

        self.files_label = tk.Label(dash, text="--", font=('Segoe UI', 24, 'bold'),
                                     fg=GOLD, bg=BG_DARK)
        self.files_label.pack(side='left', padx=(0, 4))
        tk.Label(dash, text="Files", font=('Segoe UI', 9),
                 fg=FG_GRAY, bg=BG_DARK).pack(side='left', padx=(0, 20))

        # Severity badges
        self.sev_frame = tk.Frame(dash, bg=BG_DARK)
        self.sev_frame.pack(side='right', padx=8)
        self.sev_labels = {}
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            f = tk.Frame(self.sev_frame, bg=BG_DARK)
            f.pack(side='left', padx=6)
            count_lbl = tk.Label(f, text="0", font=('Segoe UI', 14, 'bold'),
                                  fg=SEVERITY_COLORS[sev], bg=BG_DARK)
            count_lbl.pack()
            tk.Label(f, text=sev[:4], font=('Segoe UI', 7),
                     fg=FG_GRAY, bg=BG_DARK).pack()
            self.sev_labels[sev] = count_lbl

        # Results tree
        tree_frame = tk.Frame(tab, bg=BG_DARK)
        tree_frame.pack(fill='both', expand=True, padx=12, pady=(0, 8))

        columns = ('severity', 'id', 'algorithm', 'file', 'line', 'replacement')
        self.tree = ttk.Treeview(tree_frame, columns=columns, show='headings', height=18)
        self.tree.heading('severity', text='Severity')
        self.tree.heading('id', text='ID')
        self.tree.heading('algorithm', text='Algorithm')
        self.tree.heading('file', text='File')
        self.tree.heading('line', text='Line')
        self.tree.heading('replacement', text='PQC Replacement')

        self.tree.column('severity', width=80, minwidth=60)
        self.tree.column('id', width=80, minwidth=60)
        self.tree.column('algorithm', width=100, minwidth=70)
        self.tree.column('file', width=300, minwidth=150)
        self.tree.column('line', width=50, minwidth=40)
        self.tree.column('replacement', width=250, minwidth=150)

        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')

        # Tag colors for severity
        self.tree.tag_configure('CRITICAL', foreground=RED)
        self.tree.tag_configure('HIGH', foreground=ORANGE)
        self.tree.tag_configure('MEDIUM', foreground=YELLOW)
        self.tree.tag_configure('LOW', foreground=BLUE)
        self.tree.tag_configure('INFO', foreground=FG_GRAY)

    # ================================================================
    # TAB 2: TLS SCAN
    # ================================================================

    def _build_tls_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  TLS Scan  ")

        controls = tk.Frame(tab, bg=BG_DARK)
        controls.pack(fill='x', padx=12, pady=8)

        tk.Label(controls, text="Host:", font=('Segoe UI', 10),
                 fg=FG_WHITE, bg=BG_DARK).pack(side='left')

        self.tls_host_var = tk.StringVar(value='google.com')
        ttk.Entry(controls, textvariable=self.tls_host_var, width=40).pack(side='left', padx=6, ipady=3)

        tk.Label(controls, text="Port:", font=('Segoe UI', 10),
                 fg=FG_WHITE, bg=BG_DARK).pack(side='left', padx=(8, 2))
        self.tls_port_var = tk.StringVar(value='443')
        ttk.Entry(controls, textvariable=self.tls_port_var, width=6).pack(side='left', ipady=3)

        ttk.Button(controls, text="Scan TLS", style='Accent.TButton',
                   command=self._run_tls_scan).pack(side='left', padx=12)

        self.tls_output = scrolledtext.ScrolledText(tab, bg=BG_PANEL, fg=FG_WHITE,
            font=('Consolas', 10), insertbackground=CYAN, borderwidth=0, wrap='word')
        self.tls_output.pack(fill='both', expand=True, padx=12, pady=(0, 8))
        self.tls_output.insert('end', "Enter a hostname and click Scan TLS to analyze its certificate.\n\n"
                                       "Examples:\n  google.com\n  github.com\n  your-company.com\n")

    # ================================================================
    # TAB 3: CERTIFICATE SCAN
    # ================================================================

    def _build_cert_scan_tab(self):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="  Cert Scan  ")

        controls = tk.Frame(tab, bg=BG_DARK)
        controls.pack(fill='x', padx=12, pady=8)

        tk.Label(controls, text="Path:", font=('Segoe UI', 10),
                 fg=FG_WHITE, bg=BG_DARK).pack(side='left')

        self.cert_path_var = tk.StringVar()
        ttk.Entry(controls, textvariable=self.cert_path_var, width=60).pack(side='left', padx=6, ipady=3)
        ttk.Button(controls, text="Browse", command=self._browse_cert_path).pack(side='left', padx=2)
        ttk.Button(controls, text="Scan Certs", style='Accent.TButton',
                   command=self._run_cert_scan).pack(side='left', padx=12)

        self.cert_output = scrolledtext.ScrolledText(tab, bg=BG_PANEL, fg=FG_WHITE,
            font=('Consolas', 10), insertbackground=CYAN, borderwidth=0, wrap='word')
        self.cert_output.pack(fill='both', expand=True, padx=12, pady=(0, 8))
        self.cert_output.insert('end', "Browse to a directory containing .pem, .crt, .cer, or .der files.\n\n"
                                        "The scanner will analyze each certificate for quantum-vulnerable\n"
                                        "algorithms (RSA, ECDSA, Ed25519, DSA) and report findings.\n")

    # ================================================================
    # ACTIONS
    # ================================================================

    def _browse_path(self):
        path = filedialog.askdirectory(title="Select directory to scan")
        if path:
            self.path_var.set(path)

    def _browse_cert_path(self):
        path = filedialog.askdirectory(title="Select directory with certificates")
        if path:
            self.cert_path_var.set(path)

    def _set_status(self, text, color=GREEN):
        self.status_label.configure(text=text, fg=color)

    def _run_code_scan(self):
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("No Path", "Please enter or browse to a directory to scan.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Not Found", f"Path does not exist:\n{path}")
            return

        self._set_status("Scanning...", GOLD)
        self.root.update()

        def scan():
            try:
                scanner = PQCScanner()
                result = scanner.scan(path)

                # Filter by severity
                sev_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
                min_idx = sev_order.index(self.severity_var.get())
                result.findings = [f for f in result.findings if sev_order.index(f.severity.value) <= min_idx]
                result.compute_summary()

                self.last_result = result
                self.root.after(0, lambda: self._display_results(result))
            except Exception as e:
                self.root.after(0, lambda: self._scan_error(str(e)))

        threading.Thread(target=scan, daemon=True).start()

    def _display_results(self, result):
        # Update dashboard
        score = result.risk_score
        color = RED if score > 50 else (GOLD if score > 20 else GREEN)
        self.risk_label.configure(text=str(score), fg=color)
        self.findings_label.configure(text=str(len(result.findings)))
        self.files_label.configure(text=str(result.files_scanned))

        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            self.sev_labels[sev].configure(text=str(result.summary.get(sev, 0)))

        # Populate tree
        self.tree.delete(*self.tree.get_children())
        for f in result.findings:
            rel_path = os.path.relpath(f.file, result.scan_path) if result.scan_path in f.file else f.file
            self.tree.insert('', 'end', values=(
                f.severity.value, f.id, f.algorithm,
                rel_path, f.line, f.pqc_replacement
            ), tags=(f.severity.value,))

        self._set_status(f"Done: {len(result.findings)} findings", GREEN if score < 20 else RED)

    def _scan_error(self, msg):
        self._set_status("Error", RED)
        messagebox.showerror("Scan Error", msg)

    def _export(self, fmt):
        if not self.last_result:
            messagebox.showinfo("No Results", "Run a scan first.")
            return

        ext_map = {'html': '.html', 'sarif': '.sarif', 'json': '.json'}
        path = filedialog.asksaveasfilename(
            defaultextension=ext_map[fmt],
            filetypes=[(f"{fmt.upper()} files", f"*{ext_map[fmt]}"), ("All files", "*.*")],
            initialfile=f"pqc_scan_report{ext_map[fmt]}"
        )
        if not path:
            return

        formatters = {'html': format_html_report, 'sarif': format_sarif_report, 'json': format_json_report}
        output = formatters[fmt](self.last_result)

        with open(path, 'w', encoding='utf-8') as f:
            f.write(output)

        self._set_status(f"Exported: {os.path.basename(path)}", GREEN)

        if fmt == 'html':
            os.startfile(path)

    def _run_tls_scan(self):
        host = self.tls_host_var.get().strip()
        port = int(self.tls_port_var.get().strip() or '443')
        if not host:
            messagebox.showwarning("No Host", "Please enter a hostname.")
            return

        self._set_status(f"Scanning {host}:{port}...", GOLD)
        self.tls_output.delete('1.0', 'end')
        self.tls_output.insert('end', f"Connecting to {host}:{port}...\n\n")
        self.root.update()

        def scan():
            try:
                findings = scan_tls_endpoint(host, port, timeout=10)
                self.root.after(0, lambda: self._display_tls_results(host, port, findings))
            except Exception as e:
                self.root.after(0, lambda: self._display_tls_error(host, port, str(e)))

        threading.Thread(target=scan, daemon=True).start()

    def _display_tls_results(self, host, port, findings):
        self.tls_output.delete('1.0', 'end')
        if not findings:
            self.tls_output.insert('end', f"Could not retrieve certificate from {host}:{port}\n")
            self.tls_output.insert('end', "\nPossible reasons:\n")
            self.tls_output.insert('end', "  - Host unreachable or connection refused\n")
            self.tls_output.insert('end', "  - Certificate verification failed\n")
            self.tls_output.insert('end', "  - Firewall blocking the connection\n")
            self._set_status("No cert found", GOLD)
            return

        self.tls_output.insert('end', f"TLS Certificate Analysis: {host}:{port}\n")
        self.tls_output.insert('end', "=" * 60 + "\n\n")

        for f in findings:
            color_tag = f.severity.value.lower()
            self.tls_output.insert('end', f"[{f.severity.value}] {f.algorithm}")
            if f.key_size:
                self.tls_output.insert('end', f"-{f.key_size}")
            self.tls_output.insert('end', "\n")
            self.tls_output.insert('end', f"  Subject: {f.cert_subject}\n")
            self.tls_output.insert('end', f"  Issuer:  {f.cert_issuer}\n")
            self.tls_output.insert('end', f"  Expires: {f.not_after}\n")
            self.tls_output.insert('end', f"  Issue:   {f.description}\n")
            self.tls_output.insert('end', f"  Fix:     {f.recommendation}\n\n")

        self._set_status(f"TLS: {len(findings)} cert findings", GREEN)

    def _display_tls_error(self, host, port, error):
        self.tls_output.delete('1.0', 'end')
        self.tls_output.insert('end', f"Error scanning {host}:{port}\n\n{error}\n")
        self._set_status("TLS scan failed", RED)

    def _run_cert_scan(self):
        path = self.cert_path_var.get().strip()
        if not path:
            messagebox.showwarning("No Path", "Please browse to a certificate directory.")
            return

        self._set_status("Scanning certs...", GOLD)
        self.cert_output.delete('1.0', 'end')
        self.root.update()

        def scan():
            try:
                findings = scan_certificates_in_path(path)
                self.root.after(0, lambda: self._display_cert_results(path, findings))
            except Exception as e:
                self.root.after(0, lambda: self._display_cert_error(str(e)))

        threading.Thread(target=scan, daemon=True).start()

    def _display_cert_results(self, path, findings):
        self.cert_output.delete('1.0', 'end')
        if not findings:
            self.cert_output.insert('end', f"No certificate files found in:\n{path}\n\n")
            self.cert_output.insert('end', "Supported extensions: .pem, .crt, .cer, .der\n")
            self._set_status("No certs found", GOLD)
            return

        self.cert_output.insert('end', f"Certificate Scan: {path}\n")
        self.cert_output.insert('end', f"Found {len(findings)} certificate(s)\n")
        self.cert_output.insert('end', "=" * 60 + "\n\n")

        for f in findings:
            self.cert_output.insert('end', f"[{f.severity.value}] {f.algorithm}-{f.key_size}\n")
            self.cert_output.insert('end', f"  Subject: {f.cert_subject}\n")
            self.cert_output.insert('end', f"  Issuer:  {f.cert_issuer}\n")
            self.cert_output.insert('end', f"  Expires: {f.not_after}\n")
            self.cert_output.insert('end', f"  Issue:   {f.description}\n")
            self.cert_output.insert('end', f"  Fix:     {f.recommendation}\n\n")

        self._set_status(f"Certs: {len(findings)} findings", GREEN)

    def _display_cert_error(self, error):
        self.cert_output.delete('1.0', 'end')
        self.cert_output.insert('end', f"Error: {error}\n")
        self._set_status("Cert scan failed", RED)


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    root = tk.Tk()
    root.iconbitmap(default='') if os.name == 'nt' else None
    app = PQCScannerApp(root)
    root.mainloop()


if __name__ == '__main__':
    main()
