"""
ENIGMA v4.0 — Quantum Security Platform (Release Build)

Enterprise PQC scanner with readiness grading, auto-fix, and migration estimates.
Scan codebases and systems for quantum-vulnerable cryptography.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import os
import sys
from datetime import datetime

# Add scanner modules to path
_base = os.path.dirname(os.path.abspath(__file__))
_scanner = os.path.join(_base, 'phases', 'phase6_scanner')
if _scanner not in sys.path:
    sys.path.insert(0, _scanner)

# ============================================================================
# ENIGMA THEME — Navy / Gold / Silver
# ============================================================================

BG = '#0A0E1A'
BG2 = '#111827'
BG3 = '#1C2333'
FG = '#E2E8F0'
FG2 = '#8892A8'
GOLD = '#D4AF37'
GOLD2 = '#A89050'
ICE = '#7EB8DA'
RED = '#DC4A4A'
GREEN = '#48BB78'
ORANGE = '#E8853D'
BLUE = '#5B9BD5'

SIGMA = '\u03A3'


class EnigmaApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{SIGMA} ENIGMA — PQC Scanner")
        self.root.geometry("1080x760")
        self.root.configure(bg=BG)
        self.root.minsize(900, 640)

        ico = os.path.join(_base, 'enigma.ico')
        if os.path.exists(ico):
            self.root.iconbitmap(ico)

        self._style()

        self.main = tk.Frame(self.root, bg=BG)
        self.main.pack(fill='both', expand=True)

        self._build_sidebar()
        self._build_content()
        self._show_home()

    def _style(self):
        s = ttk.Style()
        s.theme_use('clam')
        s.configure('.', background=BG, foreground=FG)
        s.configure('TFrame', background=BG)
        s.configure('TLabel', background=BG, foreground=FG, font=('Segoe UI', 10))
        s.configure('TButton', background=BG2, foreground=ICE,
                     font=('Segoe UI', 10, 'bold'), borderwidth=0)
        s.map('TButton', background=[('active', BG3)])
        s.configure('Gold.TButton', background=GOLD, foreground=BG,
                     font=('Segoe UI', 12, 'bold'))
        s.map('Gold.TButton', background=[('active', GOLD2)])
        s.configure('TEntry', fieldbackground=BG3, foreground=FG,
                     insertcolor=GOLD, borderwidth=0)

    # ================================================================
    # SIDEBAR
    # ================================================================
    def _build_sidebar(self):
        self.sidebar = tk.Frame(self.main, bg=BG2, width=220)
        self.sidebar.pack(side='left', fill='y')
        self.sidebar.pack_propagate(False)

        # Logo
        logo_frame = tk.Frame(self.sidebar, bg=BG2)
        logo_frame.pack(fill='x', pady=(16, 8))
        tk.Label(logo_frame, text=SIGMA, font=('Times New Roman', 32, 'bold'),
                 fg=GOLD, bg=BG2).pack()
        tk.Label(logo_frame, text="ENIGMA", font=('Segoe UI', 14, 'bold'),
                 fg=FG, bg=BG2).pack()
        tk.Label(logo_frame, text="Quantum Security", font=('Segoe UI', 8),
                 fg=FG2, bg=BG2).pack()

        tk.Frame(self.sidebar, bg=GOLD2, height=1).pack(fill='x', padx=16, pady=12)

        # Nav — release features only
        self.nav_buttons = {}
        nav_items = [
            ('home', 'Home'),
            ('scan', 'System Scan'),
            ('code', 'Code Scanner'),
        ]
        for key, label in nav_items:
            btn = tk.Button(self.sidebar, text=f"  {label}", font=('Segoe UI', 10),
                           fg=FG2, bg=BG2, bd=0, anchor='w', padx=16, pady=8,
                           activebackground=BG3, activeforeground=GOLD,
                           command=lambda k=key: self._navigate(k))
            btn.pack(fill='x')
            self.nav_buttons[key] = btn

        # Version at bottom
        tk.Label(self.sidebar, text="v4.0", font=('Segoe UI', 8),
                 fg=FG2, bg=BG2).pack(side='bottom', pady=8)

    def _navigate(self, key):
        for k, btn in self.nav_buttons.items():
            btn.configure(fg=GOLD if k == key else FG2, bg=BG3 if k == key else BG2)
        pages = {
            'home': self._show_home,
            'scan': self._show_scan,
            'code': self._show_code,
        }
        pages.get(key, self._show_home)()

    # ================================================================
    # CONTENT AREA
    # ================================================================
    def _build_content(self):
        self.content = tk.Frame(self.main, bg=BG)
        self.content.pack(side='right', fill='both', expand=True)

    def _clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    def _make_output(self, parent):
        return scrolledtext.ScrolledText(parent, bg=BG2, fg=FG,
            font=('Consolas', 10), insertbackground=GOLD, borderwidth=0,
            wrap='word', selectbackground='#2A3040')

    def _run_bg(self, fn, callback):
        def wrapper():
            try:
                result = fn()
                self.root.after(0, lambda: callback(result))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
        threading.Thread(target=wrapper, daemon=True).start()

    # ================================================================
    # HOME
    # ================================================================
    def _show_home(self):
        self._clear_content()
        self.nav_buttons.get('home', None) and self.nav_buttons['home'].configure(fg=GOLD, bg=BG3)

        center = tk.Frame(self.content, bg=BG)
        center.place(relx=0.5, rely=0.4, anchor='center')

        tk.Label(center, text=SIGMA, font=('Times New Roman', 72, 'bold'),
                 fg=GOLD, bg=BG).pack()
        tk.Label(center, text="ENIGMA", font=('Segoe UI', 28, 'bold'),
                 fg=FG, bg=BG).pack(pady=(0, 4))
        tk.Label(center, text="Post-Quantum Cryptography Scanner", font=('Segoe UI', 12),
                 fg=FG2, bg=BG).pack(pady=(0, 24))

        self.home_score = tk.Label(center, text="", font=('Segoe UI', 18),
                                    fg=FG2, bg=BG)
        self.home_score.pack(pady=(0, 16))

        tk.Button(center, text=f"  {SIGMA}  Scan My System  ",
                  font=('Segoe UI', 14, 'bold'),
                  fg=BG, bg=GOLD, bd=0, padx=24, pady=10,
                  activebackground=GOLD2,
                  command=self._run_home_scan).pack(pady=8)

        tk.Label(center, text="Checks SSH keys, certificates, TLS connections, and git signing",
                 font=('Segoe UI', 9), fg=FG2, bg=BG).pack(pady=(8, 0))

    def _run_home_scan(self):
        self.home_score.configure(text="Scanning...", fg=GOLD)
        self.root.update()

        def scan():
            from system_scanner import run_system_scan
            return run_system_scan(include_tls=True, tls_timeout=5)

        def done(result):
            score = result.score
            grade = result.grade
            color = GREEN if score >= 75 else (ORANGE if score >= 40 else RED)
            self.home_score.configure(
                text=f"Quantum Readiness: {score}/100 ({grade})\n"
                     f"{len(result.findings)} items scanned",
                fg=color)
            self._show_scan_results(result)

        self._run_bg(scan, done)

    # ================================================================
    # SYSTEM SCAN
    # ================================================================
    def _show_scan(self):
        self._clear_content()

        header = tk.Frame(self.content, bg=BG)
        header.pack(fill='x', padx=16, pady=12)
        tk.Label(header, text="System Quantum Readiness Scan",
                 font=('Segoe UI', 16, 'bold'), fg=GOLD, bg=BG).pack(side='left')
        tk.Button(header, text="Run Scan", font=('Segoe UI', 10, 'bold'),
                  fg=BG, bg=GOLD, bd=0, padx=16, pady=4,
                  command=self._run_system_scan).pack(side='right')

        self.scan_out = self._make_output(self.content)
        self.scan_out.pack(fill='both', expand=True, padx=16, pady=(0, 12))
        self.scan_out.insert('end',
            "Click 'Run Scan' to check your system for quantum vulnerabilities.\n\n"
            "Scans:\n"
            "  - SSH keys (~/.ssh/)\n"
            "  - System certificates\n"
            "  - TLS connections to major sites\n"
            "  - Git signing configuration\n")

    def _run_system_scan(self):
        self.scan_out.delete('1.0', 'end')
        self.scan_out.insert('end', "Scanning...\n")
        self.root.update()

        def scan():
            from system_scanner import run_system_scan, format_system_report
            result = run_system_scan(include_tls=True, tls_timeout=5)
            return format_system_report(result)

        def done(text):
            self.scan_out.delete('1.0', 'end')
            self.scan_out.insert('end', text)

        self._run_bg(scan, done)

    def _show_scan_results(self, result):
        self._navigate('scan')
        self.scan_out.delete('1.0', 'end')
        from system_scanner import format_system_report
        self.scan_out.insert('end', format_system_report(result))

    # ================================================================
    # CODE SCANNER
    # ================================================================
    def _show_code(self):
        self._clear_content()

        header = tk.Frame(self.content, bg=BG)
        header.pack(fill='x', padx=16, pady=12)
        tk.Label(header, text="Code Scanner", font=('Segoe UI', 16, 'bold'),
                 fg=GOLD, bg=BG).pack(side='left')

        ctrl = tk.Frame(self.content, bg=BG)
        ctrl.pack(fill='x', padx=16)
        self.code_path = tk.StringVar()
        ttk.Entry(ctrl, textvariable=self.code_path, width=50).pack(side='left', ipady=3)
        tk.Button(ctrl, text="Browse", font=('Segoe UI', 9), fg=ICE, bg=BG2, bd=0, padx=8,
                  command=lambda: self.code_path.set(
                      filedialog.askdirectory() or '')).pack(side='left', padx=4)
        tk.Button(ctrl, text="Scan", font=('Segoe UI', 10, 'bold'), fg=BG, bg=GOLD,
                  bd=0, padx=16, command=self._run_code_scan).pack(side='left', padx=8)
        tk.Button(ctrl, text="Export PDF", font=('Segoe UI', 9), fg=ICE, bg=BG2,
                  bd=0, padx=8, command=self._export_pdf).pack(side='right')
        tk.Button(ctrl, text="Apply Fixes", font=('Segoe UI', 9), fg=GREEN, bg=BG2,
                  bd=0, padx=8, command=self._apply_fixes).pack(side='right', padx=4)

        self.code_out = self._make_output(self.content)
        self.code_out.pack(fill='both', expand=True, padx=16, pady=(8, 12))
        self.code_out.insert('end',
            "Browse to a project directory and click Scan.\n"
            "16 languages | Readiness grade | Auto-fix | Migration estimates\n")
        self._code_result = None
        self._code_grade = None

    def _run_code_scan(self):
        path = self.code_path.get().strip()
        if not path:
            return
        self.code_out.delete('1.0', 'end')
        self.code_out.insert('end', f"Scanning {path}...\n")
        self.root.update()

        def scan():
            from pqc_scanner import PQCScanner, format_text_report
            from ast_scanner import ast_scan_directory
            from dependency_scanner import scan_dependencies, format_dep_report
            from compliance import analyze_compliance, format_compliance_report
            from readiness import compute_readiness_grade, format_readiness_report
            from autofix import generate_fixes, format_fix_report
            from migration_estimator import estimate_migration

            scanner = PQCScanner()
            result = scanner.scan(path)

            # AST scan for Python
            ast_findings = ast_scan_directory(path)
            existing = {(f.file, f.line) for f in result.findings}
            for af in ast_findings:
                if (af.file, af.line) not in existing:
                    result.findings.append(af)
            result.compute_summary()

            lines = [format_text_report(result)]

            # Dependency scan
            deps = scan_dependencies(path)
            if deps:
                lines.append("\n" + format_dep_report(deps))

            # Compliance
            compliance = analyze_compliance(result)
            lines.append("\n" + format_compliance_report(compliance))

            # Readiness Grade
            grade = compute_readiness_grade(result)
            lines.append("\n" + format_readiness_report(grade))

            # Auto-fix suggestions
            if result.findings:
                fixes = generate_fixes(result.findings, path)
                if fixes:
                    lines.append("\n" + format_fix_report(fixes))

            # Migration estimate
            if result.findings:
                est = estimate_migration(result)
                lines.append(
                    f"\n{'=' * 60}\n"
                    f"  MIGRATION ESTIMATE\n"
                    f"{'=' * 60}\n"
                )
                for e in est['estimates']:
                    lines.append(
                        f"  {e['algorithm']:<12} {e['instances']:>3}x  "
                        f"{e['complexity']:<15} {e['total_hours']:>5.1f}h  "
                        f"${e['total_cost']:>8,.0f}  -> {e['pqc_target']}"
                    )
                lines.append(f"\n  Development:    {est['subtotal_hours']:>6.1f}h")
                lines.append(f"  Testing (30%):  {est['testing_hours']:>6.1f}h")
                lines.append(f"  Integration:    {est['integration_hours']:>6.1f}h")
                lines.append(f"  Documentation:  {est['documentation_hours']:>6.1f}h")
                lines.append(f"  {'─' * 24}")
                lines.append(
                    f"  TOTAL:          {est['grand_total_hours']:>6.1f}h  "
                    f"(${est['grand_total_cost']:>,.0f} @ ${est['hourly_rate']}/hr)"
                )

            # Record to history
            try:
                from history import record_scan
                record_scan(result, grade=grade.grade, qars_score=grade.score,
                           project_name=os.path.basename(path))
            except Exception:
                pass

            self._code_result = result
            self._code_grade = grade
            return "\n".join(lines)

        def done(text):
            self.code_out.delete('1.0', 'end')
            self.code_out.insert('end', text)

        self._run_bg(scan, done)

    def _export_pdf(self):
        if not self._code_result:
            return messagebox.showinfo("", "Run a scan first.")
        path = filedialog.asksaveasfilename(
            defaultextension='.pdf', initialfile='PQC_Report.pdf')
        if not path:
            return
        from executive_report import generate_executive_report
        generate_executive_report(self._code_result, "Assessment", path)
        os.startfile(path)

    def _apply_fixes(self):
        if not self._code_result or not self._code_result.findings:
            return messagebox.showinfo("", "Run a scan first.")
        from autofix import generate_fixes, apply_tier1_fixes
        fixes = generate_fixes(self._code_result.findings,
                              self._code_result.scan_path)
        tier1 = [f for f in fixes if f.tier == 1]
        if not tier1:
            return messagebox.showinfo("Auto-Fix",
                                        "No Tier 1 (safe) fixes available.")
        if not messagebox.askyesno("Auto-Fix",
                f"Apply {len(tier1)} Tier 1 deterministic fixes?\n"
                "(MD5->SHA-256, SHA-1->SHA-256, DES->AES-GCM, ECB->GCM)"):
            return
        applied = apply_tier1_fixes(tier1)
        messagebox.showinfo("Auto-Fix",
                            f"Applied {applied} fixes. Re-scan to verify.")


# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    root = tk.Tk()
    app = EnigmaApp(root)
    root.mainloop()

if __name__ == '__main__':
    main()
