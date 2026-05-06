# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for ENIGMA v4.0 — Quantum Security Platform

import os
phase_dirs = []
base = os.path.join(os.getcwd(), 'phases')
for d in os.listdir(base):
    p = os.path.join(base, d)
    if os.path.isdir(p):
        phase_dirs.append(p)

a = Analysis(
    ['enigma_app.py'],
    pathex=phase_dirs,
    binaries=[],
    datas=[],
    hiddenimports=[
        # Phase 6 — Scanner v4 modules
        'pqc_scanner', 'ast_scanner', 'dependency_scanner', 'compliance',
        'system_scanner', 'executive_report', 'treesitter_scanner',
        'autofix', 'readiness', 'rules_engine', 'dashboard', 'history',
        'migration_estimator', 'reachability', 'benchmark',
        # Phase 1 — Math
        'modular_math',
        # Phase 2 — Classical Crypto
        'rsa', 'aes', 'ecc', 'ed25519', 'sha256',
        'cryptopals', 'tls_analyzer',
        # Phase 5 — PQC
        'ml_kem', 'pqc_lattice',
        # Phase 3 — Quantum
        'quantum_circuits', 'quantum_threats', 'quantum_hardware',
        # Phase 7 — QKD
        'qkd_protocols',
        # Phase 8 — Portfolio
        'portfolio',
        # External deps
        'qiskit', 'qiskit.circuit', 'qiskit.quantum_info',
        'qiskit_aer', 'qiskit_aer.noise',
        'cryptography', 'cryptography.x509',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.asymmetric.ec',
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        'cryptography.hazmat.primitives.asymmetric.dsa',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.serialization',
        'numpy', 'numpy.core', 'numpy.linalg',
        'tree_sitter',
        'yaml',
    ],
    hookspath=[],
    excludes=['matplotlib', 'IPython', 'jupyter', 'notebook', 'reportlab',
              'scipy', 'sympy', 'PIL', 'pandas'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Enigma',
    debug=False,
    strip=False,
    upx=True,
    runtime_tmpdir=None,
    console=False,
    windowed=True,
    icon='enigma.ico',
)
