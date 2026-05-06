# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for ENIGMA v4.0 — Release Build
# All scanner modules + GUI + tree-sitter grammars for 13 languages

import os
phase_dirs = [os.path.join(os.getcwd(), 'phases', 'phase6_scanner')]

a = Analysis(
    ['enigma_release.py'],
    pathex=phase_dirs,
    binaries=[],
    datas=[],
    hiddenimports=[
        # Scanner v4 modules
        'pqc_scanner', 'ast_scanner', 'dependency_scanner', 'compliance',
        'system_scanner', 'executive_report', 'treesitter_scanner',
        'autofix', 'readiness', 'rules_engine', 'dashboard', 'history',
        'migration_estimator', 'reachability', 'benchmark',
        'ai_triage', 'sbom_enrichment', 'callgraph',
        # External deps
        'cryptography', 'cryptography.x509',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.asymmetric.ec',
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        'cryptography.hazmat.primitives.asymmetric.dsa',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.serialization',
        'tree_sitter',
        # Tree-sitter grammars for all 13 languages
        'tree_sitter_python', 'tree_sitter_java', 'tree_sitter_go',
        'tree_sitter_javascript', 'tree_sitter_typescript',
        'tree_sitter_rust', 'tree_sitter_c',
        'tree_sitter_c_sharp', 'tree_sitter_ruby', 'tree_sitter_php',
        'tree_sitter_kotlin', 'tree_sitter_swift', 'tree_sitter_scala',
        'yaml', 'sqlite3',
    ],
    hookspath=[],
    excludes=['qiskit', 'qiskit_aer', 'qiskit_ibm_runtime',
              'numpy', 'matplotlib', 'IPython', 'jupyter', 'notebook',
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
