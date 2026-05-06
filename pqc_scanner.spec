# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec for pqc-scanner GUI

a = Analysis(
    ['pqc_scanner_gui.py'],
    pathex=['C:\\Users\\jbro1\\Desktop\\Enigma\\phases\\phase6_scanner'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'pqc_scanner',
        'cryptography',
        'cryptography.x509',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.asymmetric.rsa',
        'cryptography.hazmat.primitives.asymmetric.ec',
        'cryptography.hazmat.primitives.asymmetric.ed25519',
        'cryptography.hazmat.primitives.asymmetric.dsa',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.serialization',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['qiskit', 'qiskit_aer', 'numpy', 'matplotlib', 'scipy', 'sympy',
              'IPython', 'jupyter', 'notebook', 'reportlab'],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='pqc-scanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    windowed=True,
    disable_windowed_traceback=False,
)
