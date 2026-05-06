# pqc-scanner Quickstart

Scan your code for quantum-vulnerable cryptography in 60 seconds.

## Install

```bash
pip install pqc-scanner
```

For deep analysis (recommended):
```bash
pip install pqc-scanner[all]
```

## Scan

```bash
# Basic scan
pqc-scanner scan /path/to/your/project

# Full scan with grade + compliance + fix suggestions
pqc-scanner scan . --grade --compliance --fix --scan-deps

# CI/CD mode (SARIF output, fail on critical)
pqc-scanner scan . --format sarif -o results.sarif --gate no-critical
```

## Read Results

The scanner outputs:
- **Readiness Grade** (A+ to F) — instant quantum readiness assessment
- **Findings** grouped by severity (CRITICAL / HIGH / MEDIUM / LOW)
- **QARS Score** (0-100) — multi-factor quantum risk score
- **Fix suggestions** — deterministic transforms you can apply immediately

## What It Detects

| Risk | Algorithms | PQC Replacement |
|------|-----------|-----------------|
| CRITICAL | RSA, ECDSA, ECDH, DH, DSA | ML-KEM-768, ML-DSA-65 |
| HIGH | Ed25519, MD5, 3DES, RC4, Blowfish | ML-DSA-44, SHA-256, AES-256-GCM |
| MEDIUM | AES-128, SHA-1 | AES-256, SHA-256 |

## Fix

For each finding, the scanner provides:
1. **What's wrong** — which algorithm, which file, which line
2. **Why it matters** — Shor's algorithm breaks it, CNSA 2.0 deadline
3. **What to use instead** — specific NIST PQC standard replacement
4. **Auto-fix** (with `--fix`) — code diff you can apply

Quick wins (deterministic, safe to auto-apply):
- `hashlib.md5()` → `hashlib.sha256()`
- `hashlib.sha1()` → `hashlib.sha256()`
- `DES.new()` → `AES.new()`
- TLS 1.0/1.1 → TLS 1.3

## Output Formats

| Format | Flag | Best For |
|--------|------|----------|
| Text | `--format text` | Terminal |
| Dashboard | `--format dashboard -o report.html` | CISO presentation |
| SARIF | `--format sarif` | GitHub/Azure CI/CD |
| CBOM | `--format cbom` | Enterprise SBOM toolchains |
| JSON | `--format json` | Automation |

## Suppress False Positives

Create `.pqcignore` in your project root:
```
tests/*
vendor/**
legacy_code.py
```

Or suppress inline:
```python
key = rsa.generate_private_key(...)  # pqc-ignore
```

## Key Flags

| Flag | What It Does |
|------|-------------|
| `--grade` | Show PQC readiness grade (A+ to F) |
| `--gate pqc-ready` | CI/CD pass/fail quality gate |
| `--compliance` | CNSA 2.0 + NIST + PCI DSS mapping |
| `--fix` | Auto-fix suggestions with diffs |
| `--scan-deps` | Scan dependency manifests + lock files |
| `--estimate` | Migration effort/cost estimate |
| `--baseline prev.json` | Only show NEW findings |
| `--reachability` | Verify if crypto deps are actually called |

## Languages Supported

Python, Java, Go, JavaScript, TypeScript, Rust, C, C++, C#, Ruby, PHP, Kotlin, Swift, Scala, Terraform, YAML, Dockerfile
