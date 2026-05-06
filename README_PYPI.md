# pqc-scanner

**Post-Quantum Cryptography Migration Scanner** — Detect quantum-vulnerable cryptography in your codebase before it's too late.

The NIST deadline is 2035. CNSA 2.0 deadlines start in 2025. Your code has quantum-vulnerable crypto. This tool finds it.

## Features

- **7-language deep analysis** via tree-sitter: Python, Java, Go, JavaScript/TypeScript, Rust, C/C++
- **50+ crypto API patterns** across all languages with key size extraction
- **CycloneDX CBOM 1.7** output for enterprise security toolchains
- **SARIF 2.1.0** output for GitHub Code Scanning
- **CNSA 2.0 deadline countdown** — know exactly how many days until each algorithm is non-compliant
- **QARS risk scoring** — multi-factor Quantum-Adjusted Risk Score with A-F grades
- **Auto-fix suggestions** — deterministic transforms (MD5->SHA-256) and template migrations (RSA->ML-KEM)
- **Baseline diffing** — compare scans to only see NEW findings in CI/CD
- **Dependency scanning** — 6 ecosystems + lock files with transitive dependency detection
- **Suppression** — `.pqcignore` file + inline `# pqc-ignore[ALGO]` comments
- **Comment stripping** — eliminates false positives from commented-out code
- **Certificate scanning** — PEM/DER file analysis + live TLS endpoint checking
- **GitHub Action** — drop-in CI/CD integration with SARIF upload

## Quick Start

```bash
pip install pqc-scanner

# Scan your project
pqc-scanner scan /path/to/project

# With all features
pqc-scanner scan . --compliance --scan-deps --fix --format sarif -o results.sarif

# CBOM output for enterprise
pqc-scanner scan . --format cbom -o cbom.json

# Scan with risk scoring
pqc-scanner scan . --sensitivity confidential --exposure internet

# Compare against baseline (CI/CD)
pqc-scanner scan . --baseline previous.json --format json -o current.json

# Scan certificates
pqc-scanner scan-certs /path/to/certs/

# Check TLS endpoint
pqc-scanner scan-tls example.com:443
```

## Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Text | `--format text` | Human-readable terminal output |
| JSON | `--format json` | Programmatic processing |
| HTML | `--format html` | Shareable reports |
| SARIF | `--format sarif` | GitHub Code Scanning, Azure DevOps |
| CBOM | `--format cbom` | CycloneDX 1.7 Cryptographic Bill of Materials |

## Compliance Frameworks

pqc-scanner maps findings to three frameworks with `--compliance`:

- **CNSA 2.0** (NSA) — with deadline countdown per algorithm
- **NIST IR 8547** — federal PQC transition guidance
- **PCI DSS 4.0** — payment card industry requirements

## QARS Scoring

The Quantum-Adjusted Risk Score considers:
- Algorithm vulnerability (Shor/Grover susceptibility)
- Key size analysis
- Mosca's inequality urgency
- Data sensitivity and exposure weighting

Scores 0-100 with letter grades A-F.

## Suppression

Create `.pqcignore` in your project root:
```
# Ignore test files
tests/*
# Ignore vendored code
vendor/**
```

Or suppress inline:
```python
key = rsa.generate_private_key(...)  # pqc-ignore
hash = hashlib.md5(data)  # pqc-ignore[MD5]
```

## GitHub Action

```yaml
- uses: enigma/pqc-scanner@v4
  with:
    path: '.'
    format: 'sarif'
    fail-on-critical: 'true'
    scan-dependencies: 'true'
```

## Dependencies

**Zero required dependencies** for basic scanning. Optional:
- `cryptography` — for certificate scanning (`pip install pqc-scanner[certs]`)
- `reportlab` — for PDF executive reports (`pip install pqc-scanner[reports]`)
- `tree-sitter` + grammars — for deep multi-language analysis (`pip install pqc-scanner[all]`)

## What It Detects

| Algorithm | Risk | PQC Replacement |
|-----------|------|-----------------|
| RSA | CRITICAL (Shor) | ML-KEM-768 / ML-DSA-65 |
| ECDSA/ECDH | CRITICAL (Shor) | ML-DSA-65 / ML-KEM-768 |
| Ed25519 | HIGH (Shor) | ML-DSA-44 |
| DH/DSA | CRITICAL (Shor) | ML-KEM-768 / ML-DSA-65 |
| AES-128 | MEDIUM (Grover) | AES-256 |
| SHA-1 | MEDIUM (broken) | SHA-256 |
| MD5 | HIGH (broken) | SHA-256 |
| 3DES/DES | HIGH (deprecated) | AES-256-GCM |
| RC4/Blowfish | HIGH (broken) | AES-256-GCM |

## License

MIT
