# Enigma — Post-Quantum Cryptography Scanner

**Detect quantum-vulnerable cryptography in your codebase before it's too late.**

The NIST deadline is 2035. CNSA 2.0 deadlines start in 2025. Your code has quantum-vulnerable crypto. Enigma finds it, scores it, and auto-suggests the migration path.

## Features

- **7-language deep analysis** via tree-sitter — Python, Java, Go, JavaScript/TypeScript, Rust, C/C++
- **50+ crypto API patterns** with key-size extraction
- **CycloneDX CBOM 1.7** output — Cryptographic Bill of Materials for enterprise security toolchains
- **SARIF 2.1.0** output — drop into GitHub Code Scanning, GitLab Security, Azure DevOps
- **CNSA 2.0 deadline countdown** — exact days until each algorithm becomes non-compliant
- **QARS risk scoring** — multi-factor Quantum-Adjusted Risk Score with A–F grades
- **Auto-fix suggestions** — deterministic transforms (MD5 → SHA-256) and template migrations (RSA → ML-KEM-768)
- **Baseline diffing** — compare scans, see only NEW findings in CI/CD
- **Dependency scanning** — 6 ecosystems + lock files with transitive resolution
- **Suppression** — `.pqcignore` file + inline `# pqc-ignore[ALGO]` comments
- **Comment stripping** — eliminates false positives from commented-out code
- **Certificate scanning** — PEM/DER file analysis + live TLS endpoint checks
- **GitHub Action** — drop-in CI/CD integration with SARIF upload
- **VS Code extension** — inline diagnostics + quick-fix code actions

## Quick Start

```bash
pip install pqc-scanner

# Basic scan
pqc-scanner scan /path/to/project

# Full enterprise pipeline
pqc-scanner scan . --compliance --scan-deps --fix --format sarif -o results.sarif

# CBOM for your security org
pqc-scanner scan . --format cbom -o cbom.json

# Risk-weighted scan
pqc-scanner scan . --sensitivity confidential --exposure internet

# CI baseline diff
pqc-scanner scan . --baseline previous.json --format json -o current.json

# Certificate inventory
pqc-scanner scan-certs /path/to/certs/

# Live TLS endpoint
pqc-scanner scan-tls example.com:443
```

## Output Formats

| Format | Flag | Use Case |
|---|---|---|
| Text | `--format text` | Human-readable terminal |
| JSON | `--format json` | Programmatic processing |
| HTML | `--format html` | Shareable reports |
| SARIF | `--format sarif` | GitHub Code Scanning, Azure DevOps |
| CBOM | `--format cbom` | CycloneDX 1.7 Cryptographic Bill of Materials |

## Compliance Frameworks

Map findings to three frameworks with `--compliance`:

- **CNSA 2.0** (NSA) — deadline countdown per algorithm
- **NIST IR 8547** — federal PQC transition guidance
- **PCI DSS 4.0** — payment card industry requirements

## QARS Scoring

The Quantum-Adjusted Risk Score considers:

- Algorithm vulnerability (Shor / Grover susceptibility)
- Key size analysis
- Mosca's inequality urgency
- Data sensitivity and exposure weighting

Scores 0–100 with A–F letter grades.

## What It Detects

| Algorithm | Risk | PQC Replacement |
|---|---|---|
| RSA | CRITICAL (Shor) | ML-KEM-768 / ML-DSA-65 |
| ECDSA / ECDH | CRITICAL (Shor) | ML-DSA-65 / ML-KEM-768 |
| Ed25519 | HIGH (Shor) | ML-DSA-44 |
| DH / DSA | CRITICAL (Shor) | ML-KEM-768 / ML-DSA-65 |
| AES-128 | MEDIUM (Grover) | AES-256 |
| SHA-1 | MEDIUM (broken) | SHA-256 |
| MD5 | HIGH (broken) | SHA-256 |
| 3DES / DES | HIGH (deprecated) | AES-256-GCM |
| RC4 / Blowfish | HIGH (broken) | AES-256-GCM |

## GitHub Action

```yaml
- uses: itsribbZ/Enigma/github-action@v4
  with:
    path: '.'
    format: 'sarif'
    fail-on-critical: 'true'
    scan-dependencies: 'true'
```

## Suppression

`.pqcignore` in your project root:

```
# Ignore tests
tests/*
# Ignore vendored code
vendor/**
```

Or inline:

```python
key = rsa.generate_private_key(...)  # pqc-ignore
hash = hashlib.md5(data)  # pqc-ignore[MD5]
```

## Repo Layout

| Path | Purpose |
|---|---|
| `phases/` | Phased PQC scanner implementation (Phase 1–9) |
| `demo/` | Sample vulnerable project for end-to-end testing |
| `github-action/` | Drop-in CI/CD action with SARIF upload |
| `vscode-extension/` | VS Code extension source + .vsix build |
| `assets/` | Branding |
| `*.spec` | PyInstaller build specs (dev / release / scanner) |

## Dependencies

**Zero required** for basic scanning. Optional:

- `cryptography` — certificate scanning (`pip install pqc-scanner[certs]`)
- `reportlab` — PDF executive reports (`pip install pqc-scanner[reports]`)
- `tree-sitter` + grammars — deep multi-language analysis (`pip install pqc-scanner[all]`)

## Documentation

Bundled corporate-overview PDFs in repo:

- `Enigma_PQC_Scanner_Corporate_Overview.pdf` — exec summary
- `PQC_Executive_Report.pdf` — sample executive report output
- `PQC_Scanner_Test_Guide.pdf` — testing walkthrough
- `Quantum_Security_Expert_Roadmap.pdf` — ecosystem map
- `Enigma_Capstone.pdf` — full deep-dive

## License

MIT

## Author

Jacob Ribbe — [github.com/itsribbZ](https://github.com/itsribbZ)
