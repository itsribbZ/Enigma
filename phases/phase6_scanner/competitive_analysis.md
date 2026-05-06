# Competitive Analysis: Best-in-Class Security Scanning Tools

## Research Date: 2026-03-23
## Purpose: Extract features for PQC scanner product strategy

---

# TOOL 1: SEMGREP

## Why Developers Love It
Semgrep wins on **developer experience** -- it feels like writing code, not configuring a security tool. The rule format uses the same syntax as the language being scanned, so a Python developer writes Python-like patterns.

## Custom Rule YAML Format

```yaml
rules:
  - id: unique-rule-identifier
    languages: [python, javascript]  # Multi-language support
    message: "Why this is bad and how to fix it"
    severity: HIGH  # LOW | MEDIUM | HIGH | CRITICAL

    # Pattern operators (pick one top-level):
    pattern: "insecure_function(...)"           # Simple match
    patterns:                                    # AND logic
      - pattern: "hashlib.md5(...)"
      - pattern-not: "hashlib.md5(..., usedforsecurity=False)"
    pattern-either:                              # OR logic
      - pattern: "DES.new(...)"
      - pattern: "Blowfish.new(...)"
    pattern-regex: "api_key\s*=\s*['\"].*['\"]"  # PCRE2 regex

    # Nested modifiers within patterns:
    # - pattern-inside: constrain to enclosing context
    # - pattern-not-inside: exclude enclosing context
    # - metavariable-regex: filter captured $VARs by regex
    # - metavariable-pattern: match $VARs against sub-patterns
    # - metavariable-comparison: numeric comparison on $VARs
    # - focus-metavariable: narrow the reported range

    # Autofix:
    fix: "secure_function($ARG)"  # Supports metavariable substitution

    # Metadata (arbitrary key-value):
    metadata:
      cve: CVE-2024-XXXXX
      category: security
      confidence: HIGH
      cwe: ["CWE-327"]

    # Path filtering:
    paths:
      include: ["src/**"]
      exclude: ["tests/**", "vendor/**"]

    # Version constraints:
    min-version: "1.50.0"

    # Analysis options:
    options:
      constant_propagation: true
      interfile: true
      taint_assume_safe_functions: false
```

**Key insight**: The `pattern` field uses the TARGET language syntax, not a separate DSL. `$VAR` captures any expression as a metavariable. `...` is the ellipsis operator matching any sequence of arguments/statements.

## VS Code Extension
- Scans on file open, file save, and on-demand via command palette
- Yellow inline underlines for findings with hover tooltips
- Findings appear in VS Code Problems panel (standard diagnostic integration)
- Quick links to rule definitions from inline findings
- One-click Autofix: apply suggested fix directly from the editor
- Uses Language Server Protocol (LSP) under the hood
- "Instantaneous" on most files -- speed is a major differentiator

## CLI UX
- Output formats: text (default), JSON, SARIF, EMACS, VIM, GitLab SAST, GitLab Secrets, JUnit XML
- Color-coded terminal output with file path, line number, matched code snippet, and rule ID
- `--severity` flag to filter by level
- `--config auto` to use recommended ruleset without configuration
- `--config p/security-audit` for curated rulesets (registry paths)
- `--json` for machine-parseable output
- `--autofix` to apply fixes automatically
- Exit codes: 0 (no findings), 1 (findings found) -- works with CI gates

## Suppression/Ignoring
- Inline comment: `# nosemgrep` (ignores all rules on that line)
- Rule-specific: `# nosemgrep: rule-id-here`
- Multi-rule: `# nosemgrep: rule1, rule2, rule3`
- Legacy `# nosem` still supported
- Platform triage states: Open, Reviewing, To fix, Ignored, Fixed, Closed
- "Provisionally ignored" -- AI-flagged likely false positives
- Ignore reasons: false positive, acceptable risk, or no reason
- Bulk triage via PR/MR commands: `/fp`, `/ar`, `/other`, `/open`
- Triage decisions propagate across branches automatically

## PR/MR Integration
- Native GitHub PR comments with issue description and remediation steps
- GitLab MR comments supported
- Two types of autofix in PRs:
  1. Rule-defined: `fix:` key in YAML with metavariable replacement
  2. AI-assisted: Semgrep Assistant generates fix when no rule-defined fix exists
- PR comments include step-by-step remediation when Assistant is enabled
- Requires read/write access to actions, PRs, secrets, security events, workflows

## Playground/Testing
- Live web editor at semgrep.dev/playground
- Three-pane design: rule YAML | test code | match results
- Simple mode and Advanced mode for rule editing
- Comment-based test assertions for expected matches
- Rule library browser (requires sign-in for saved rules)
- Shareable rule links for community/team collaboration
- **Privacy warning**: code submitted to playground is processed server-side

## BEST Feature
**Pattern syntax that mirrors the target language.** No separate query language to learn. A Python security engineer writes Python-like patterns. This is the #1 reason developers choose it over competitors.

## Pricing Model
| Tier | Price | Key Features |
|------|-------|--------------|
| Community (OSS CLI) | Free forever | Single-file SAST, 3000+ community rules, IDE + CI/CD |
| AppSec Platform Free | Free up to 10 contributors | Cross-file SAST, Pro Rules, SCA, Secrets |
| Teams | $35/contributor/month | Unlimited repos, AI triage (Assistant), dashboards, policies |
| Enterprise | Custom | SSO, RBAC, custom SLAs, dedicated support |

## Distribution Model
- `pip install semgrep` or `brew install semgrep`
- Docker: `semgrep/semgrep`
- GitHub Action: `semgrep/semgrep-action`
- VS Code Marketplace extension
- No account required for CLI OSS usage

## Features to Adopt for PQC Scanner
1. YAML rule format with target-language pattern matching
2. `# nopqc` / `# nopqc: rule-id` inline suppression syntax
3. Multiple output formats (text, JSON, SARIF)
4. Meaningful exit codes for CI integration
5. `--config auto` equivalent for sensible defaults
6. Playground for testing custom PQC rules
7. Metavariable system for flexible pattern capture

---

# TOOL 2: SNYK

## Why Enterprises Pay For It
Snyk wins on **fix automation and dependency intelligence**. It doesn't just find vulnerabilities -- it opens PRs with the fix, tells you if the vulnerable code is actually reachable, and provides a proprietary vulnerability database that's faster than NVD.

## Vulnerability Presentation
- Issues shown with severity badge (Critical/High/Medium/Low)
- Each finding includes: CVE ID, CWE, CVSS score, exploit maturity, fix availability
- Data flow visualization for code issues (source -> sink path)
- Dependency tree showing how a vulnerable package entered the project
- "Reachability" badge -- is the vulnerable function actually called in your code?

## Fix PR Generation
- **Automatic Fix PRs**: Generated when Snyk detects a new vulnerability with an available fix
- **Manual Fix via PR comments**: Reply with `@snyk /fix` to get up to 5 AI-generated fix suggestions
- **Apply specific fix**: `@snyk /apply 3` to apply suggestion #3 as a commit on the PR branch
- **PR summary comment**: Every PR gets a summary with check type breakdown and severity counts
- **Inline comments**: Per-issue comments with severity, description, data flow, and helpful links
- Fix PRs created based on configurable test frequency

## Dashboard Features
- Project-level vulnerability counts by severity
- Organization-wide security posture view
- License compliance tracking
- Dependency health metrics
- Integration with Jira for issue tracking
- Rich API for custom reporting
- Custom user roles and security policy management

## IDE Integration
- Plugins for: VS Code, all JetBrains IDEs, Eclipse, Cursor
- Real-time "scan on save" and "scan as you type" modes
- Inline vulnerability highlights with severity ratings
- AI-generated fix suggestions directly in the editor
- Three scan types in one plugin: Code (SAST), Open Source (SCA), IaC
- Uses Language Server Protocol for consistent cross-IDE experience

## Dependency Handling
- **Snyk Open Source**: SCA with reachability analysis
- Monitors dependency trees, not just direct dependencies
- Transitive dependency depth factored into risk scoring
- Automatic monitoring for new CVEs against your locked dependencies
- License compliance checking per dependency
- Container image scanning for base image vulnerabilities

## Scoring/Priority System

### Risk Score (replaces Priority Score)
- Range: 0-1000
- Two subscores:
  1. **Impact** (from CVSS: Confidentiality, Integrity, Availability, Scope) + business criticality attribute
  2. **Likelihood** incorporating:
     - Exploit maturity + EPSS (updated daily)
     - CVSS exploitability metrics (Attack Vector, Complexity, Privileges Required, User Interaction)
     - Vulnerability age (>1 year changes weighting)
     - Social trends / malicious package status
     - Package popularity
     - Reachability (is the vulnerable method called?)
     - Transitive depth (how deep in dependency tree?)
- **Key differentiator**: Reachability analysis (Java, JavaScript) -- determines if the vulnerable function is actually invoked in your code path

### Severity Levels
- Critical (CVSS 9.0-10.0)
- High (CVSS 7.0-8.9)
- Medium (CVSS 4.0-6.9)
- Low (CVSS 0.1-3.9)

## CLI Experience
- `snyk test` -- scan and report vulnerabilities
- `snyk monitor` -- take a snapshot for continuous monitoring
- `snyk fix` -- apply available fixes
- `snyk code test` -- SAST scanning
- `snyk container test` -- container scanning
- `snyk iac test` -- infrastructure as code scanning
- Color-coded terminal output with severity indicators
- JSON output supported for CI/CD integration
- **Note**: Risk Score is NOT available in CLI (platform only)

## BEST Feature
**Automated Fix PR generation with reachability analysis.** Snyk doesn't just say "you have a vulnerability" -- it tells you if it's actually exploitable in YOUR code and opens a PR with the fix. This is why enterprises pay.

## Pricing Model
| Tier | Price | Key Features |
|------|-------|--------------|
| Free | $0 | Up to 5 developers, basic scanning |
| Team | $25/dev/month | Min 5, max 10 developers |
| Enterprise | Custom (~$697/dev for 50 devs) | SSO, Jira, RBAC, custom policies |
| Ignite | $1,260/year/dev | For <50 dev orgs, bundled products |

Typical enterprise range: $5,000-$70,000 depending on scale.

## Distribution Model
- `npm install -g snyk`
- Standalone binaries for all platforms
- Docker images
- IDE plugins via marketplaces
- GitHub App / GitLab integration
- Account required for all functionality

## Features to Adopt for PQC Scanner
1. Risk scoring that factors in reachability / actual usage
2. Fix PR generation (suggest PQC migration code)
3. Dependency tree visualization for crypto library chains
4. "Is this actually used?" analysis for flagged algorithms
5. Severity + exploitability combined scoring
6. Per-issue inline PR comments with remediation steps

---

# TOOL 3: SONARQUBE

## Why It's the Enterprise Standard
SonarQube wins on **quality gates and historical tracking**. It's the "did this code get worse?" tool. The concept of gating releases on measurable quality thresholds is its killer feature.

## Quality Gates
- Boolean pass/fail gate on configurable conditions
- Default "Sonar way" gate conditions:
  - No new bugs (reliability)
  - No new vulnerabilities (security)
  - No new code smells above threshold (maintainability)
  - Code coverage on new code >= X%
  - Duplication on new code <= X%
- Custom gates can include ANY metric as a condition
- Enterprise edition: gates can fail on "prioritized issues" in custom quality profiles
- AI Code Assurance gate ("Sonar way for AI Code") for AI-generated code
- **Key concept**: "Clean as You Code" -- gates apply to NEW code only, so legacy debt doesn't block releases

## Historical Tracking
- Activity page with pre-defined metric visualizations
- Custom trend diagrams: select metrics and time period
- Tracks how metrics changed across successive analyses
- Metrics available: bugs, vulnerabilities, code smells, coverage, duplication, complexity
- **Limitation**: Only analyzes latest code version by default -- no automatic cross-version comparison
- Third-party extension "SoHist" adds automated historical snapshot evaluation

## Dashboard Visualization
- Project-level dashboard: current quality gate status, metric summary
- Portfolio-level views for enterprise multi-project oversight
- Reliability, Security, Maintainability ratings (A-E scale)
- Technical debt quantified in time (e.g., "3 days of debt")
- Hotspot review tracking (security-sensitive code requiring manual review)
- Issue breakdown by severity, type, and status

## False Positive Handling
- Issues can be marked as "False Positive" (requires permission)
- False positive issues excluded from quality reports and ratings
- Issues can be marked as "Accepted" (won't fix / acceptable risk)
- Both states are persistent across analyses
- **Limitation**: Studies show ~18% true positive rate in some samples -- significant FP noise
- No AI-assisted triage (unlike Semgrep)

## Rule System
- 30+ languages supported
- Built-in "Sonar way" quality profiles per language as starting points
- Custom quality profiles with custom rule activation
- Rule types: Bug, Vulnerability, Security Hotspot, Code Smell
- AI CodeFix: auto-generated fixes for C++, JS/TS, Python, Java, C#
- Enterprise: prioritized rules that trigger quality gate failures
- Plugin ecosystem for additional languages (Hadolint, Swift, PL/SQL, etc.)
- Design & Architecture verification (Java) -- validates code structure against patterns

## Integration Ecosystem
- Jenkins plugin (native, mature)
- GitHub Actions, Azure DevOps, GitLab CI
- IDE plugins: VS Code (SonarLint), IntelliJ (SonarLint)
- PR decoration: inline comments on GitHub/GitLab/Azure DevOps PRs
- Webhook notifications
- API for custom integrations
- SSO (SAML, LDAP)
- Self-hosted (Server) or cloud (SonarCloud)

## BEST Feature
**Quality Gates with "Clean as You Code" philosophy.** The ability to set measurable, automated pass/fail conditions on new code while ignoring legacy debt is why every enterprise CI/CD pipeline includes SonarQube. It makes quality objective and non-negotiable.

## Pricing Model
| Tier | Price | Key Features |
|------|-------|--------------|
| Community (OSS) | Free | 17 languages, basic quality gates |
| Developer | ~$150/year (based on LOC) | Branch analysis, PR decoration |
| Enterprise | Custom (LOC-based) | Portfolio mgmt, security reports, SAST |
| Data Center | Custom | HA, horizontal scaling |
| SonarCloud | Free for OSS; paid for private | Cloud-hosted, no infrastructure |

Pricing is per-instance, per-year, based on lines of code analyzed.

## Distribution Model
- Self-hosted: Docker or manual install (Java-based)
- SonarCloud: SaaS (no install)
- Plugins via marketplace
- SonarLint IDE plugin free for all

## Features to Adopt for PQC Scanner
1. Quality gate concept: "Is this codebase PQC-ready?" pass/fail
2. Historical tracking of PQC migration progress over time
3. "Clean as You Code" -- only flag new crypto introductions as blocking
4. Technical debt quantification ("3 days to migrate to PQC")
5. Portfolio-level views for enterprise multi-project PQC status
6. Rating system (A-E) for PQC readiness

---

# TOOL 4: QUALYS SSL LABS

## Why It's the Go-To for TLS Scanning
SSL Labs wins on **trust, transparency, and simplicity**. The grading methodology is fully public, the tool is free, and an "A+" grade has become an industry-recognized credential. Everyone links to their grade.

## Grading System (A+ to F)

### Score to Grade Mapping
| Score | Grade |
|-------|-------|
| >= 80 | A |
| >= 65 | B |
| >= 50 | C |
| >= 35 | D |
| >= 20 | E |
| < 20 | F |

### Score Calculation (Three Categories)
| Category | Weight | What It Measures |
|----------|--------|------------------|
| Protocol Support | 30% | Which TLS/SSL versions are supported |
| Key Exchange | 30% | Key size, algorithm strength |
| Cipher Strength | 40% | Encryption algorithm strength |

Final score = weighted average of category scores (0-100 each).

### Protocol Scoring
| Protocol | Score |
|----------|-------|
| SSL 2.0 | 0% |
| SSL 3.0 | 80% |
| TLS 1.0 | 90% |
| TLS 1.1 | 95% |
| TLS 1.2 | 100% |
| TLS 1.3 | 100% |

Score = average of best + worst supported protocol.

### Key Exchange Scoring
| Key Size | Score |
|----------|-------|
| < 512 bits | 20% |
| < 1024 bits | 40% |
| < 2048 bits | 80% |
| < 4096 bits | 90% |
| >= 4096 bits | 100% |
| Anonymous/Weak Debian key | 0% |

### Cipher Strength Scoring
| Strength | Score |
|----------|-------|
| 0 bits (none) | 0% |
| < 128 bits | 20% |
| < 256 bits | 80% |
| >= 256 bits | 100% |

### A+ Requirements
- Score >= 80/100
- No warnings
- HSTS enabled with max-age >= 6 months
- No SHA1 certificates
- TLS 1.3 supported

### Automatic Grade Caps
| Condition | Capped To |
|-----------|-----------|
| No Forward Secrecy | B |
| No AEAD ciphers | B |
| TLS 1.0 or 1.1 supported | B |
| Weak DH params (<2048 bits) | B |
| RC4 supported | B |
| CRIME vulnerability | C |
| No TLS 1.2 support | C |
| POODLE vulnerability | C |

### Automatic Failures (F)
- SSL 2.0 support
- Insecure renegotiation
- Heartbleed, ROBOT, Ticketbleed vulnerabilities
- Export cipher suites
- DH parameters < 1024 bits
- Only RC4 suites available

## What They Check
- Certificate validity (chain, expiration, domain match, revocation)
- Protocol versions supported
- Cipher suite enumeration and preference order
- Key exchange parameters
- 60+ browser handshake simulations
- Known vulnerability presence (Heartbleed, ROBOT, POODLE, etc.)
- HSTS configuration
- OCSP stapling
- Certificate transparency
- DNS CAA records

## How They Present Results
- Single letter grade prominently displayed (massive, colored)
- Three category scores shown as horizontal bars
- Detailed expandable sections for each check category
- Browser simulation table showing which browsers can connect
- Certificate chain visualization
- Color coding: green (good), yellow (warning), red (bad/fail)
- Full configuration details available for technical deep-dive

## What Makes It Trustworthy
- Methodology is fully public (published rating guide)
- No account required, no login, completely free
- Results are reproducible and deterministic
- Run by Qualys (established security company, founded 1999)
- Used as reference by NIST, PCI DSS auditors, and security professionals
- Regular methodology updates with public announcements
- No commercial upsell pressure on the free tool itself

## BEST Feature
**The letter grade system with transparent, published methodology.** Everyone understands A+ to F. The grading criteria are public, making it auditable and trustworthy. "We got an A+ on SSL Labs" has become a universally recognized security credential.

## Pricing Model
- SSL Labs online test: **Completely free**, no account required
- Qualys CertView (enterprise product): Paid, for continuous monitoring and fleet management
- No CLI tool (web-only for the free version)
- API available for automated testing

## Distribution Model
- Web-based: ssllabs.com/ssltest
- API: api.ssllabs.com (rate-limited, free)
- No downloadable tool (deliberate -- ensures consistent methodology)
- Qualys CertView for enterprise fleet scanning

## Features to Adopt for PQC Scanner
1. **Letter grading system** (A+ to F) for PQC readiness -- this is CRITICAL
2. Transparent, published scoring methodology
3. Category-based scoring (Algorithm Strength, Key Exchange, Protocol Support)
4. Automatic grade caps for known-bad configurations
5. Immediate failure conditions for critical weaknesses
6. Browser/library simulation equivalent ("Can this app negotiate PQC?")
7. Free tier with no login required to build trust and adoption

---

# TOOL 5: OWASP DEPENDENCY-CHECK

## Why It Matters
Dependency-Check wins on **being free, open-source, and NVD-integrated**. It's the baseline SCA tool that every other tool is compared against. No vendor lock-in, no account required.

## How They Identify Vulnerabilities
1. **Evidence collection**: Analyzers inspect each dependency, extracting "evidence" (vendor, product, version info)
2. **CPE identification**: Evidence is matched to Common Platform Enumeration (CPE) identifiers
3. **CVE lookup**: CPE is matched against the NVD database to find associated CVEs
4. **Confidence scoring**: Each match has a confidence level based on evidence quality

### Analyzer Types
- Archive Analyzer (JAR, WAR, EAR)
- Assembly Analyzer (.NET DLLs)
- Node.js/npm Analyzer (package.json, package-lock.json)
- Python Analyzer (requirements.txt, setup.py)
- Ruby Bundler Analyzer (Gemfile.lock)
- CMake, Autoconf analyzers
- Retired.js integration for JavaScript libraries

## NVD Integration
- **API-based** (since v9.0.0, moved from NVD data feeds to NVD API)
- Maintains local copy of NVD CVE data
- Default: local H2 database
- Optional: PostgreSQL, MySQL for shared/enterprise use
- Automatic daily updates from NVD
- NVD API key supported for higher rate limits
- Supplemental data sources: NPM Audit, RetireJS, OSS Index

## Report Format
- **HTML**: Rich visual report with dependency listing, CVE details, severity badges
- **JSON**: Machine-parseable for CI/CD integration
- **XML**: Legacy format, still supported
- **CSV**: Spreadsheet-friendly
- **SARIF**: For GitHub Advanced Security integration
- **JUnit XML**: For test framework integration

### Report Contents
- Project name and scan date
- Per-dependency listing with:
  - File path and hash
  - Identified CPE
  - Associated CVEs with CVSS scores
  - CVE descriptions and references
  - Confidence level of the match
  - Evidence used for identification
- Summary statistics: total dependencies, vulnerable count, CVE count by severity
- Suppressed vulnerabilities section

## Suppression System
- XML-based suppression file
- Suppress by: CVE ID, CPE, GAV (Group/Artifact/Version), file path, SHA1
- Justification notes supported in suppression entries
- Shared suppression files across projects

## BEST Feature
**Zero vendor lock-in with direct NVD integration.** It's completely free, open-source (Apache 2.0), uses the same data source (NVD) that every commercial tool ultimately relies on, and produces standard output formats. It's the "honest baseline" of dependency scanning.

## Pricing Model
- **Completely free** and open-source (Apache 2.0 license)
- No paid tier, no commercial variant
- NVD API key is free but requires registration with NIST

## Distribution Model
- CLI: Download from GitHub releases
- Maven plugin: `org.owasp:dependency-check-maven`
- Gradle plugin: `org.owasp.dependencycheck`
- Ant task
- Jenkins plugin
- GitHub Action
- Docker image available

## Features to Adopt for PQC Scanner
1. Evidence-based identification (collect "evidence" of crypto usage, then match)
2. CPE-like identifier system for cryptographic algorithms
3. Suppression XML file format for known acceptable uses
4. Multiple report formats (HTML, JSON, SARIF)
5. Local database of known-weak algorithms (like their NVD mirror)
6. Confidence scoring on detection accuracy
7. Open-source, no-account-required distribution

---

# PLATFORM COMPARISON: GitHub Alternatives

## GitLab

### Cloud (gitlab.com)
- **Free tier**: 5GB storage, 400 CI/CD minutes/month, unlimited public/private repos
- **Premium**: $29/user/month -- merge request approvals, code review analytics
- **Ultimate**: $99/user/month -- security scanning (SAST, DAST, SCA), compliance
- **CI/CD**: Native, best-in-class. YAML pipeline definitions, shared runners, Docker-based
- **Strength**: Complete DevOps platform (planning -> monitoring in one tool)
- **Concern**: Source-available (not fully open source for EE features)

### Self-Hosted (GitLab CE)
- Community Edition is fully open source (MIT license)
- Enterprise Edition features are source-available but proprietary-licensed
- Requires significant infrastructure (PostgreSQL, Redis, Sidekiq, etc.)
- CI/CD: Full support with self-hosted runners
- **Best for**: Organizations needing full control + complete DevOps suite

## Codeberg

- **Pricing**: Completely free, donation-supported nonprofit
- **Platform**: Runs on Forgejo (hard fork of Gitea)
- **CI/CD**: Woodpecker CI at ci.codeberg.org + Forgejo Actions (public alpha)
- **Governance**: Democratic, nonprofit (registered in Germany, e.V.)
- **Strengths**:
  - Ethical, non-commercial, privacy-respecting
  - Good GitHub-like UX (Forgejo is user-friendly)
  - Growing FOSS community
- **Weaknesses**:
  - CI/CD not yet reliable for production use
  - Smaller community, fewer integrations
  - Woodpecker team instability (Crow CI fork)
- **Best for**: FOSS projects wanting ethical hosting

## SourceHut

- **Pricing**: $3/month (paid beta), will be free for FOSS when out of beta
- **CI/CD**: builds.sr.ht -- runs in isolated VMs, YAML manifests
- **Philosophy**: Minimalist, Unix-philosophy, mailing-list based
- **Workflow**: Uses `git send-email` patches instead of PRs
- **Strengths**:
  - Extremely fast, lightweight, no JavaScript required
  - Pure open source
  - Native CI/CD with VM-based isolation
  - Accessible via plain email (no web browser needed)
- **Weaknesses**:
  - Patch-based workflow unfamiliar to most developers
  - Small community
  - Minimal web UI
- **Best for**: Linux kernel-style projects, minimalists

## Forgejo

- **Pricing**: Free, open-source (MIT + community governance)
- **CI/CD**: Forgejo Actions (compatible with GitHub Actions ecosystem)
- **Self-hosted**: Very lightweight (single binary, ~100MB RAM)
- **Governance**: Quarterly contributor meetings, transparent roadmap
- **Strengths**:
  - GitHub Actions YAML compatibility (reuse existing workflows)
  - Extremely lightweight to self-host
  - Fork of Gitea with better governance
  - Growing rapidly
- **Weaknesses**:
  - Smaller plugin ecosystem
  - Fewer enterprise features
  - Actions runners need self-hosting
- **Best for**: Self-hosted with GitHub Actions compatibility

## Direct PyPI Distribution (No Git Hosting)

- **Feasibility**: Fully possible. PyPI requires only a source distribution or wheel
- **How it works**:
  - Build with `python -m build`
  - Upload with `twine upload`
  - Source code can live anywhere (or nowhere public)
  - No Git hosting required at all
- **Limitations**:
  - No issue tracker, no PRs, no community contribution workflow
  - No browsable source code
  - pip install works, but developers can't inspect code before installing
  - No CI/CD without separate solution
  - Reduces trust (users prefer browsable source)
- **Best for**: Distribution-only; NOT for open-source community building

## CI/CD Support Summary

| Platform | Native CI/CD | Quality | GitHub Actions Compatible |
|----------|-------------|---------|--------------------------|
| GitLab | YES (best) | Production-grade | No (own format) |
| Codeberg | Partial | Alpha quality | Partial (Forgejo Actions) |
| SourceHut | YES | Good (VM-isolated) | No (own format) |
| Forgejo | YES | Maturing | YES |
| PyPI-only | NO | N/A | N/A |
| GitHub | YES | Production-grade | YES (defines the standard) |

## Recommendation for PQC Scanner

**Primary**: GitHub (largest audience, best CI/CD, most integrations, where security tools are expected to live)

**Secondary**: PyPI distribution (pip install enigma-pqc) -- works regardless of where source is hosted

**Consider**: Codeberg mirror for FOSS credibility, GitLab for enterprise self-hosted deployments

---

# SYNTHESIS: What to Build

## The "Steal List" -- Best Features to Adopt

### From Semgrep (Developer Experience)
1. YAML rule format with target-language patterns
2. `# nopqc` inline suppression comments
3. Multiple output formats (text, JSON, SARIF)
4. VS Code extension with inline findings
5. Online playground for rule testing
6. `--config auto` for zero-config scanning
7. CLI exit codes for CI/CD gating

### From Snyk (Intelligence Layer)
1. Risk scoring (0-1000) combining severity + reachability + exploitability
2. "Is this actually used?" reachability analysis
3. Auto-generated fix PRs with PQC migration code
4. Per-issue PR comments with remediation steps
5. Dependency tree visualization for crypto library chains
6. Scan-on-save IDE integration

### From SonarQube (Enterprise Governance)
1. Quality gates: "Is this codebase PQC-ready?" pass/fail
2. "Clean as You Code" -- only gate on NEW crypto, not legacy
3. Historical trend tracking of PQC migration progress
4. Portfolio view for enterprise multi-project status
5. Technical debt quantification ("X days to full PQC migration")
6. A-E readiness rating per project

### From SSL Labs (Trust & Simplicity)
1. **Letter grading system (A+ to F)** -- THE killer feature for PQC scanner
2. Transparent, published scoring methodology
3. Category-based scoring (Algorithm, Key Exchange, Protocol)
4. Automatic grade caps for known-bad configurations
5. Immediate failure for critical weaknesses (RSA < 2048, MD5, etc.)
6. Free, no-login initial experience to build trust

### From OWASP Dependency-Check (Open Source Credibility)
1. Evidence-based identification with confidence scoring
2. Local database of known-weak algorithms
3. Suppression file for acceptable crypto usage
4. Multiple report formats (HTML, JSON, SARIF)
5. Apache 2.0 or similar permissive license
6. Zero vendor lock-in, zero account required

## The PQC Scanner Differentiator

No existing tool does what we're building:
- **Semgrep** scans for code patterns but knows nothing about PQC
- **Snyk** scans dependencies but doesn't understand cryptographic algorithm migration
- **SonarQube** tracks quality but has no PQC rules
- **SSL Labs** grades TLS but doesn't scan codebases
- **OWASP DC** finds vulnerable dependencies but not vulnerable crypto primitives

**Our gap**: A tool that combines SSL Labs grading (A+ to F for PQC readiness) + Semgrep's developer UX (YAML rules, CLI, IDE) + SonarQube's quality gates (is this codebase PQC-ready?) + Snyk's intelligence (reachability, auto-fix) -- focused entirely on the quantum cryptographic migration problem.

No one else is doing this. The niche is wide open.
