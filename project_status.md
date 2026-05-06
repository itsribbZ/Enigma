# Enigma — Project Status

## Session: Phase 9 Vault Blueprint (Godspeed + Cycle) — 2026-04-09

**Completed**:
- Godspeed dispatch → 4 parallel Sonnet research agents (PQC tooling / hardware / adversarial reality / CRQC timeline), 42+ T1-T3 sourced findings
- Cycle skill 3-pass refinement (Cycle 1 inventory compressed via pre-gathered context per SL-006; Cycle 2 single refinement agent on age/restic/cryptomator patterns + OWASP Argon2id + zeroize-python + python-fido2; Cycle 3 synthesis)
- `research/Enigma_Phase9_Vault_Cycle_Blueprint.pdf` — 30 pages, 74.4 KB, 14 sections + 2 appendices, zero BifrostPDF API errors
- `tools/generate_phase9_cycle_blueprint.py` — ~630-line regenerator
- `research/phase9_session_handoff.md` — resume doc with 5 build paths, critical reminders, expected file tree
- Memory seeded: `user_quantum_defense_goals.md`, `project_enigma_structure.md`, `MEMORY.md` index
- Godspeed + Cycle learnings written with structured v2.0 format + incremental checkpoint discipline
- Cycle state checkpoint at `~/.claude/skills/cycle/.state/cycle_enigma_vault_20260409.json`
- SL-055 promoted to shared learnings (prior-phase audit files as anti-pattern source)

**In-Progress**:
- Phase 9.1 vault CLI scaffold — NOT started, awaiting user build path choice (A/B/C/D/E)

**Decisions**:
- Argon2id recalibrated to **m=64 MiB, t=3, p=1** (NOT original m=256 MB, t=4, p=4) per OWASP 2025/2026 + timing leak avoidance
- Hybrid KEM = **X25519 + ML-KEM-768** (X-Wing pattern, real-world default) — NOT ML-KEM-1024
- Core abstraction = **age Recipient/Identity** two-method interface split (stolen wholesale)
- Chunk MAC = **chunk index as AAD** (Cryptomator pattern, no separate MAC pass)
- Duress = **second SLIP-0039 share set** (NOT branching flag — structurally invisible to attacker)
- Memory safety = **zeroize-python 1.1.2 (Rust-backed) + bytearray throughout** — NEVER bytes for key material
- YubiKey 5.7+ **MANDATORY** — EUCLEAK (CVE-2024-45678) breaks all pre-5.7
- DevTeam 7 Laws pre-implementation score: **32/35** (vs. 16/35 unrefined baseline)
- Phase 9 roadmap: 7 sub-phases (9.1 CLI → 9.2 YubiKey → 9.3 Shamir → 9.4 external Qubes → 9.5 footprint → 9.6 network → 9.7 Rust port), ~8-10 sessions total, MVP in 1-2

**Next Session**:
1. **Read `research/phase9_session_handoff.md` FIRST** — has exact resume steps, 5 build paths, critical reminders
2. User picks build path A-E from the handoff doc
3. If A (scaffold 9.1): create `enigma_vault/` package tree, pyproject.toml + mypy strict, core/interfaces.py (Recipient/Identity ABCs), core/secret.py (SecretBytes mlock+zeroize), crypto/hybrid_kem.py (XWing), crypto/aead.py (index-as-AAD), crypto/kdf.py (Argon2id+HKDF), cli.py, 30+ pytest cases, extends `phases/phase5_pqc/pqc_lattice.py`
4. If C (skip to 9.5 footprint): DSAR template generator, Incogni/Optery subscription, account deletion tracker — no crypto code
5. If E (hardware first): order ThinkPad T480 + YubiKey 5.7+ x2 + Nitrokey 3 + Cryptosteel plates (~$500-700)

**CRITICAL reminders do-not-lose**:
- YubiKey firmware 5.7+ check (EUCLEAK kills anything older)
- Argon2id params are 64 MiB / 3 / 1 (corrected from initial paranoia numbers)
- ML-KEM-768 not 1024
- Chunk index as AAD on every chunk
- Duress vault = second share set, not flag
- US 5th Amendment protects passphrase (mostly); UK RIPA compels keys — don't travel with device
- Phase 6 audit (`research/audit_phases6_8.md`) has 48 anti-patterns Phase 9 must explicitly avoid

**Tools deployed this session**: godspeed, cycle, Agent x5 (all Sonnet), Write x8, Read x6, Edit x4, TaskCreate x5, TaskUpdate x6, Bash, context7 resolve, ToolSearch, Glob x5, Grep

**Session metrics**: ~20 min wall clock · 32/35 DevTeam · Cycle 3 score 9.5/10 · PDF 74.4 KB · zero BifrostPDF API errors
