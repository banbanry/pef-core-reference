# PEF Core — Reference Implementation

> **Anchored Determinism: only the anchor produces the potential difference.**

Reference implementation of the PEF (Primary Entity – Execution Variable – Final Result) meta-architecture, extracted from a production deployment.

This is **not a framework or library** — it is a working reference of the PEF kernel patterns: π-anchoring, three-tier ledger, triad P/E/F, MOD3 interrogation, and axiomatic circuit breaking.

---

## Quick Start

```bash
pip install -r requirements.txt
python demo_minimal.py
```

The demo demonstrates in ~50 lines:
1. **PEFmod creation** — read-only state snapshot with domain tag (P/E/F)
2. **π-anchor allocation** — unforgeable, irreversible, globally unique
3. **Three-tier ledger recording** — axiom (readonly) / runtime (read-write) / audit (append-only)
4. **Self-check** — 8 verification items: anchor validity, domain consistency, one-to-one binding, temporal ordering, audit hash integrity
5. **Circuit breaker** — duplicate anchor binding triggers P0 termination
6. **Archive** — archived anchors can never be reused

---

## Architecture

```
PEF Meta-Architecture: Anchor → Potential Difference → Triad

┌─────────────────────────────────────────────────────────┐
│  Anchor Layer: π (transcendental number)                │
│  · Unforgeable  · Irreversible  · Globally unique       │
└──────────────────────────┬──────────────────────────────┘
                           │ produces potential difference
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Triad Layer: P · E · F                                  │
│  P = Primary Entity (subject)                            │
│  E = Execution Variable (E_in controllable / E_out not) │
│  F = Final Result (traceable to (P, E, t))              │
└──────────────────────────┬──────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────┐
│  Three-Tier Ledger                                       │
│  1. Axiom Ledger    — readonly, immutable facts         │
│  2. Runtime Ledger  — read-write, Πₛ-keyed entries     │
│  3. Audit Ledger    — append-only, SHA-256 hash chain  │
└─────────────────────────────────────────────────────────┘
```

---

## Core Modules

| Module | Purpose | Key concepts |
|--------|---------|-------------|
| `pefmod.py` | PEFmod primitive + Πₛ anchor dispatcher | One-to-one binding, domain consistency (π%3), temporal ordering |
| `state_ledger.py` | Three-tier ledger (axiom/runtime/audit) | Anchored write timing, self-check, append-only audit |
| `pi_constants.py` | π sequence, E_in/E_out field classification | Π₀ isolation, π mantissa static library with integrity fingerprint |
| `pef_shadow_graph.py` | Shadow graph protocol | Interface + PiAnchor + SafetyResult + BehaviorHash injection |
| `software_state_vector.py` | State vector with deviation rate ρ | Geometric adjudication: ρ ≤ λ → PASS, λ driven by MOD3 |
| `information_entropy.py` | Information entropy pollution detection | Shannon entropy, single-value column handling |
| `pi_tools.py` | π-density grid projection | Column-to-π-grid mapping, deviation rate computation |
| `abstract_auditor.py` | Auditor abstract interface | Business logic decoupled from PEF kernel |

---

## The Eight Axioms (Software PEF)

Violation of any axiom triggers **熔断 (circuit breaker)** — immediate termination, no graceful degradation.

| Axiom | Statement |
|-------|-----------|
| **A1** Unforgeability | Unforgeable coordinate must come from external π-source. Self-computation of π-digits triggers熔断. |
| **A2** Triad Completeness | Every computation must explicitly declare P, E, and F. |
| **A3** Variable Partition | E must be partitioned into E_in and E_out. Mixed variables trigger熔断. |
| **A4** Temporal Causality | Discrete irreversible time steps. Result cannot precede cause. |
| **A5** π-Anchor Binding | Every code entity must bind to a unique π-anchor interval. |
| **A6** Anchor Monotonicity | Consumed π-bits cannot be skipped or returned. |
| **A7** Audit Traceability | Every F must be traceable to (P, E, t). |
| **A8** Memory Alignment | Cross-language memory layout aligned to anchor coordinate. |

---

## Desensitization Note

This is the **public reference version**. All domain-specific field names (logistics, customs, document processing) have been replaced with generic placeholders. The PEF architecture patterns — π-anchoring, three-tier ledger, triad P/E/F, MOD3 interrogation, axiomatic circuit breaking — are preserved intact.

To integrate into a specific domain:
1. Replace `ENTITY_ID_PREFIXES`, `FEATURE_KEYWORDS` in `pi_constants.py`
2. Replace `PEF_E_IN_FIELDS`, `PEF_E_OUT_FIELDS` with your schema
3. Implement `AbstractAuditor` with your business rules
4. Configure `framework_config.json` with your thresholds

---

## Relationship to PEF Architecture Theory

This repository is the **software PEF (π-anchored)** reference implementation. The meta-architecture theory, boundary map, non-obviousness argument, and physical PEF (thermodynamics-anchored) instantiation are documented in:

**[PEF Architecture — Theory Repository](https://github.com/banbanry/pef-architecture)**

---

## License

MIT License

---

*PEF Core · Reference Implementation · Only the anchor produces the potential difference. No anchor, no variable. No trace, no result.*
