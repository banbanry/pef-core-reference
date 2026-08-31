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

**Expected output (exit code 0, last line machine-extractable):**
```
[场景1] 正常流程：PEFmod创建 → Πₛ分配(域匹配) → 三级登记簿record()
  ① 创建 PEFmod: domain=P, state_hash=5505f831281b…, t_state=...
  ② 分配 Πₛ=3, 域=P (π%3=0), t_anchor=...
  ③ record() → status=CONFIRMED, seq=1, t_write=...
     时序: t_state ≤ t_anchor ≤ t_write

[场景2] 攻击1：未锚定写入（绕过Πₛ分配直接record）
  ✅ P0熔断: P0: Πₛ=99999 无效或未活动，禁止登记（引用未来态）

[场景3] 攻击2：篡改审计条目（修改detail字段）
  ✅ 哈希不一致: True（篡改被检测）

[场景4] 攻击3：域不匹配（PEFmod声明P，但Πₛ域≠P）
  ✅ 三重一致性失败: P0: 三重一致性失败 Πₛ=4 π%3=1→E, domain_tag=P

[场景5] 归档后锚不可复用（铁律7）
  归档后 is_active=False（应为False）

SELF-CHECK (8 items):
  [PASS] Πₛ合法性-运行时条目
  [PASS] 域一致性-铁律1
  [PASS] 一对一-Πₛ主键唯一
  [PASS] 时序-状态≤锚≤写入
  [PASS] 时序-写入序号单调
  [PASS] 审计-防篡改哈希一致
  [PASS] Π₀隔离-登记簿不承载Π₀
  [PASS] 公理层-只读契约

SELF-CHECK: 8/8 PASS
```

The demo (`demo_minimal.py`, ~600 lines) is extracted from the production PEF_Core codebase and demonstrates:
1. **PEFmod creation** — read-only state snapshot with domain tag (P/E/F), structural SHA-256 hash
2. **Πₛ anchor allocation** — `PiSDispatcher.allocate()`: one-time, non-reentrant, domain by π%3
3. **Three-tier ledger recording** — `PEF_StateLedger.record()`: axiom (readonly) / runtime (read-write) / audit (append-only)
4. **Anchored write timing** — `t_state ≤ t_anchor ≤ t_write`, violation → P0 circuit breaker
5. **Self-check** — 8 verification items: anchor validity, domain consistency (铁律1), one-to-one binding, temporal ordering, audit hash integrity, Π₀ isolation, axiom readonly
6. **Attack demonstrations** — unanchored write → P0, audit tampering → hash mismatch, domain mismatch → triple-consistency failure
7. **Archive** — archived anchors can never be reused (铁律7, non-reuse of fault π)

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
