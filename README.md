# PEF Core Reference — Production Kernel (Desensitized)

> **Source**: https://github.com/banbanry/pef-core-reference
> **Author**: banbanry (沈鹭)
> **License**: MIT
> **PEF Architecture**: Anchored Determinism Meta-Architecture — 唯锚才有势差产生 (Only the anchor produces potential difference)
> **Main repo**: [pef-architecture](https://github.com/banbanry/pef-architecture)

The **production PEF kernel**, extracted from the CLE V3.9 deployment and desensitized for public release.
This is the runnable counterpart to the theory in `pef-architecture` — **19 modules, ~3,600 lines**.

## Quick Start (30 seconds)

```bash
git clone https://github.com/banbanry/pef-core-reference.git
cd pef-core-reference
pip install -r requirements.txt
python demo_minimal.py
```

**Expected output (last line):**

```
SELF-CHECK: 8/8 PASS
Ledger: 4 entries, tail=xxxx...
```

Exit code `0` = PASS. This is the machine-extractable acceptance signal.

## What this repo contains

| Layer | Modules | Lines | Role |
|---|---|---|---|
| **π anchor core** | `secure_pi_provider.py`, `sharded_pi_coordinator.py` | ~174 | Unforgeable π-anchor coordinates; MOD3 domain scheduling |
| **Operator library** | `pef_operators.py`, `python_operators.py`, `signature_library.py`, `signature_library_data.py`, `base_operator.py` | ~1,399 | 720+ signature patterns; P/E/F/M layered operators |
| **Evidence & audit** | `ds_evidence_fusion.py`, `audit_log_chain.py`, `onion_pipeline.py` | ~477 | Dempster/Yager fusion; 3-level ledger; onion pipeline veto |
| **L1–L3 pipeline** | `cle_base_layer.py`, `layer2_ai_review.py`, `cle_v38_engine.py`, `scene_adapter.py`, `cle_deploy.py` | ~1,139 | Deterministic L1, AI L2 with deterministic fallback, L3 canary |
| **Byzantine tests** | `byzantine_tests.py` | 255 | 11/11 real adversarial scenarios (S5=0.0) |
| **Closed-loop engine** | `pef_cl_engine.py`, `pef_cl_e2e.py` | — | Tier-2/3 executable engine; real e2e results in `pef-architecture/01-core-spec` |
| **Demo** | `demo_minimal.py` | — | 8/8 self-check; P0 circuit breaker; tamper detection |

## Verified results (from the CLE V3.9 deployment)

- **Regression**: 49/49 PASS
- **Byzantine**: 11/11 PASS (S5=0.0)
- **Signature library**: 720 entries, hash-integrity OK
- **Feature non-regression**: malloc-P0 / division-P0 / empty-input-GAMMA all correct
- **Real scan**: 95 findings on a ~1,100-line C++17 codebase (P0=4, P1=91) — previously 0 by the legacy pipeline

## Reproducing the real scan

```bash
python core/cle_deploy.py scan <source_dir>   # run PEF operators on any codebase
```

## Relationship to pef-architecture

```
pef-architecture (theory + evidence)
├─ 01-core-spec        design specs (3-tier closed-loop engine, primitives, axioms)
├─ 02-applications     CIC / PIMEM / π-anchor applications
├─ 03-operator-library 800+ operator taxonomy
├─ 04-engineering-cases CLE deployment, 95-finding report
└─ 05-references       external grounding
        │
        ▼
pef-core-reference (this repo — runnable production kernel)
├─ core/               19 modules extracted & desensitized
├─ demo_minimal.py     8/8 self-check entry
└─ requirements.txt
```

## Integrity & watermark

- Every module carries the PEF header watermark (`Anchored Determinism Meta-Architecture`).
- Source provenance: https://github.com/banbanry/pef-architecture (MIT).
- Desensitized: no customer names, no business data, no patent/schematic details.
- If you fork or reuse, retain the header watermark and source attribution.

## License

MIT © 2026 banbanry (沈鹭). See LICENSE in the main repository.
