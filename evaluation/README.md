# PEF A/B Test

A/B test comparing **Bare Extractor** (no PEF) vs **PEF-Enhanced Extractor** (π-anchored + three-tier ledger + anomaly detection + P0 circuit breaker + SHA-256 audit chain).

## Quick Start

```bash
pip install -r requirements.txt
python run_ab_test.py
```

## Test Design

### Samples
10 test samples (desensitized generic entity extraction task):
- 5 normal samples
- 5 samples with injected anomalies:
  - `field_value_error` — wrong field value in input
  - `timestamp_forgery` — input timestamp claims to be from the past
  - `identity_spoofing` — entity_id does not match known prefix
  - `missing_field` — required field absent from input
  - `hallucinated_value` — extra field not in ground truth

### Group A: Bare Extractor
- Direct field extraction, no validation
- Trusts input timestamp (forgeable)
- Trusts input identity (spoofable)
- No anomaly detection
- No audit chain
- No circuit breaker

### Group B: PEF-Enhanced Extractor
- π-anchor allocation (`PiSDispatcher`, one-time, domain by π%3)
- `PEFmod` read-only state snapshot with structural SHA-256 hash
- Three-tier ledger (axiom readonly / runtime read-write / audit append-only)
- Temporal ordering enforcement (`t_state ≤ t_anchor ≤ t_write`)
- 5-layer anomaly detection (field value / timestamp / identity / missing / hallucination)
- P0 circuit breaker (CRITICAL anomaly → immediate termination)
- SHA-256 hash-linked audit chain (tamper-evident)

## Metrics

1. **Extraction accuracy** — correct fields / total fields
2. **Anomaly detection** — precision / recall / F1
3. **Circuit breaker response** — critical anomalies that trigger P0
4. **Audit integrity** — chain length, tamper-evident, π-anchor coordinate
5. **Log output comparison** — fields per entry, processing overhead

## Output

```
output/
├── ab_report.md           # Full A/B comparison report
├── a_group_logs.jsonl     # A group raw logs
├── b_group_logs.jsonl     # B group PEF-anchored logs
└── b_audit_chain.jsonl    # B group SHA-256 hash-linked audit chain
```

## Project Structure

```
pef-ab-test/
├── run_ab_test.py         # Main test script
├── requirements.txt       # Dependencies
├── README.md             # This file
├── data/
│   └── test_samples.json  # 10 test samples (5 normal + 5 anomalies)
├── lib/
│   ├── bare_extractor.py  # A group: bare extractor (no PEF)
│   ├── pef_extractor.py   # B group: PEF-enhanced extractor
│   └── metrics.py         # Metric computation
└── output/                # Test results (generated)
```

## The Core Question

Does PEF improve extraction? **No.** Both groups use the same extraction logic and achieve the same raw accuracy.

What PEF adds is **detectability and auditability**:
- A group *hopes* it is correct — no way to verify input authenticity
- B group *can prove* it is correct — every extraction is π-anchored, anomaly-checked, and hash-linked

---

*PEF A/B Test · Anchored Determinism · Only the anchor produces the potential difference.*
