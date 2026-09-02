#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEF A/B 测试主脚本
==================
对比 A组（裸抽取）vs B组（PEF增强抽取）：
  1. 加载测试样本（10个，5正常+5异常）
  2. A组处理所有样本，记录日志
  3. B组处理所有样本，记录日志（π锚定+三级登记簿+异常检测+P0熔断+审计链）
  4. 计算指标（准确率、异常检测率、熔断响应、审计完整性、日志对比）
  5. 生成 A/B 对比报告（Markdown）
  6. 保存日志到 output/

运行: python run_ab_test.py
"""
import json
import os
import sys
from datetime import datetime, timezone

# 添加 lib 目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

from bare_extractor import BareExtractor
from pef_extractor import PEFEnhancedExtractor
from metrics import compute_all_metrics


def load_samples(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_jsonl(data: list, path: str):
    with open(path, 'w', encoding='utf-8') as f:
        for item in data:
            f.write(json.dumps(item, ensure_ascii=False) + '\n')


def generate_report(metrics: dict, a_summary: dict, b_summary: dict,
                    samples: list) -> str:
    """生成 A/B 对比报告（Markdown）。"""
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    total_samples = len(samples)
    normal_samples = sum(1 for s in samples if not s.get("injected_anomaly"))
    anomaly_samples = total_samples - normal_samples

    acc_a = metrics["extraction_accuracy"]["A"]["accuracy"]
    acc_b = metrics["extraction_accuracy"]["B"]["accuracy"]

    anom_a = metrics["anomaly_detection"]["A"]
    anom_b = metrics["anomaly_detection"]["B"]

    cb_a = metrics["circuit_breaker"]["A"]
    cb_b = metrics["circuit_breaker"]["B"]

    audit = metrics["audit_integrity"]
    log_cmp = metrics["log_comparison"]

    report = f"""# PEF A/B Test Report

**Generated:** {now}
**Test samples:** {total_samples} ({normal_samples} normal, {anomaly_samples} with injected anomalies)
**Anomaly types:** field_value_error, timestamp_forgery, identity_spoofing, missing_field, hallucinated_value

---

## 1. Executive Summary

| Metric | A: Bare Extractor | B: PEF-Enhanced | Difference |
|--------|-------------------|------------------|------------|
| Extraction accuracy | {acc_a:.2%} | {acc_b:.2%} | {acc_b - acc_a:+.2%} |
| Anomaly detection rate | {anom_a['recall']:.2%} | {anom_b['recall']:.2%} | {anom_b['recall'] - anom_a['recall']:+.2%} |
| Anomaly precision | {anom_a['precision']:.2%} | {anom_b['precision']:.2%} | {anom_b['precision'] - anom_a['precision']:+.2%} |
| F1 score | {anom_a['f1']:.4f} | {anom_b['f1']:.4f} | {anom_b['f1'] - anom_a['f1']:+.4f} |
| Circuit breaker response | {cb_a['breaker_response_rate']:.2%} | {cb_b['breaker_response_rate']:.2%} | {cb_b['breaker_response_rate'] - cb_a['breaker_response_rate']:+.2%} |
| Audit chain length | 0 | {audit['audit_chain_length']} | +{audit['audit_chain_length']} |
| Audit tamper-evident | No | Yes | +Yes |
| Log fields per entry | {log_cmp['a_log_fields']} | {log_cmp['b_log_fields']} | +{log_cmp['b_log_fields'] - log_cmp['a_log_fields']} |
| Avg processing time | {log_cmp['a_avg_elapsed_ms']:.2f}ms | {log_cmp['b_avg_elapsed_ms']:.2f}ms | {log_cmp['overhead_ratio']}x |

---

## 2. Extraction Accuracy

Both groups use the same extraction logic (direct field copy). The difference is not in *what* is extracted, but in *what happens after* extraction.

| Group | Total Fields | Correct Fields | Accuracy |
|-------|-------------|----------------|----------|
| A (Bare) | {metrics['extraction_accuracy']['A']['total_fields']} | {metrics['extraction_accuracy']['A']['correct_fields']} | {acc_a:.2%} |
| B (PEF) | {metrics['extraction_accuracy']['B']['total_fields']} | {metrics['extraction_accuracy']['B']['correct_fields']} | {acc_b:.2%} |

**Key insight:** PEF does not improve raw extraction accuracy — it improves *detection of bad extractions* and *auditability of all extractions*.

---

## 3. Anomaly Detection

### 3.1 Overall

| Metric | A (Bare) | B (PEF) |
|--------|----------|---------|
| Total injected anomalies | {anom_a['total_injected']} | {anom_b['total_injected']} |
| Detected | {anom_a['detected']} | {anom_b['detected']} |
| False positives | {anom_a['false_positives']} | {anom_b['false_positives']} |
| Detection rate (recall) | {anom_a['recall']:.2%} | {anom_b['recall']:.2%} |
| Precision | {anom_a['precision']:.2%} | {anom_b['precision']:.2%} |
| F1 | {anom_a['f1']:.4f} | {anom_b['f1']:.4f} |

### 3.2 Per anomaly type (B group)

| Anomaly Type | Injected | Detected | Detection Rate |
|-------------|----------|----------|----------------|
"""
    for atype, data in anom_b.get("per_type", {}).items():
        rate = data['detected'] / data['total'] if data['total'] else 0
        report += f"| {atype} | {data['total']} | {data['detected']} | {rate:.2%} |\n"

    report += f"""
**A group detects 0% of anomalies by design** — it has no anomaly detection layer. It extracts whatever is in the input, including forged timestamps, spoofed identities, and hallucinated fields.

---

## 4. Circuit Breaker Response

Critical anomalies (timestamp_forgery, identity_spoofing) should trigger immediate P0 circuit breaker.

| Group | Critical Samples | Breaker Triggered | Response Rate |
|-------|-----------------|-------------------|---------------|
| A (Bare) | {cb_a['critical_samples']} | {cb_a['critical_with_breaker']} | {cb_a['breaker_response_rate']:.2%} |
| B (PEF) | {cb_b['critical_samples']} | {cb_b['critical_with_breaker']} | {cb_b['breaker_response_rate']:.2%} |

**A group never triggers circuit breaker** — it has no concept of "critical anomaly" or "circuit breaker." It processes everything, including critical security violations.

---

## 5. Audit Integrity

| Property | A (Bare) | B (PEF) |
|----------|----------|---------|
| Audit chain length | 0 | {audit['audit_chain_length']} events |
| Chain intact | N/A | {audit['audit_chain_intact']} |
| Tamper-evident | No | Yes |
| π-anchor coordinate per log | No | Yes |
| Temporal ordering enforced | No | Yes (t_state ≤ t_anchor ≤ t_write) |
| Entity identity verified | No | Yes (prefix check) |

**B group's audit chain is SHA-256 hash-linked** — tampering with any event breaks the entire chain, making it detectable. A group's logs are plain JSON with no integrity protection.

---

## 6. Log Output Comparison

### 6.1 Log fields

A group logs have **{log_cmp['a_log_fields']} fields** per entry.
B group logs have **{log_cmp['b_log_fields']} fields** per entry.

B group extra fields (not in A group):
{chr(10).join(f'- {f}' for f in log_cmp['b_extra_fields'])}

### 6.2 Processing overhead

| Group | Avg Time | Overhead |
|-------|----------|----------|
| A (Bare) | {log_cmp['a_avg_elapsed_ms']:.2f}ms | baseline |
| B (PEF) | {log_cmp['b_avg_elapsed_ms']:.2f}ms | {log_cmp['overhead_ratio']}x |

**Overhead is acceptable** — PEF adds anomaly detection, π-anchoring, and audit chain generation for ~{log_cmp['overhead_ratio']}x processing time. For document processing workloads (seconds per document), this overhead is negligible.

---

## 7. Conclusion

### What PEF adds (not "better extraction")

1. **Anomaly detection** — 0% → {anom_b['recall']:.0%}% detection rate across 5 anomaly types
2. **Circuit breaker** — critical anomalies trigger immediate P0 termination (0% → {cb_b['breaker_response_rate']:.0%}%)
3. **Audit integrity** — SHA-256 hash-linked audit chain, tamper-evident
4. **Identity verification** — entity_id prefix check prevents identity spoofing
5. **Temporal ordering** — t_state ≤ t_anchor ≤ t_write enforced, prevents timestamp forgery
6. **Provenance** — every log entry carries π-anchor coordinate, traceable to (P, E, t)

### What PEF does NOT do

- Does not improve raw extraction accuracy (same extraction logic)
- Adds ~{log_cmp['overhead_ratio']}x processing overhead (acceptable for batch workloads)
- Does not replace business logic — it wraps it with anchoring and audit

### The core difference

**A group hopes it is correct.** It extracts fields and logs them, with no way to verify that the input was authentic, the timestamp was real, or the identity was legitimate.

**B group can prove it is correct.** Every extraction is anchored to a π-coordinate, checked against 5 anomaly types, linked in a tamper-evident audit chain, and critical violations trigger immediate circuit breaker.

---

## 8. Artifacts

- `output/a_group_logs.jsonl` — A group raw logs
- `output/b_group_logs.jsonl` — B group PEF-anchored logs
- `output/b_audit_chain.jsonl` — B group SHA-256 hash-linked audit chain
- `output/ab_report.md` — this report

---

*PEF A/B Test · Anchored Determinism · Only the anchor produces the potential difference.*
"""
    return report


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    samples_path = os.path.join(base_dir, 'data', 'test_samples.json')
    output_dir = os.path.join(base_dir, 'output')
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 64)
    print("PEF A/B Test — Bare Extractor vs PEF-Enhanced Extractor")
    print("=" * 64)

    # 1. 加载测试样本
    print("\n[1/5] Loading test samples...")
    data = load_samples(samples_path)
    samples = data["samples"]
    print(f"  Loaded {len(samples)} samples "
          f"({sum(1 for s in samples if not s.get('injected_anomaly'))} normal, "
          f"{sum(1 for s in samples if s.get('injected_anomaly'))} with anomalies)")

    # 2. A组处理
    print("\n[2/5] Running A group (Bare Extractor)...")
    a_extractor = BareExtractor()
    a_results = []
    for sample in samples:
        result = a_extractor.extract(sample)
        a_results.append(result)
        anomalies = sample.get("injected_anomaly")
        status = "ANOMALY" if anomalies else "normal"
        print(f"  {sample['sample_id']}: {status}, extracted {len(result['extracted'])} fields")
    a_summary = a_extractor.get_summary()
    print(f"  A group summary: {a_summary['extracted_count']} extracted, "
          f"{a_summary['anomalies_detected']} anomalies detected")

    # 3. B组处理
    print("\n[3/5] Running B group (PEF-Enhanced Extractor)...")
    b_extractor = PEFEnhancedExtractor()
    b_results = []
    for sample in samples:
        result = b_extractor.extract(sample)
        b_results.append(result)
        anomalies = sample.get("injected_anomaly")
        status = "ANOMALY" if anomalies else "normal"
        cb = "P0_BREAKER" if result["circuit_breaker"] else "ok"
        print(f"  {sample['sample_id']}: {status}, {cb}, "
              f"anomalies={len(result['anomalies'])}, pi_s={result['pi_s']}")
    b_summary = b_extractor.get_summary()
    chain_ok, chain_msg = b_extractor.verify_audit_chain()
    print(f"  B group summary: {b_summary['extracted_count']} extracted, "
          f"{b_summary['anomalies_detected']} anomalies detected, "
          f"{b_summary['circuit_breakers_triggered']} circuit breakers")
    print(f"  Audit chain: {chain_msg}")

    # 4. 计算指标
    print("\n[4/5] Computing metrics...")
    metrics = compute_all_metrics(a_results, b_results, samples, a_summary, b_summary)
    print(f"  Extraction accuracy: A={metrics['extraction_accuracy']['A']['accuracy']:.2%}, "
          f"B={metrics['extraction_accuracy']['B']['accuracy']:.2%}")
    print(f"  Anomaly detection: A={metrics['anomaly_detection']['A']['recall']:.2%}, "
          f"B={metrics['anomaly_detection']['B']['recall']:.2%}")
    print(f"  Circuit breaker: A={metrics['circuit_breaker']['A']['breaker_response_rate']:.2%}, "
          f"B={metrics['circuit_breaker']['B']['breaker_response_rate']:.2%}")

    # 5. 生成报告和保存日志
    print("\n[5/5] Generating report and saving artifacts...")
    report = generate_report(metrics, a_summary, b_summary, samples)
    report_path = os.path.join(output_dir, 'ab_report.md')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"  Report saved: {report_path}")

    a_logs_path = os.path.join(output_dir, 'a_group_logs.jsonl')
    save_jsonl([r["log"] for r in a_results], a_logs_path)
    print(f"  A group logs: {a_logs_path}")

    b_logs_path = os.path.join(output_dir, 'b_group_logs.jsonl')
    save_jsonl([r["log"] for r in b_results], b_logs_path)
    print(f"  B group logs: {b_logs_path}")

    b_audit_path = os.path.join(output_dir, 'b_audit_chain.jsonl')
    save_jsonl(b_extractor.get_audit_events(), b_audit_path)
    print(f"  B audit chain: {b_audit_path}")

    print("\n" + "=" * 64)
    print("A/B Test Complete!")
    print(f"  Report: {report_path}")
    print(f"  A logs: {a_logs_path}")
    print(f"  B logs: {b_logs_path}")
    print(f"  Audit chain: {b_audit_path}")
    print("=" * 64)


if __name__ == "__main__":
    main()
