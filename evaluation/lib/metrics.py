#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A/B 测试指标计算模块
====================
对比 A组（裸抽取）和 B组（PEF增强）的各项指标：
  1. 抽取准确率
  2. 异常检测率 / 精确率 / 召回率
  3. 熔断响应率
  4. 审计完整性
  5. 日志产出对比
  6. 平均处理时间
"""
import json
from typing import Any, Dict, List, Tuple


def compute_extraction_accuracy(results: List[Dict[str, Any]],
                                 samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算抽取准确率：正确字段数 / 总字段数。"""
    sample_map = {s["sample_id"]: s for s in samples}
    total_fields = 0
    correct_fields = 0
    per_sample = []

    for r in results:
        sid = r["sample_id"]
        sample = sample_map.get(sid)
        if not sample:
            continue
        gt = sample["ground_truth"]
        extracted = r.get("extracted", {})
        sample_total = len(gt)
        sample_correct = sum(1 for f, v in gt.items() if extracted.get(f) == v)
        total_fields += sample_total
        correct_fields += sample_correct
        per_sample.append({
            "sample_id": sid,
            "total": sample_total,
            "correct": sample_correct,
            "accuracy": round(sample_correct / sample_total, 4) if sample_total else 0,
        })

    return {
        "total_fields": total_fields,
        "correct_fields": correct_fields,
        "accuracy": round(correct_fields / total_fields, 4) if total_fields else 0,
        "per_sample": per_sample,
    }


def compute_anomaly_detection(results: List[Dict[str, Any]],
                               samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算异常检测指标：检测率、精确率、召回率。"""
    sample_map = {s["sample_id"]: s for s in samples}

    total_injected = 0  # 注入的异常总数
    detected = 0        # 检测到的异常数
    false_positives = 0  # 误报数
    per_type = {}

    for r in results:
        sid = r["sample_id"]
        sample = sample_map.get(sid)
        if not sample:
            continue

        injected = sample.get("injected_anomaly")
        detected_anomalies = r.get("anomalies", [])
        detected_types = {a["type"] for a in detected_anomalies}

        if injected:
            total_injected += 1
            injected_type = injected["type"]
            if injected_type in detected_types:
                detected += 1
            per_type[injected_type] = per_type.get(injected_type, {"total": 0, "detected": 0})
            per_type[injected_type]["total"] += 1
            if injected_type in detected_types:
                per_type[injected_type]["detected"] += 1
        else:
            # 正常样本，如果检测到异常就是误报
            if detected_anomalies:
                false_positives += len(detected_anomalies)

    total_detections = detected + false_positives
    precision = round(detected / total_detections, 4) if total_detections else 0
    recall = round(detected / total_injected, 4) if total_injected else 0
    f1 = round(2 * precision * recall / (precision + recall), 4) if (precision + recall) else 0

    return {
        "total_injected": total_injected,
        "detected": detected,
        "false_positives": false_positives,
        "detection_rate": recall,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "per_type": per_type,
    }


def compute_circuit_breaker(results: List[Dict[str, Any]],
                             samples: List[Dict[str, Any]]) -> Dict[str, Any]:
    """计算熔断响应：CRITICAL异常是否触发熔断。"""
    sample_map = {s["sample_id"]: s for s in samples}
    critical_samples = 0
    critical_with_breaker = 0

    for r in results:
        sid = r["sample_id"]
        sample = sample_map.get(sid)
        if not sample:
            continue
        injected = sample.get("injected_anomaly")
        if injected and injected["type"] in ("timestamp_forgery", "identity_spoofing"):
            critical_samples += 1
            if r.get("circuit_breaker"):
                critical_with_breaker += 1

    return {
        "critical_samples": critical_samples,
        "critical_with_breaker": critical_with_breaker,
        "breaker_response_rate": round(critical_with_breaker / critical_samples, 4) if critical_samples else 0,
    }


def compute_audit_integrity(b_summary: Dict[str, Any]) -> Dict[str, Any]:
    """计算审计完整性：B组的审计链是否可验证、不可篡改。"""
    return {
        "audit_chain_length": b_summary.get("audit_chain_length", 0),
        "audit_chain_intact": b_summary.get("audit_chain_intact", False),
        "tamper_evident": b_summary.get("tamper_evident", False),
    }


def compute_log_comparison(a_logs: List[Dict[str, Any]],
                            b_logs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """对比日志产出：字段数、信息量、可追溯性。"""
    a_fields = set()
    b_fields = set()
    for log in a_logs:
        a_fields.update(log.keys())
    for log in b_logs:
        b_fields.update(log.keys())

    a_avg_elapsed = sum(l.get("elapsed_ms", 0) for l in a_logs) / len(a_logs) if a_logs else 0
    b_avg_elapsed = sum(l.get("elapsed_ms", 0) for l in b_logs) / len(b_logs) if b_logs else 0

    return {
        "a_log_fields": len(a_fields),
        "b_log_fields": len(b_fields),
        "b_extra_fields": sorted(b_fields - a_fields),
        "a_avg_elapsed_ms": round(a_avg_elapsed, 2),
        "b_avg_elapsed_ms": round(b_avg_elapsed, 2),
        "overhead_ratio": round(b_avg_elapsed / a_avg_elapsed, 2) if a_avg_elapsed else 0,
    }


def compute_all_metrics(a_results: List[Dict[str, Any]],
                         b_results: List[Dict[str, Any]],
                         samples: List[Dict[str, Any]],
                         a_summary: Dict[str, Any],
                         b_summary: Dict[str, Any]) -> Dict[str, Any]:
    """计算所有指标。"""
    return {
        "extraction_accuracy": {
            "A": compute_extraction_accuracy(a_results, samples),
            "B": compute_extraction_accuracy(b_results, samples),
        },
        "anomaly_detection": {
            "A": compute_anomaly_detection(a_results, samples),
            "B": compute_anomaly_detection(b_results, samples),
        },
        "circuit_breaker": {
            "A": compute_circuit_breaker(a_results, samples),
            "B": compute_circuit_breaker(b_results, samples),
        },
        "audit_integrity": compute_audit_integrity(b_summary),
        "log_comparison": compute_log_comparison(
            [r["log"] for r in a_results],
            [r["log"] for r in b_results]),
    }
