#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
A组：裸抽取器（Bare Extractor）
================================
没有 PEF 锚定、没有三级登记簿、没有审计链、没有异常检测。
直接从输入提取字段，记录简单日志。时间戳直接信任输入（可伪造）。

这是对照组：模拟普通 LLM 抽取流水线的行为。
"""
import json
import time
from typing import Any, Dict, List


class BareExtractor:
    """裸抽取器：直接提取，无审计，无异常检测。"""

    def __init__(self):
        self.logs: List[Dict[str, Any]] = []
        self.extracted_count = 0

    def extract(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """从输入样本提取字段。直接复制 raw_fields，不做任何校验。"""
        start_time = time.time()
        input_data = sample["input"]

        # 直接提取：信任输入的所有字段，包括可能伪造的 timestamp 和 entity_id
        extracted = dict(input_data["raw_fields"])

        # 如果输入有幻觉字段（field_extra），也会被直接提取
        # （裸抽取器不知道什么是"幻觉"，有什么提什么）

        elapsed_ms = (time.time() - start_time) * 1000

        # 简单日志：只有时间戳和提取结果，没有审计链
        log_entry = {
            "log_id": len(self.logs) + 1,
            "timestamp": input_data["timestamp"],  # 直接信任输入时间戳（可伪造）
            "entity_id": input_data["entity_id"],   # 直接信任输入身份（可欺骗）
            "sample_id": sample["sample_id"],
            "action": "EXTRACT",
            "extracted_fields": extracted,
            "field_count": len(extracted),
            "elapsed_ms": round(elapsed_ms, 2),
            "anomaly_detected": False,  # 裸抽取器永远不检测异常
            "circuit_breaker": "NOT_TRIGGERED",
        }
        self.logs.append(log_entry)
        self.extracted_count += 1

        return {
            "sample_id": sample["sample_id"],
            "extracted": extracted,
            "log": log_entry,
        }

    def get_logs(self) -> List[Dict[str, Any]]:
        return self.logs

    def get_summary(self) -> Dict[str, Any]:
        return {
            "group": "A (Bare Extractor)",
            "total_samples": len(self.logs),
            "extracted_count": self.extracted_count,
            "anomalies_detected": 0,  # 永远是0
            "circuit_breakers_triggered": 0,
            "audit_chain_length": 0,  # 没有审计链
            "tamper_evident": False,  # 日志可篡改
        }
