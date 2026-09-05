#!/usr/bin/env python3
"""
CLE V3.8 AuditLogChain — 审计日志链（设计第9章L1082 + PIMEM V2.5公式10.1）
H_n = SHA-256(H_{n-1} ‖ n ‖ D_n ‖ content)，篡改检测。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from hashlib import sha256
import json


@dataclass
class AuditRecord:
    n: int  # 判定轴事件序号（单调递增）
    D_n: int  # 调度轴π尾数盐值
    content: Dict[str, Any]  # (S_t, ΔV_t, J_t) 或扩展事件
    H_n: str = ""  # 本记录哈希

    def compute_hash(self, prev_H: str) -> str:
        """H_n = SHA-256(H_{n-1} ‖ n ‖ D_n ‖ content)"""
        content_str = json.dumps(self.content, sort_keys=True, ensure_ascii=False)
        combined = f"{prev_H}|{self.n}|{self.D_n}|{content_str}"
        return sha256(combined.encode('utf-8')).hexdigest()


class AuditLogChain:
    """审计日志链：哈希链篡改溯源（设计第9章L1082）

    严格对齐V2.5公式10.1: H_n = SHA-256(H_{n-1} ‖ n ‖ D_n ‖ S_t ‖ ΔV_t ‖ J_t)
    """

    def __init__(self, pi_digit_provider=None):
        self.records: List[AuditRecord] = []
        self.H_genesis = sha256("genesis".encode('utf-8')).hexdigest()
        self._pi_provider = pi_digit_provider
        self._pi_step = 100  # 演示取π[100]号段（与PIMEM demo一致）

    def _get_d_n(self) -> int:
        """获取调度轴π尾数盐值"""
        if self._pi_provider:
            d = self._pi_provider.get_digit(self._pi_step + len(self.records))
            return d if d != -1 else 0
        return (self._pi_step + len(self.records)) % 10

    def append(self, content: Dict[str, Any], event_type: str = "fact") -> AuditRecord:
        """追加记录，n由判定轴事件驱动单调递增"""
        n = len(self.records) + 1
        D_n = self._get_d_n()
        record = AuditRecord(n=n, D_n=D_n, content=content)
        prev_H = self.records[-1].H_n if self.records else self.H_genesis
        record.H_n = record.compute_hash(prev_H)
        self.records.append(record)
        return record

    def append_genesis(self, anchor: str, base_digest: str) -> AuditRecord:
        """创世上链（PIMEM GENESIS事件，设计第4章4.5）"""
        content = {
            "event": "GENESIS",
            "anchor": anchor,
            "P_base_digest": base_digest,
        }
        return self.append(content, event_type="GENESIS")

    def verify_chain(self) -> Dict[str, Any]:
        """全链重算验证（设计第9章）"""
        if not self.records:
            return {"valid": True, "total": 0, "tampered": []}

        tampered = []
        prev_H = self.H_genesis
        for rec in self.records:
            expected = rec.compute_hash(prev_H)
            if rec.H_n != expected:
                tampered.append(rec.n)
            prev_H = rec.H_n if rec.H_n == expected else expected

        return {
            "valid": len(tampered) == 0,
            "total": len(self.records),
            "tampered_count": len(tampered),
            "tampered_indices": tampered,
        }

    def tamper_detection(self) -> List[int]:
        """返回被篡改的记录序号列表"""
        return self.verify_chain().get("tampered_indices", [])

    def get_record(self, n: int) -> Optional[AuditRecord]:
        for r in self.records:
            if r.n == n:
                return r
        return None

    def get_latest_hash(self) -> str:
        return self.records[-1].H_n if self.records else self.H_genesis

    def to_dict(self) -> Dict[str, Any]:
        return {
            "H_genesis": self.H_genesis[:16],
            "length": len(self.records),
            "latest_H": self.get_latest_hash()[:16],
            "records": [{"n": r.n, "D_n": r.D_n, "H_n": r.H_n[:16],
                         "content": r.content} for r in self.records],
        }
