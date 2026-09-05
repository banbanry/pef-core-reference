#!/usr/bin/env python3
"""
CLE V3.8 SignatureLibraryRegistry — 特征库注册表（设计第11章L1128）
720条特征注册/哈希校验/π绑定。
特征分片：通用250(π0-3) + DOC100(π4) + MOD80(π5) + LLM120(π6) + WEB100(π7) + EVASION70(π8-9)
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from hashlib import sha256


@dataclass
class Signature:
    """特征条目（设计第11章）"""
    fault_id: str
    name: str
    severity: str  # P0/P1/P2
    operator: str  # 对应算子ID
    trigger_pattern: str  # 触发正则或描述
    fix: str  # 修复建议
    pi_binding: int  # π绑定: 0-3通用, 4=DOC, 5=MOD, 6=LLM, 7=WEB, 8-9=EVASION
    category: str = ""  # P/E/F/M域
    verified: bool = False  # 人工有效性验证标记（设计L2611诚实声明）
    hash: str = ""

    def compute_hash(self) -> str:
        content = f"{self.fault_id}|{self.name}|{self.severity}|{self.operator}|{self.trigger_pattern}|{self.pi_binding}"
        return sha256(content.encode('utf-8')).hexdigest()[:32]

    def __post_init__(self):
        if not self.hash:
            self.hash = self.compute_hash()


class SignatureLibraryRegistry:
    """特征库注册表：注册/哈希校验/π绑定查询（设计第11章L1128）"""

    def __init__(self):
        self._signatures: Dict[str, Signature] = {}
        self._pi_index: Dict[int, List[str]] = {i: [] for i in range(10)}

    def register(self, sig: Signature) -> None:
        """注册特征，自动计算哈希"""
        if not sig.hash:
            sig.hash = sig.compute_hash()
        self._signatures[sig.fault_id] = sig
        if 0 <= sig.pi_binding <= 9:
            self._pi_index[sig.pi_binding].append(sig.fault_id)

    def get(self, fault_id: str) -> Optional[Signature]:
        return self._signatures.get(fault_id)

    def get_by_pi_digit(self, digit: int) -> List[Signature]:
        """按π数字查询对应分片特征（π调度激活用）"""
        if digit < 0 or digit > 9:
            return []
        if digit <= 3:
            # 通用特征：π=0-3全部返回
            ids = []
            for d in range(4):
                ids.extend(self._pi_index.get(d, []))
            return [self._signatures[i] for i in ids if i in self._signatures]
        return [self._signatures[i] for i in self._pi_index.get(digit, []) if i in self._signatures]

    def get_by_operator(self, operator_id: str) -> List[Signature]:
        return [s for s in self._signatures.values() if s.operator == operator_id]

    def verify_integrity(self) -> Dict[str, any]:
        """全库哈希校验（防篡改，设计第11章）"""
        total = len(self._signatures)
        tampered = []
        for fid, sig in self._signatures.items():
            expected = sig.compute_hash()
            if sig.hash != expected:
                tampered.append(fid)
        return {
            "total": total,
            "tampered_count": len(tampered),
            "tampered_ids": tampered,
            "integrity_ok": len(tampered) == 0,
        }

    def get_stats(self) -> Dict[str, any]:
        """各分片数量统计"""
        stats = {"total": len(self._signatures), "by_pi": {}, "by_severity": {}}
        for d in range(10):
            count = len(self._pi_index.get(d, []))
            if count > 0:
                stats["by_pi"][str(d)] = count
        for sig in self._signatures.values():
            stats["by_severity"][sig.severity] = stats["by_severity"].get(sig.severity, 0) + 1
        return stats

    def count(self) -> int:
        return len(self._signatures)

    def all_signatures(self) -> List[Signature]:
        return list(self._signatures.values())
