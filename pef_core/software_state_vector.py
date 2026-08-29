#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
软件状态向量 — SoftwareStateVector（增强版）
===========================================
7维物理不变量状态向量，含MOD3相位调度、熵评分、锚覆盖率。
"""
import math
from typing import Any, Dict, Optional


class SoftwareStateVector:
    """7维软件状态向量（S1-S7）。

    维度：
      S1_Parsability       — 解析度（[0,1]）
      S2_Graph_Integrity   — 图完整性（节点数）
      S2_Cyclomatic_Complexity — 循环复杂度
      S3_Confidence        — 置信度（'HIGH'/'MEDIUM'/'LOW'）
      S4_Deviation_Rate    — 偏离率（[0,1]）
      S4_Verdict           — 裁决状态
      S4_Byzantine_Risk    — 拜占庭风险
      S5_Phase             — MOD3相位（0/1/2）
      S6_Entropy           — 信息熵
      S6_Entropy_Risk      — 熵风险等级
      S7_Anchor_Coverage   — 锚覆盖率（[0,1]）
    """

    def __init__(self):
        self.S1_Parsability = 1.0
        self.S1_Unresolved_Count = 0
        self.S2_Graph_Integrity = 0
        self.S2_Cyclomatic_Complexity = 1
        self.S3_Confidence = 'HIGH'
        self.S4_Deviation_Rate = 0.0
        self.S4_Verdict = 'PASS'
        self.S4_Byzantine_Risk = False
        self.S5_Phase = 0
        self.S6_Entropy = 0.0
        self.S6_Entropy_Risk = 'LOW'
        self.S7_Anchor_Coverage = 1.0
        # 第一公理：R=0(P-Domain)→1.0, R=1(E-Domain)→0.8, R=2(F-Domain)→0.5
        self.lambda_threshold = 1.0

    def update_phase(self, step: int):
        """更新MOD3相位（基于π序列强度）。"""
        R = step % 3
        self.S5_Phase = R
        # 第一公理：R=0→1.0, R=1→0.8, R=2→0.5
        self.lambda_threshold = 1.0 if R == 0 else (0.8 if R == 1 else 0.5)

    def calculate_deviation(self) -> float:
        """计算ρ偏离率：ρ = ||v - RHO_SPEC|| / sqrt(7)。"""
        RHO_SPEC = [1.0] * 7
        v = [
            self.S1_Parsability,
            self.S2_Graph_Integrity / max(self.S2_Cyclomatic_Complexity, 1),
            1.0 if self.S3_Confidence == 'HIGH' else 0.5 if self.S3_Confidence == 'MEDIUM' else 0.0,
            1.0 - self.S4_Deviation_Rate,
            1.0 - (self.S4_Byzantine_Risk * 0.5),
            self.S6_Entropy / max(self.S6_Entropy, 1) if self.S6_Entropy > 0 else 1.0,
            self.S7_Anchor_Coverage,
        ]
        diff_sq = sum((v[i] - RHO_SPEC[i]) ** 2 for i in range(7))
        self.S4_Deviation_Rate = math.sqrt(diff_sq) / math.sqrt(7)
        return self.S4_Deviation_Rate

    def to_dict(self) -> Dict[str, Any]:
        return {
            'S1_Parsability': self.S1_Parsability,
            'S1_Unresolved_Count': self.S1_Unresolved_Count,
            'S2_Graph_Integrity': self.S2_Graph_Integrity,
            'S2_Cyclomatic_Complexity': self.S2_Cyclomatic_Complexity,
            'S3_Confidence': self.S3_Confidence,
            'S4_Deviation_Rate': self.S4_Deviation_Rate,
            'S4_Verdict': self.S4_Verdict,
            'S4_Byzantine_Risk': self.S4_Byzantine_Risk,
            'S5_Phase': self.S5_Phase,
            'S6_Entropy': self.S6_Entropy,
            'S6_Entropy_Risk': self.S6_Entropy_Risk,
            'S7_Anchor_Coverage': self.S7_Anchor_Coverage,
            'lambda_threshold': self.lambda_threshold,
        }