#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
信息熵铁律 — InformationEntropy
==============================
数据污染风险检测与Shannon熵计算。
"""
import math
from typing import Dict, Any, List, Optional
import pandas as pd

# 【OBS-012 修复】单值列（唯一值=1）为批级常量（如单据级键：
# 同一批次所有行 entity_id 相同）——全同值是正常结构而非数据污染。真污染来自多值列的低熵聚集。
# 参数经 framework_config（pef.entropy.skip_single_value_columns）可关断，属审计阈值类内核参数。
try:
    from .config_loader import load_framework_config
    _ent_cfg = load_framework_config().get('pef', {}).get('entropy', {})
    SKIP_SINGLE_VALUE_COLUMNS = bool(_ent_cfg.get('skip_single_value_columns', True))
except Exception:
    SKIP_SINGLE_VALUE_COLUMNS = True


class InformationEntropy:
    """信息熵铁律：数据污染风险检测。"""

    @staticmethod
    def calculate_entropy(values: list) -> float:
        """计算Shannon熵（H = -Σ p(x) * log2(p(x))）。"""
        if not values:
            return 0.0
        total = len(values)
        freq = {}
        for v in values:
            sv = str(v)
            freq[sv] = freq.get(sv, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def detect_pollution_risk(
        df: pd.DataFrame,
        text_columns: List[str],
        high_risk_threshold: float = 0.9,
        medium_risk_threshold: float = 0.3,
    ) -> Dict[str, Any]:
        """检测数据污染风险：基于信息熵分析。"""
        result = {
            'risk': 'LOW',
            'risk_score': 0.0,
            'column_entropies': {},
            'details': [],
        }
        if df.empty:
            return result
        total_entropy = 0.0
        analyzed_cols = 0
        for col in text_columns:
            if col not in df.columns:
                continue
            non_null = df[col].dropna().astype(str).tolist()
            if not non_null:
                continue
            # 【OBS-012】单值列（唯一值=1）为批级常量（如单据级键
            # entity_id：同一批次所有行相同），全同值是正常结构——既不污染 details 也不污染 risk_score
            # （否则熵=0 拉低均值→risk_score 飙高→误报 HIGH）。
            if SKIP_SINGLE_VALUE_COLUMNS and len(set(non_null)) == 1:
                result['column_entropies'][col] = 0.0
                continue
            entropy = InformationEntropy.calculate_entropy(non_null)
            result['column_entropies'][col] = round(entropy, 4)
            total_entropy += entropy
            analyzed_cols += 1
            # 低熵 → 高污染风险（多值列的聚集才是真污染）
            col_ratio = len(non_null) / max(len(df), 1)
            if entropy < medium_risk_threshold and col_ratio > high_risk_threshold:
                result['details'].append(
                    f'列"{col}"熵={entropy:.3f}，存在重复数据污染风险'
                )
        if analyzed_cols > 0:
            avg_entropy = total_entropy / analyzed_cols
            result['risk_score'] = round(1.0 - avg_entropy / max(avg_entropy, 1), 4)
            if result['risk_score'] > high_risk_threshold:
                result['risk'] = 'HIGH'
            elif result['risk_score'] > medium_risk_threshold:
                result['risk'] = 'MEDIUM'
            else:
                result['risk'] = 'LOW'
        return result

    @staticmethod
    def update_entropy(
        previous_entropy: float, new_values: list,
    ) -> float:
        """增量更新熵值。"""
        combined = []
        if previous_entropy > 0:
            pass
        combined.extend(new_values)
        return InformationEntropy.calculate_entropy(combined)