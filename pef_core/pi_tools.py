#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
π密度工具 — PEF π网格投影与锚点验证
====================================
包含表头行识别、列网格投影、ρ偏离率计算等π密度相关工具。

【声明】本模块的 π锚验证命中统计（register_anchor_verification / _ANCHOR_STATS）
为**内存计数器**，仅供 L4 ρ 偏离率与锚覆盖率计算使用，**非持久化登记簿**，
与 PEF_StateLedger（π锚登记簿）无关；运行时 Πₛ 绑定与持久化一律走
PEF_StateLedger.record()。
"""
import re
from .pefmod import PEFBindingError
from .utils import string_normalize
from .pi_constants import PI_TAIL_LIBRARY

_HEADER_HINT_RE = re.compile(
    r'item|qty|quantity|description|part.?no|serial|section|project|job|'
    r'customer.?order|order.?no|entity|ref|doc|batch|code|label|flag|'
    r'amount|unit|type|category|status|source|target', re.I)


def detect_header_row_by_pi_density(rows) -> 'int | None':
    """π密度表头识别：对前若干行打分，返回表头行索引。"""
    try:
        if not rows:
            return None
        limit = min(len(rows), 25)
        best_idx = None
        best_score = 0.0
        for ri in range(limit):
            row_vals = rows[ri]
            if not row_vals:
                continue
            non_empty = 0
            kw_hits = 0
            short_cnt = 0
            total = len(row_vals)
            for v in row_vals:
                if v is None:
                    continue
                s = string_normalize(v)
                if not s:
                    continue
                non_empty += 1
                if len(s) <= 40:
                    short_cnt += 1
                if _HEADER_HINT_RE.search(s.lower()):
                    kw_hits += 1
            if non_empty == 0:
                continue
            density = non_empty / max(total, 1)
            short_ratio = short_cnt / max(non_empty, 1)
            score = kw_hits * 3.0 + density * 2.0 + short_ratio * 1.0
            if score > best_score:
                best_score = score
                best_idx = ri
        if best_idx is None or best_score < 2.0:
            return None
        return best_idx
    except Exception:
        return None


def project_columns_to_pi_grid(columns) -> dict:
    """将列集合投影到 π 网格（PEF π%3 绑定域 0→P / 1→E / 2→F，使用 PI_TAIL_LIBRARY 运行时查表）。"""
    result = {}
    # 【铁律5 2026-08-16】列数超过 π 尾数库长度 → P0 终止，禁止取模回绕（在 try 外抛出，防止被吞）
    if columns and len(columns) > len(PI_TAIL_LIBRARY):
        raise PEFBindingError(
            f'P0: π网格投影越界：列数{len(columns)} > π尾数库长度{len(PI_TAIL_LIBRARY)}'
            f'（铁律5：禁止回绕/动态生成）')
    try:
        if not columns:
            return result
        for idx, col in enumerate(columns, 1):
            d_i = int(PI_TAIL_LIBRARY[idx - 1])
            result[col] = {
                'i': idx,
                'd_i': d_i,
                'domain': {0: 'P', 1: 'E', 2: 'F'}[d_i % 3],
            }
    except Exception:
        pass
    return result


# π锚验证统计
_ANCHOR_STATS = {'total': 0, 'hit': 0}


def register_anchor_verification(hit: bool) -> None:
    """外部注入一次锚点验证结果。"""
    try:
        _ANCHOR_STATS['total'] += 1
        if hit:
            _ANCHOR_STATS['hit'] += 1
    except Exception:
        pass


def compute_deviation_rate(state_indices=None) -> dict:
    """ρ 偏离率：rho=1.0 表示零偏离；coverage_pct 为锚点覆盖率。"""
    try:
        total = int(_ANCHOR_STATS.get('total', 0))
        hit = int(_ANCHOR_STATS.get('hit', 0))
        if total <= 0:
            return {'rho': 1.0, 'coverage_pct': 0.0, 'hit_count': 0, 'total_count': 0}
        rho = 1.0 - (hit / float(total))
        coverage = 100.0 * (hit / float(total))
        return {
            'rho': round(rho, 6), 'coverage_pct': round(coverage, 2),
            'hit_count': hit, 'total_count': total,
        }
    except Exception:
        return {'rho': 1.0, 'coverage_pct': 0.0, 'hit_count': 0, 'total_count': 0}