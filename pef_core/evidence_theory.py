#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
证据理论融合 — EvidenceTheory
============================
Dempster-Shafer 证据理论融合引擎，用于多源不确定性推理。
"""


class EvidenceTheory:
    """DS证据理论融合（含除零保护）。"""

    def __init__(self):
        self.mass = {}

    def set_mass(self, hypothesis: str, value: float):
        self.mass[hypothesis] = value

    def combine(self, other: 'EvidenceTheory') -> 'EvidenceTheory':
        """Dempster组合规则：融合两组证据。"""
        result = EvidenceTheory()
        total_conflict = 0.0
        for h1, m1 in self.mass.items():
            for h2, m2 in other.mass.items():
                intersection = self._intersect(h1, h2)
                if intersection and intersection != '∅':
                    result.mass[intersection] = (
                        result.mass.get(intersection, 0) + m1 * m2
                    )
                else:
                    total_conflict += m1 * m2
        if total_conflict < 1.0:
            denominator = 1 - total_conflict
            if denominator > 0:
                for h in list(result.mass.keys()):
                    result.mass[h] /= denominator
        return result

    def _intersect(self, h1: str, h2: str) -> str:
        if h1 == h2:
            return h1
        if h1 == 'Ω' or h2 == 'Ω':
            return h1 if h2 == 'Ω' else h2
        if h1 == '∅' or h2 == '∅':
            return '∅'
        return '∅'

    def get_belief(self, hypothesis: str) -> float:
        belief = 0.0
        for h, m in self.mass.items():
            if h == hypothesis:
                belief += m
        return belief

    def get_plausibility(self, hypothesis: str) -> float:
        plausibility = 0.0
        for h, m in self.mass.items():
            if h == hypothesis or h == 'Ω':
                plausibility += m
        return plausibility

    def __repr__(self):
        return f'Evidence({dict(self.mass)})'