#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
算子组合 — OperatorCombination
============================
逻辑算子组合工具：AND/OR/NOT/XOR/IMPLY/NAND/NOR/MAJORITY。
"""


class OperatorCombination:
    """逻辑算子组合，提供8种布尔逻辑运算。"""

    @staticmethod
    def AND(*conditions) -> bool:
        return all(conditions)

    @staticmethod
    def OR(*conditions) -> bool:
        return any(conditions)

    @staticmethod
    def NOT(condition) -> bool:
        return not condition

    @staticmethod
    def XOR(c1, c2) -> bool:
        return c1 != c2

    @staticmethod
    def IMPLY(c1, c2) -> bool:
        return not c1 or c2

    @staticmethod
    def NAND(*conditions) -> bool:
        return not all(conditions)

    @staticmethod
    def NOR(*conditions) -> bool:
        return not any(conditions)

    @staticmethod
    def MAJORITY(*conditions) -> bool:
        true_count = sum((1 for c in conditions if c))
        return true_count > len(conditions) / 2