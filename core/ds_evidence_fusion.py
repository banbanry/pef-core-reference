#!/usr/bin/env python3
"""
CLE V3.8 D-S证据融合（设计第27章）
识别框架Θ={FAIL,PASS,UNCERTAIN}，Dempster/Yager冲突解决，四大证据源Mass函数。
"""
from __future__ import annotations
from typing import Dict, List, Tuple, Set, Any
from itertools import combinations


# 识别框架
THETA = {"FAIL", "PASS", "UNCERTAIN"}

# 幂集 2^Θ（8个子集）
POWER_SET = [
    set(), {"FAIL"}, {"PASS"}, {"UNCERTAIN"},
    {"FAIL", "PASS"}, {"FAIL", "UNCERTAIN"}, {"PASS", "UNCERTAIN"},
    {"FAIL", "PASS", "UNCERTAIN"},
]


def _power_set_key(s: Set[str]) -> str:
    return "|".join(sorted(s)) if s else "EMPTY"


def normalize_mass(m: Dict[str, float]) -> Dict[str, float]:
    """归一化Mass函数，使Σm(A)=1"""
    total = sum(m.values())
    if total == 0:
        return {_power_set_key(THETA): 1.0}
    return {k: v / total for k, v in m.items()}


def dempster_combine(m1: Dict[str, float], m2: Dict[str, float]) -> Tuple[Dict[str, float], float]:
    """Dempster组合规则（K<0.5时使用）
    返回: (组合后的mass, 冲突系数K)
    """
    combined: Dict[str, float] = {}
    conflict = 0.0

    for a_key, a_val in m1.items():
        a_set = set(a_key.split("|")) if a_key != "EMPTY" else set()
        for b_key, b_val in m2.items():
            b_set = set(b_key.split("|")) if b_key != "EMPTY" else set()
            intersection = a_set & b_set
            product = a_val * b_val
            if not intersection:
                conflict += product
            else:
                ik = _power_set_key(intersection)
                combined[ik] = combined.get(ik, 0.0) + product

    # 归一化（排除空集）
    if conflict < 1.0:
        combined = {k: v / (1 - conflict) for k, v in combined.items()}
    else:
        combined = {_power_set_key(THETA): 1.0}

    return combined, conflict


def yager_combine(m1: Dict[str, float], m2: Dict[str, float]) -> Tuple[Dict[str, float], float]:
    """Yager规则（K≥0.5时使用，冲突质量保留到全集Θ）"""
    combined: Dict[str, float] = {}
    conflict = 0.0

    for a_key, a_val in m1.items():
        a_set = set(a_key.split("|")) if a_key != "EMPTY" else set()
        for b_key, b_val in m2.items():
            b_set = set(b_key.split("|")) if b_key != "EMPTY" else set()
            intersection = a_set & b_set
            product = a_val * b_val
            if not intersection:
                conflict += product
            else:
                ik = _power_set_key(intersection)
                combined[ik] = combined.get(ik, 0.0) + product

    # Yager: 冲突质量分配给全集Θ（不归一化冲突）
    theta_key = _power_set_key(THETA)
    combined[theta_key] = combined.get(theta_key, 0.0) + conflict

    return combined, conflict


def bel(m: Dict[str, float], subset: Set[str]) -> float:
    """信任函数 Bel(A) = Σ m(B), ∀B ⊆ A"""
    result = 0.0
    for key, val in m.items():
        b_set = set(key.split("|")) if key != "EMPTY" else set()
        if b_set and b_set.issubset(subset):
            result += val
    return result


def pl(m: Dict[str, float], subset: Set[str]) -> float:
    """似然函数 Pl(A) = Σ m(B), ∀B ∩ A ≠ ∅"""
    result = 0.0
    for key, val in m.items():
        b_set = set(key.split("|")) if key != "EMPTY" else set()
        if b_set and b_set & subset:
            result += val
    return result


def mass_layer1_cle(p0_count: int, p1_count: int, invalid_ratio: float = 0.0) -> Dict[str, float]:
    """证据源1: Layer1 CLE确定性探针
    P0每条+0.25(上限0.85)，P1每条+0.05，无效节点→UNCERTAIN
    """
    m = {"FAIL": 0.0, "PASS": 0.0, "UNCERTAIN": 0.0, _power_set_key(THETA): 0.0}
    m["FAIL"] = min(0.85, p0_count * 0.25 + p1_count * 0.05)
    m["UNCERTAIN"] = min(0.5, invalid_ratio)
    remaining = 1.0 - m["FAIL"] - m["UNCERTAIN"]
    m["PASS"] = max(0.0, remaining * 0.7)
    m[_power_set_key(THETA)] = max(0.0, remaining * 0.3)
    return normalize_mass(m)


def mass_layer2_ai(ai_p0: int, ai_p1: int, anti_fraud_passed: bool = True) -> Dict[str, float]:
    """证据源2: Layer2 AI语义审查
    AI P0每条+0.10(上限0.6，低于L1因有幻觉风险)，反欺诈未通过→UNCERTAIN=1.0
    """
    m = {"FAIL": 0.0, "PASS": 0.0, "UNCERTAIN": 0.0, _power_set_key(THETA): 0.0}
    if not anti_fraud_passed:
        m["UNCERTAIN"] = 1.0
        return normalize_mass(m)
    m["FAIL"] = min(0.6, ai_p0 * 0.10 + ai_p1 * 0.02)
    remaining = 1.0 - m["FAIL"]
    m["PASS"] = max(0.0, remaining * 0.6)
    m[_power_set_key(THETA)] = max(0.0, remaining * 0.4)
    return normalize_mass(m)


def mass_signature_match(match_ratio: float, has_library: bool = True) -> Dict[str, float]:
    """证据源3: 特征签名匹配
    匹配比例→FAIL(上限0.5)，无特征库→UNCERTAIN=1.0
    """
    m = {"FAIL": 0.0, "PASS": 0.0, "UNCERTAIN": 0.0, _power_set_key(THETA): 0.0}
    if not has_library:
        m["UNCERTAIN"] = 1.0
        return normalize_mass(m)
    m["FAIL"] = min(0.5, match_ratio)
    remaining = 1.0 - m["FAIL"]
    m["PASS"] = max(0.0, remaining * 0.5)
    m[_power_set_key(THETA)] = max(0.0, remaining * 0.5)
    return normalize_mass(m)


def mass_ast_subgraph(ast_coverage: float, ast_findings: int = 0) -> Dict[str, float]:
    """证据源4: AST子图分析
    AST覆盖率<0.5→UNCERTAIN=0.6，发现每条+0.08(上限0.4)
    """
    m = {"FAIL": 0.0, "PASS": 0.0, "UNCERTAIN": 0.0, _power_set_key(THETA): 0.0}
    if ast_coverage < 0.5:
        m["UNCERTAIN"] = 0.6
    m["FAIL"] = min(0.4, ast_findings * 0.08)
    remaining = 1.0 - m["FAIL"] - m["UNCERTAIN"]
    m["PASS"] = max(0.0, remaining * 0.5)
    m[_power_set_key(THETA)] = max(0.0, remaining * 0.5)
    return normalize_mass(m)


def fuse_all(masses: List[Dict[str, float]]) -> Tuple[Dict[str, float], float, str]:
    """融合所有证据源，自动选择Dempster/Yager
    返回: (最终mass, 最终冲突系数K, 使用的规则)
    """
    if not masses:
        return {_power_set_key(THETA): 1.0}, 0.0, "none"

    combined = masses[0]
    total_conflict = 0.0
    rule_used = "dempster"

    for i in range(1, len(masses)):
        # 先试Dempster计算冲突
        _, k = dempster_combine(combined, masses[i])
        if k < 0.5:
            combined, k = dempster_combine(combined, masses[i])
            rule_used = "dempster"
        elif k < 0.75:
            combined, k = yager_combine(combined, masses[i])
            rule_used = "yager_warning"
        else:
            combined, k = yager_combine(combined, masses[i])
            rule_used = "yager_high_conflict"
        total_conflict = max(total_conflict, k)

    return combined, total_conflict, rule_used


def compute_s3(masses: List[Dict[str, float]], avg_reliability: float = 0.8) -> float:
    """S3置信度 = max(Bel(FAIL),Bel(PASS)) - Pl(UNCERTAIN)*0.5 - (1-avg_reliability)*0.3
    健康阈值: S3 >= 0.8
    """
    combined, _, _ = fuse_all(masses)
    bel_fail = bel(combined, {"FAIL"})
    bel_pass = bel(combined, {"PASS"})
    pl_uncertain = pl(combined, {"UNCERTAIN"})
    s3 = max(bel_fail, bel_pass) - pl_uncertain * 0.5 - (1 - avg_reliability) * 0.3
    return max(0.0, min(1.0, s3))


def final_verdict(masses: List[Dict[str, float]], p0_count: int, ai_p0_count: int,
                  s3: float) -> str:
    """最终裁决逻辑（设计第27章裁决逻辑）
    P0硬阻断→FAIL; AI_ONLY→REVIEW; Bel(FAIL)>0.5→FAIL;
    Bel(PASS)>0.5且S3>=0.8→PASS; S3<0.8→GAMMA; 否则REVIEW
    """
    if p0_count > 0:
        return "FAIL"  # P0硬阻断，DS不覆盖
    if ai_p0_count > 0 and p0_count == 0:
        return "REVIEW"  # AI_ONLY，需人工复核

    combined, _, _ = fuse_all(masses)
    bel_fail = bel(combined, {"FAIL"})
    bel_pass = bel(combined, {"PASS"})

    if bel_fail > 0.5:
        return "FAIL"
    if bel_pass > 0.5 and s3 >= 0.8:
        return "PASS"
    if s3 < 0.8:
        return "GAMMA"
    return "REVIEW"
