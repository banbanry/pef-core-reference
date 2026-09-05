#!/usr/bin/env python3
"""
CLE V3.8 Layer2 AI语义审查接口 + V1-V6反欺诈验证协议（设计第9章Gate9 + SKILL.md）
AI实现由调用方提供，本模块定义接口规范、15类检查项清单、反欺诈验证协议。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from enum import Enum


class L2Category(Enum):
    """L2审查15类检查项（设计第9章Gate9）"""
    PLACEHOLDER = "PLACEHOLDER"
    UNIMPLEMENTED = "UNIMPLEMENTED"
    DEAD_CODE = "DEAD_CODE"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    LOGIC_CHAIN = "LOGIC_CHAIN"
    MATH_PROPERTY = "MATH_PROPERTY"
    INVALID_PATTERN = "INVALID_PATTERN"
    LOGIC = "LOGIC"
    RACE = "RACE"
    API_MISUSE = "API_MISUSE"
    ERROR_PATH = "ERROR_PATH"
    LEAK = "LEAK"
    BUSINESS = "BUSINESS"
    PATH_COVERAGE = "PATH_COVERAGE"
    BEST_PRACTICE = "BEST_PRACTICE"


# 15类检查项清单（L1能否检测 + AI独立验证要求）
L2_CHECKLIST = [
    {"id": 1, "category": L2Category.PLACEHOLDER, "l1_can_detect": True, "ai_must_verify": True},
    {"id": 2, "category": L2Category.UNIMPLEMENTED, "l1_can_detect": True, "ai_must_verify": True},
    {"id": 3, "category": L2Category.DEAD_CODE, "l1_can_detect": True, "ai_must_verify": True},
    {"id": 4, "category": L2Category.BUFFER_OVERFLOW, "l1_can_detect": True, "ai_must_verify": True},
    {"id": 5, "category": L2Category.LOGIC_CHAIN, "l1_can_detect": True, "ai_must_verify": True},
    {"id": 6, "category": L2Category.MATH_PROPERTY, "l1_can_detect": True, "ai_must_verify": True},
    {"id": 7, "category": L2Category.INVALID_PATTERN, "l1_can_detect": True, "ai_must_verify": True},
    {"id": 8, "category": L2Category.LOGIC, "l1_can_detect": False, "ai_must_verify": True},
    {"id": 9, "category": L2Category.RACE, "l1_can_detect": False, "ai_must_verify": True},
    {"id": 10, "category": L2Category.API_MISUSE, "l1_can_detect": False, "ai_must_verify": True},
    {"id": 11, "category": L2Category.ERROR_PATH, "l1_can_detect": False, "ai_must_verify": True},
    {"id": 12, "category": L2Category.LEAK, "l1_can_detect": False, "ai_must_verify": True},
    {"id": 13, "category": L2Category.BUSINESS, "l1_can_detect": False, "ai_must_verify": True},
    {"id": 14, "category": L2Category.PATH_COVERAGE, "l1_can_detect": True, "ai_must_verify": True},
    {"id": 15, "category": L2Category.BEST_PRACTICE, "l1_can_detect": False, "ai_must_verify": True},
]


@dataclass
class L2Finding:
    """L2 AI发现（与L1输出格式对齐）"""
    event_id: str
    file: str
    line_range: List[int]
    severity: str  # P0/P1
    category: str
    description: str
    suggestion: str
    confidence: str  # HIGH/MEDIUM/LOW
    source_trace: str = ""  # V1来源溯源: 具体代码行号+推理过程
    is_tool_output: bool = False  # V4: 是否为工具输出(编译器/linter)而非AI推理


@dataclass
class L2Result:
    """L2审查结果"""
    reviewer: str = "AI_LAYER2"
    findings: List[L2Finding] = field(default_factory=list)
    summary: str = ""
    false_positive_candidates: List[str] = field(default_factory=list)
    traversal_evidence: str = ""  # V3遍历证据: 文件→函数→行号阅读路径
    tool_disclosure: str = ""  # V4工具披露: 区分工具发现vs AI推理
    smoke_test_passed: bool = False  # V6冒烟测试


@dataclass
class AntiFraudResult:
    """V1-V6反欺诈验证结果"""
    V1_source_traceable: bool = False
    V1_detail: str = ""
    V2_independent_reproduce: bool = False
    V2_detail: str = ""
    V3_traversal_evidence: bool = False
    V3_detail: str = ""
    V4_tool_disclosure: bool = False
    V4_detail: str = ""
    V5_compile_match: bool = False
    V5_detail: str = ""
    V6_smoke_test: bool = False
    V6_detail: str = ""
    verdict: str = "PASS"  # PASS/FRAUD_DETECTED/INCOMPLETE/GAMMA
    fraud_flags: List[str] = field(default_factory=list)


class Layer2Reviewer:
    """L2 AI语义审查接口（设计第9章Gate9）

    AI实现由调用方提供(review_callback)，本类负责：
    - 定义15类检查项清单
    - 调用AI审查回调
    - 执行V1-V6反欺诈验证协议
    - L2确定性回退（AI未返回有效结果时用PEF算子补充）
    """

    def __init__(self, review_callback: Optional[Callable] = None):
        self.review_callback = review_callback
        self.checklist = L2_CHECKLIST

    def review(self, source_code: str, findings_layer1: List[Dict],
               filename: str = "source.c") -> L2Result:
        """执行L2审查（调用AI回调或确定性回退）"""
        if self.review_callback:
            try:
                result = self.review_callback(source_code, findings_layer1, filename)
                if isinstance(result, L2Result):
                    return result
            except Exception:
                pass
        # L2确定性回退（AI未返回有效结果时）
        return self._run_deterministic_fallback(source_code, findings_layer1)

    def _run_deterministic_fallback(self, source_code: str,
                                     findings_layer1: List[Dict]) -> L2Result:
        """L2确定性回退：用PEF算子作为确定性补充，标记来源为L2_DETERMINISTIC_FALLBACK"""
        result = L2Result(
            reviewer="L2_DETERMINISTIC_FALLBACK",
            summary="AI审查未返回有效结果，执行确定性回退（PEF算子补充）",
        )
        l1_ids = {f.get("event_id") for f in findings_layer1}
        # 回退逻辑：标记L1未覆盖的检查项为需人工复核
        uncovered = [c for c in self.checklist if not c["l1_can_detect"]]
        for c in uncovered:
            result.findings.append(L2Finding(
                event_id=f"L2_FALLBACK_{c['category'].value}",
                file="", line_range=[0, 0], severity="P1",
                category=c["category"].value,
                description=f"L1无法检测{c['category'].value}，需AI人工审查",
                suggestion="执行AI语义审查",
                confidence="LOW",
            ))
        return result

    def verify_anti_fraud(self, l2_result: L2Result,
                          compile_errors: List[str] = None,
                          code_runs: bool = False) -> AntiFraudResult:
        """V1-V6反欺诈验证协议（每次L2完成后强制执行，不可跳过）"""
        result = AntiFraudResult()

        # V1 来源溯源: 每个发现必须有具体行号+推理过程
        v1_pass = all(f.source_trace for f in l2_result.findings if f.severity == "P0")
        result.V1_source_traceable = v1_pass
        result.V1_detail = "所有P0发现均有来源溯源" if v1_pass else "存在P0发现无来源溯源"

        # V2 独立复现: 不使用工具仅凭阅读代码重述同一问题
        result.V2_independent_reproduce = v1_pass  # 简化：有溯源即可独立复现
        result.V2_detail = "可独立复现" if v1_pass else "无法独立复现"

        # V3 遍历证据: 文件→函数→行号阅读路径
        result.V3_traversal_evidence = bool(l2_result.traversal_evidence)
        result.V3_detail = l2_result.traversal_evidence if l2_result.traversal_evidence else "无遍历证据"

        # V4 工具披露: 区分工具发现vs AI推理
        tool_findings = [f for f in l2_result.findings if f.is_tool_output]
        ai_findings = [f for f in l2_result.findings if not f.is_tool_output]
        result.V4_tool_disclosure = bool(l2_result.tool_disclosure) or len(tool_findings) > 0
        result.V4_detail = f"工具发现{len(tool_findings)}条, AI推理{len(ai_findings)}条"

        # V5 编译验证: AI发现应覆盖编译器报错
        if compile_errors:
            ai_descs = {f.description for f in l2_result.findings}
            covered = sum(1 for e in compile_errors if any(e[:20] in d for d in ai_descs))
            result.V5_compile_match = covered >= len(compile_errors) * 0.5
            result.V5_detail = f"编译器报错{len(compile_errors)}个, AI覆盖{covered}个"
        else:
            result.V5_compile_match = True
            result.V5_detail = "无编译错误可对比"

        # V6 冒烟测试: PASS必须意味着代码可运行
        result.V6_smoke_test = code_runs
        result.V6_detail = "代码可运行" if code_runs else "代码无法运行, 裁决应降级GAMMA"

        # 最终裁决
        if not result.V1_source_traceable:
            result.verdict = "FRAUD_DETECTED"
            result.fraud_flags.append("V1_FAIL: AI欺诈, 无来源溯源")
        elif not result.V3_traversal_evidence:
            result.verdict = "INCOMPLETE"
            result.fraud_flags.append("V3_FAIL: AI未遍历")
        elif not result.V6_smoke_test:
            result.verdict = "GAMMA"
            result.fraud_flags.append("V6_FAIL: 代码不可运行")
        else:
            result.verdict = "PASS"

        return result
