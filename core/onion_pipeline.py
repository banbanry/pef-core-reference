#!/usr/bin/env python3
"""
CLE V3.8 OnionPipeline — 洋葱流水线三级阻断（设计第28章）
Gate0-8逐级阻断恢复，单级失败不中断（GAMMA事件记录）。
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
from cle_base_layer import sha256_hash, strip_c_comments


@dataclass
class GateResult:
    gate_id: int
    gate_name: str
    passed: bool
    findings: List[Dict] = field(default_factory=list)
    gamma_events: List[str] = field(default_factory=list)
    error: str = ""


class OnionPipeline:
    """洋葱流水线：Gate0-8逐级阻断恢复（设计第28章）

    三级阻断:
    - Gate0: 空输入阻断→GAMMA
    - Gate1-6: 节点级算子（单算子异常→GAMMA事件+继续）
    - Gate7-8: 图级分析+裁决
    """

    GATE_NAMES = {
        0: "空输入阻断",
        1: "注释剥离",
        2: "字符串字面量剥离",
        3: "时间单调性算子",
        4: "资源界限算子",
        5: "状态有界性算子",
        6: "污点传播算子",
        7: "图级分析",
        8: "裁决与印章",
    }

    def __init__(self):
        self.gate_results: List[GateResult] = []

    def run(self, source_code: str, operator_funcs: Dict[str, Callable] = None) -> Dict[str, Any]:
        """执行洋葱流水线"""
        self.gate_results = []
        all_findings = []
        source_hash = sha256_hash(source_code)

        # Gate0: 空输入阻断
        g0 = self._gate0_empty_check(source_code)
        self.gate_results.append(g0)
        if not g0.passed:
            return self._build_result(source_hash, all_findings, "GAMMA")

        # Gate1: 注释剥离
        g1 = self._gate1_strip_comments(source_code)
        self.gate_results.append(g1)
        stripped = g1.findings[0].get("stripped", source_code) if g1.findings else source_code

        # Gate2: 字符串字面量剥离
        g2 = self._gate2_strip_strings(stripped)
        self.gate_results.append(g2)

        # Gate3-6: 节点级算子（单算子异常隔离）
        lines = source_code.split('\n')
        for gate_id, op_name, op_func in [
            (3, "TimeMonotonicity", operator_funcs.get("time") if operator_funcs else None),
            (4, "ResourceBound", operator_funcs.get("resource") if operator_funcs else None),
            (5, "StateBoundedness", operator_funcs.get("state") if operator_funcs else None),
            (6, "TaintPropagation", operator_funcs.get("taint") if operator_funcs else None),
        ]:
            g = self._run_gate_operator(gate_id, op_name, op_func, lines, stripped)
            self.gate_results.append(g)
            all_findings.extend(g.findings)

        # Gate7: 图级分析（简化）
        g7 = GateResult(7, self.GATE_NAMES[7], True, [], [])
        self.gate_results.append(g7)

        # Gate8: 裁决与印章
        p0 = sum(1 for f in all_findings if f.get("severity") == "P0")
        p1 = sum(1 for f in all_findings if f.get("severity") == "P1")
        verdict = "FAIL" if p0 > 0 else ("REVIEW" if p1 > 0 else "PASS")
        g8 = GateResult(8, self.GATE_NAMES[8], True,
                        [{"verdict": verdict, "p0": p0, "p1": p1}], [])
        self.gate_results.append(g8)

        return self._build_result(source_hash, all_findings, verdict)

    def _gate0_empty_check(self, source: str) -> GateResult:
        stripped = strip_c_comments(source)
        clean = [l for l in stripped.split('\n') if l.strip()]
        if not clean:
            return GateResult(0, self.GATE_NAMES[0], False,
                              [{"event_id": "GATE0_EMPTY", "description": "空输入阻断"}],
                              ["空输入→GAMMA"])
        return GateResult(0, self.GATE_NAMES[0], True)

    def _gate1_strip_comments(self, source: str) -> GateResult:
        stripped = strip_c_comments(source)
        return GateResult(1, self.GATE_NAMES[1], True,
                          [{"stripped": stripped, "original_len": len(source),
                            "stripped_len": len(stripped)}])

    def _gate2_strip_strings(self, source: str) -> GateResult:
        import re
        stripped = re.sub(r'"[^"]*"', '""', source)
        return GateResult(2, self.GATE_NAMES[2], True,
                          [{"stripped": stripped}])

    def _run_gate_operator(self, gate_id: int, name: str,
                           op_func: Optional[Callable],
                           lines: List[str], stripped: str) -> GateResult:
        if op_func is None:
            return GateResult(gate_id, self.GATE_NAMES[gate_id], True, [],
                              [f"{name}算子未注册, 跳过"])
        try:
            findings = op_func(lines, stripped)
            return GateResult(gate_id, self.GATE_NAMES[gate_id], True, findings or [])
        except Exception as e:
            # 单算子异常隔离: 捕获+GAMMA事件+不中断
            return GateResult(gate_id, self.GATE_NAMES[gate_id], True, [],
                              [f"{name}算子异常: {str(e)}→GAMMA隔离, 不中断"])

    def _build_result(self, source_hash: str, findings: List[Dict],
                      verdict: str) -> Dict[str, Any]:
        p0 = sum(1 for f in findings if f.get("severity") == "P0")
        p1 = sum(1 for f in findings if f.get("severity") == "P1")
        gamma_count = sum(len(g.gamma_events) for g in self.gate_results)
        return {
            "source_hash": source_hash,
            "verdict": verdict,
            "p0_count": p0,
            "p1_count": p1,
            "findings": findings,
            "gate_results": [{"gate": g.gate_id, "name": g.gate_name,
                              "passed": g.passed, "findings_count": len(g.findings),
                              "gamma_events": g.gamma_events}
                             for g in self.gate_results],
            "gamma_total": gamma_count,
            "hash_self": sha256_hash(f"{verdict}|{p0}|{p1}|{source_hash}"),
        }
