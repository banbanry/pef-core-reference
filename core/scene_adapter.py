#!/usr/bin/env python3
"""
CLE V3.8 SceneAdapter — 场景适配器（设计第11章L1133）
Embedded/Web/Generic三场景过滤算子和特征。
"""
from __future__ import annotations
from typing import List, Set, Dict, Any


class SceneAdapter:
    """场景适配器：按场景过滤算子和特征（设计第11章L1133）

    场景定义：
    - embedded: 嵌入式系统（TIME/HW/CONC/MEM/INT/UNIVERSAL）
    - web: Web应用（SEC/RES/WEB/INJECT/UNIVERSAL）
    - generic: 通用（全量）
    """

    SCENE_OPERATORS: Dict[str, Set[str]] = {
        "embedded": {
            "TimeMonotonicity", "ResourceBound", "StateBoundedness",
            "TaintPropagation", "HardwareChecker", "ConcurrencyChecker",
            "MemoryChecker", "InterruptChecker", "UniversalChecker",
        },
        "web": {
            "ResourceBound", "StateBoundedness", "TaintPropagation",
            "SecurityChecker", "WebChecker", "InjectChecker",
            "UniversalChecker",
        },
        "generic": set(),  # 空集=全场景适用
    }

    SCENE_SIGNATURES: Dict[str, Set[str]] = {
        "embedded": {"P-INIT", "P-PARAM", "E-ARITH", "E-RESOURCE", "E-CONCURRENCY", "E-TIMING"},
        "web": {"P-INPUT", "E-RESOURCE", "WEB"},
        "generic": set(),
    }

    @classmethod
    def get_operators_for_scene(cls, scene: str, all_operator_ids: List[str] = None) -> List[str]:
        """返回该场景应激活的算子ID列表"""
        if scene not in cls.SCENE_OPERATORS:
            scene = "generic"
        allowed = cls.SCENE_OPERATORS[scene]
        if not allowed:  # generic=全量
            return all_operator_ids or []
        if all_operator_ids:
            return [op for op in all_operator_ids if op in allowed]
        return list(allowed)

    @classmethod
    def get_signature_prefixes_for_scene(cls, scene: str) -> Set[str]:
        """返回该场景应激活的特征ID前缀"""
        if scene not in cls.SCENE_SIGNATURES:
            scene = "generic"
        return cls.SCENE_SIGNATURES[scene]

    @classmethod
    def filter_signatures(cls, scene: str, signatures: List[Any]) -> List[Any]:
        """按场景过滤特征列表"""
        if scene == "generic":
            return signatures
        prefixes = cls.get_signature_prefixes_for_scene(scene)
        if not prefixes:
            return signatures
        return [s for s in signatures if any(s.fault_id.startswith(p) for p in prefixes)]

    @classmethod
    def is_operator_allowed(cls, scene: str, operator_id: str) -> bool:
        """检查算子是否适用于该场景"""
        if scene == "generic":
            return True
        allowed = cls.SCENE_OPERATORS.get(scene, set())
        if not allowed:
            return True
        return operator_id in allowed

    @classmethod
    def list_scenes(cls) -> List[str]:
        return ["embedded", "web", "generic"]
