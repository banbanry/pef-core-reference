#!/usr/bin/env python3
"""
CLE V3.8 算子基类与工厂（设计第1章L773/L775）
BaseOperator: ABC策略模式接口
OperatorFactory: @register装饰器自动注册，开闭原则
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set
from cle_base_layer import CodeNode, AuditContext, AuditEvent, Severity


class BaseOperator(ABC):
    """算子基类：所有算子必须继承此类，实现evaluate方法"""
    operator_id: str = ""
    name: str = ""
    severity: str = Severity.P1.value
    scene_filter: Set[str] = set()  # 空集=全场景适用
    pi_binding: int = -1  # -1=通用(0-3)，4-9=对应π分片

    def should_run(self, scene: str) -> bool:
        """检查该算子是否适用于当前场景"""
        if not self.scene_filter:
            return True
        return scene in self.scene_filter

    @abstractmethod
    def evaluate(self, node: CodeNode, context: AuditContext) -> List[AuditEvent]:
        """评估单个代码节点，返回发现列表"""
        ...

    def evaluate_source(self, source_lines: List[str], context: AuditContext) -> List[AuditEvent]:
        """批量评估源码行（默认逐行构造CodeNode），子类可覆盖"""
        findings = []
        for i, line in enumerate(source_lines):
            node = CodeNode(
                node_id=i, node_type="line", source_line=line,
                function_name="", line_number=i + 1,
            )
            if self.should_run(context.scene):
                findings.extend(self.evaluate(node, context))
        return findings


class OperatorFactory:
    """算子工厂：@register_operator装饰器自动注册，开闭原则"""
    _registry: Dict[str, BaseOperator] = {}

    @classmethod
    def register(cls, operator_class):
        """类装饰器：注册算子到工厂"""
        instance = operator_class()
        cls._registry[instance.operator_id] = instance
        return operator_class

    @classmethod
    def get_operator(cls, operator_id: str) -> Optional[BaseOperator]:
        return cls._registry.get(operator_id)

    @classmethod
    def get_all_operators(cls, scene: str = None) -> List[BaseOperator]:
        """获取所有算子，可按场景过滤"""
        ops = list(cls._registry.values())
        if scene:
            ops = [op for op in ops if op.should_run(scene)]
        return ops

    @classmethod
    def get_operators_by_pi(cls, pi_digit: int) -> List[BaseOperator]:
        """按π数字获取对应分片的算子（π调度激活）"""
        if pi_digit < 0:
            return []
        if pi_digit <= 3:
            # 通用算子：pi_binding=-1 或 0-3
            return [op for op in cls._registry.values()
                    if op.pi_binding == -1 or op.pi_binding <= 3]
        return [op for op in cls._registry.values() if op.pi_binding == pi_digit]

    @classmethod
    def list_operator_ids(cls) -> List[str]:
        return list(cls._registry.keys())

    @classmethod
    def count(cls) -> int:
        return len(cls._registry)
