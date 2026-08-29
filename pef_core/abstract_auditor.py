#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
抽象审计网关 — AbstractAuditor
============================
PEF 审计引擎抽象接口。业务层通过本接口访问 PEF 内核，
实现审计逻辑与业务逻辑的解耦。
"""
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd


class AbstractAuditor(ABC):
    """PEF 审计引擎抽象网关。

    业务层通过本接口访问 PEF 内核，实现审计逻辑与业务逻辑的解耦。
    PEF_Core 仅依赖本抽象类，不依赖具体业务实现。
    """

    @abstractmethod
    def execute(
        self,
        full_df: pd.DataFrame,
        master_df: pd.DataFrame,
        decisions: List[Tuple[str, Dict]],
    ) -> Dict[str, Any]:
        """执行完整审计流水线。

        Args:
            full_df: 全量数据（含历史+新增）
            master_df: 主单数据（用于对照校验）
            decisions: 决策列表 [(action, row_dict), ...]

        Returns:
            {
                'verdict': 'PASS' | 'FAIL' | 'MISMATCH',
                'findings': List[Tuple[str, str, str]],
                'state_vector': Dict[str, Any],
                'summary': str,
                'checklist': str,
            }
        """
        ...

    @abstractmethod
    def map_to_pefmod(self, row: pd.Series) -> Dict[str, str]:
        """将业务行数据映射为 PEFmod 格式。

        Args:
            row: 业务数据行

        Returns:
            PEFmod dictionary (with entity_id, part_code, owner, section and other key fields)

        Raises:
            SemanticError: 无法映射时抛出
        """
        ...

    @abstractmethod
    def judge(self) -> str:
        """基于当前审计发现做出裁决（第一公理几何裁决）。

        Returns:
            'PASS' | 'FAIL' | 'MISMATCH'
        """
        ...

    @abstractmethod
    def get_state_vector(self) -> Dict[str, Any]:
        """获取当前状态向量快照。"""
        ...

    @abstractmethod
    def get_checklist(self) -> str:
        """获取PEF自检清单报告文本。"""
        ...

    @abstractmethod
    def get_findings(self) -> List[Tuple[str, str, str]]:
        """获取所有审计发现。"""
        ...

    # ---- 钩子方法（Hook Methods）：业务层可选择性覆写 ----

    def hook_pre_execute(self, full_df: pd.DataFrame, master_df: pd.DataFrame) -> None:
        """执行前的钩子，业务层可在此注入预处理逻辑。"""
        pass

    def hook_post_execute(self, result: Dict[str, Any]) -> None:
        """执行后的钩子，业务层可在此注入后处理逻辑。"""
        pass

    def hook_custom_check(
        self, pm: Dict[str, str], row: Optional[pd.Series],
    ) -> List[Tuple[str, str, str]]:
        """自定义检查钩子，业务层可在此注入业务专属审计规则。

        Returns:
            额外审计发现列表 [(op, severity, message), ...]
        """
        return []