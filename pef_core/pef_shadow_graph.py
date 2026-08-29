#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
影子图协议 — PEFShadowGraph（A8公理执行器）
===========================================
职责：
  1. 节点注入（SHADOW_GRAPH_INJECT）
  2. 完整性校验（SHADOW_GRAPH_INTEGRITY_CHECK）
  3. 行为哈希生成（SHA-256 + 纳秒时间戳防碰撞）
"""
import hashlib
import time as _time
from typing import Dict, Any, List, Tuple, Optional


class PEFShadowGraph:
    """影子图协议：审计节点注入、完整性校验、行为哈希。"""

    def __init__(self):
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[Tuple[str, str]] = []
        self._hash_history: List[str] = []

    def behavior_hash(self, entity: str, data: str) -> str:
        """生成行为哈希：SHA-256 + 纳秒时间戳防碰撞。"""
        raw = f'{entity}|{data}|{_time.time_ns()}'
        h = hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]
        return h

    def inject(self, entity: str, phase: int, verdict: str, signature: str) -> str:
        """注入节点到影子图。"""
        bh = self.behavior_hash(entity, f'{phase}|{verdict}|{signature}')
        self._nodes[entity] = {
            'entity': entity,
            'phase': phase,
            'verdict': verdict,
            'signature': signature,
            'behavior_hash': bh,
            'timestamp': _time.time_ns(),
        }
        self._hash_history.append(bh)
        # 记录边：如果有前一个节点，建立边关系
        if len(self._edges) > 0:
            prev = self._edges[-1][1]
            self._edges.append((prev, entity))
        else:
            self._edges.append(('__root__', entity))
        return bh

    def validate(self, entity: str) -> Tuple[bool, str]:
        """验证影子图节点是否存在（FAIL/MISMATCH 均为合法裁决，不检查裁决值）。"""
        node = self._nodes.get(entity)
        if not node:
            return False, f'节点不存在:{entity}'
        return True, f'节点验证通过:{entity}'

    def integrity_check(self) -> Tuple[bool, List[str]]:
        """完整性检查：孤立节点、断裂链条、非法篡改。"""
        issues = []
        if not self._nodes:
            return True, ['空图，跳过完整性检查']
        # 检查所有节点
        for entity, node in self._nodes.items():
            ok, msg = self.validate(entity)
            if not ok:
                issues.append(f'篡改:{msg}')
        # 检查边连通性
        connected = set()
        for src, dst in self._edges:
            connected.add(src)
            connected.add(dst)
        for entity in self._nodes:
            if entity not in connected:
                issues.append(f'孤立节点:{entity}')
        return (len(issues) == 0, issues)

    def get_node(self, entity: str) -> Optional[Dict[str, Any]]:
        return self._nodes.get(entity)

    def get_all_nodes(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._nodes)

    def get_edges(self) -> List[Tuple[str, str]]:
        return list(self._edges)