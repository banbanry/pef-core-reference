#!/usr/bin/env python3
"""
CLE V3.8 ShardedPiCoordinator — 分片π协调器（设计第24章L2172）
全局π步数统一分配，所有分片共享同一π数字序列。
单分片模式下退化为全局计数器，多分片并行时保证π步数不重复、单调递增。
"""
from __future__ import annotations
from typing import Dict, List, Optional, Set
from secure_pi_provider import SecurePiDigitProvider


class ShardedPiCoordinator:
    """分片π协调器：全局π步数统一分配（设计第24章）

    核心规则：
    - 全局pi_step计数器，所有分片共享
    - allocate_pi_step(shard_id) → 返回唯一递增步数
    - get_current_digit() → 当前全局π数字
    - 分片间π步数不重复、单调递增
    """

    def __init__(self, source_hash: str, cache_size: int = 100, num_shards: int = 1):
        self.source_hash = source_hash
        self.cache_size = cache_size
        self.num_shards = num_shards
        self._global_step = 0
        self._pi_provider = SecurePiDigitProvider(source_hash, cache_size)
        self._shard_steps: Dict[int, List[int]] = {i: [] for i in range(num_shards)}
        self._allocated_steps: Set[int] = set()

    def allocate_pi_step(self, shard_id: int = 0) -> int:
        """分配一个全局π步数，返回step；耗尽返回-1"""
        if self._global_step >= self.cache_size:
            return -1
        step = self._global_step
        self._global_step += 1
        self._allocated_steps.add(step)
        if shard_id in self._shard_steps:
            self._shard_steps[shard_id].append(step)
        else:
            self._shard_steps[shard_id] = [step]
        return step

    def get_current_digit(self) -> int:
        """获取当前全局π数字（最后分配的步数对应的π数字）"""
        if self._global_step == 0:
            return -1
        return self._pi_provider.get_digit(self._global_step - 1)

    def get_digit_at(self, step: int) -> int:
        """获取指定步数的π数字"""
        return self._pi_provider.get_digit(step)

    def get_global_step(self) -> int:
        return self._global_step

    def get_coverage(self) -> float:
        """全局π覆盖率 = global_step / cache_size"""
        if self.cache_size == 0:
            return 1.0
        return min(1.0, self._global_step / self.cache_size)

    def get_shard_steps(self, shard_id: int) -> List[int]:
        """获取指定分片已分配的步数列表"""
        return self._shard_steps.get(shard_id, [])

    def is_exhausted(self) -> bool:
        return self._global_step >= self.cache_size

    def reset(self) -> None:
        """重置（新审计文件时调用）"""
        self._global_step = 0
        self._shard_steps = {i: [] for i in range(self.num_shards)}
        self._allocated_steps.clear()
        self._pi_provider.reset()
