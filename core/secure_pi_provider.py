#!/usr/bin/env python3
"""
CLE V3.8 SecurePiDigitProvider — π数字安全提供者（设计第6章L719）
source_hash + step 联合 SHA-256 生成π数字，防止共因穿透碰撞攻击。
不同源码 → 不同哈希 → 不同π序列 → 激活不同特征子集。
"""
from __future__ import annotations
from hashlib import sha256
from typing import List, Optional


class SecurePiDigitProvider:
    """π数字安全提供者：双模合一体制（设计第6章L719）

    模式1（默认）：source_hash + step → SHA-256 → π数字
      - 相同输入 → 相同输出（确定性，可复现）
      - 不同source_hash → 不同π序列（防共因穿透）
    模式2（mpmath实算）：真实π数位（用于基线一致性断言）
    """

    def __init__(self, source_hash: str, cache_size: int = 100):
        self.source_hash = source_hash
        self.cache_size = cache_size
        self._cache: dict = {}
        self._step_counter = 0
        self._real_pi_digits: Optional[str] = None

    def _compute_digit(self, step: int) -> int:
        """核心：source_hash + step 联合 SHA-256 → π数字(0-9)"""
        combined = f"{self.source_hash}|{step}"
        digest = sha256(combined.encode('utf-8')).hexdigest()
        # 取哈希最后一位作为π数字（十六进制0-9直接用，a-f映射到0-5）
        last_char = digest[-1]
        if last_char.isdigit():
            return int(last_char)
        return ord(last_char) - ord('a')  # a→0, b→1, ..., f→5

    def get_digit(self, step: int) -> int:
        """获取指定步的π数字；缓存耗尽返回-1（触发GAMMA降级）"""
        if step >= self.cache_size:
            return -1  # π耗尽 → GAMMA降级（设计第22章场景10）
        if step not in self._cache:
            self._cache[step] = self._compute_digit(step)
        return self._cache[step]

    def get_digits(self, start: int, count: int) -> List[int]:
        """获取连续π数字序列"""
        result = []
        for i in range(start, start + count):
            d = self.get_digit(i)
            if d == -1:
                break
            result.append(d)
        return result

    def next_digit(self) -> int:
        """顺序获取下一个π数字（调度轴用）"""
        d = self.get_digit(self._step_counter)
        self._step_counter += 1
        return d

    def get_current_step(self) -> int:
        return self._step_counter

    def get_coverage(self) -> float:
        """S6 π覆盖率 = pi_step / pi_cache_size（设计第23章L2091）"""
        if self.cache_size == 0:
            return 1.0
        return min(1.0, self._step_counter / self.cache_size)

    def is_exhausted(self) -> bool:
        return self._step_counter >= self.cache_size

    def reset(self) -> None:
        """重置步数（新审计文件时调用）"""
        self._step_counter = 0

    @staticmethod
    def load_real_pi_digits(precision: int = 1200) -> str:
        """模式2：用mpmath实算π数位（用于基线一致性断言）"""
        try:
            import mpmath
            mpmath.mp.dps = precision
            pi_str = str(+mpmath.mp.pi)
            return pi_str.replace('.', '')
        except ImportError:
            return ""

    @classmethod
    def verify_paper_consistency(cls) -> bool:
        """与V2.5论文第十一章记录一致性断言：π[100..105]=[9,8,2,1,4,8]"""
        digits = cls.load_real_pi_digits(1200)
        if not digits:
            return False  # mpmath不可用，跳过断言
        paper_ref = [9, 8, 2, 1, 4, 8]
        actual = [int(digits[i]) for i in range(100, 106)]
        return actual == paper_ref
