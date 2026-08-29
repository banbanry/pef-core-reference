#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEFmod 原语 + Πₛ π锚轴绑定契约（PEF 架构【第二步】交付物）
================================================================
落地内容：
  1. PEFmod —— 只读状态快照原语（features / domain_tag / state_hash）
  2. PiSDispatcher —— Πₛ 运行时 π 锚实例分配器（一次性、不可重入、域绑定）
  3. Πₛ π锚轴绑定契约 ——
      ① PEFmod ↔ Πₛ 一对一强绑定：不可变更、不可共享；
      ② Π₀ 严格隔离：本模块不引用、不存储、不运算 Π₀ 基准标尺常量；
      ③ 绑定边界：仅 PEFmod 实例与 PEF_StateLedger 条目允许绑定 Πₛ，
         其余组件只可引用 Πₛ 凭证（int 锚号），禁止直接绑定。

对齐公理：
  铁律1（π%3 与 domain_tag 一致）、铁律3（禁止引用未来态）、
  三重一致性（PEFmod.domain_tag == π%3 映射域）。
  Π₀ 隔离：本模块不导入 pi_constants，Π₀ 不参与任何绑定/存储/运行时逻辑。
"""
import copy
import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

# ---- MOD3 域映射（铁律1：π%3 → P/E/F）----
_DOMAIN_BY_R: Dict[int, str] = {0: 'P', 1: 'E', 2: 'F'}
_R_BY_DOMAIN: Dict[str, int] = {'P': 0, 'E': 1, 'F': 2}


def utc_now_iso() -> str:
    """UTC 时间戳（ISO 8601 微秒精度，同格式下字符串比较即时序比较）。"""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


class PEFBindingError(RuntimeError):
    """Πₛ 绑定契约违规（P0 级，终止链路）。"""


def _compute_state_hash(features, domain_tag) -> str:
    """结构哈希：SHA256(features + domain_tag)。确定性，不含时间戳（L2 结构匹配可用）。"""
    canonical = json.dumps(
        {'features': [float(x) for x in features], 'domain_tag': domain_tag},
        sort_keys=True, separators=(',', ':'),
    )
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


class PiSDispatcher:
    """Πₛ 运行时 π 锚实例分配器（一次性分配、不可重入、不可复用故障π）。

    职责（对齐铁律1 / 黑名单4 跳过π模数校验 / 黑名单5 复用故障π）：
      - allocate()：分配唯一 Πₛ，返回 (pi_s, domain)；域由 π%3 确定（0→P/1→E/2→F）。
        域一致性由调用方（绑定层）校验：不一致 → 拒绝绑定；禁止丢弃 π 锚重新分配。
      - 活动/归档分离：归档锚永不复用。
      - 绑定注册表：内部维护 pi_s → pefmod_id（仅 PEFmod.bind 调用），
        强制一对一不可共享。
      - Π₀ 隔离：仅维护运行时锚计数器与集合，不引用 Π₀ 基准标尺常量。
    """

    _lock = threading.Lock()
    _counter = 0
    _active: set = set()
    _archived: set = set()
    _alloc_ts: Dict[int, str] = {}       # pi_s -> 锚生成时刻（时序校验）
    _bound: Dict[int, int] = {}          # pi_s -> id(pefmod)（一对一不可共享）

    # ---------------- Πₛ 分配 ----------------
    @classmethod
    def allocate(cls) -> Tuple[int, str]:
        """生成有效 Πₛ。返回 (pi_s, domain)，域由 π%3 确定（铁律1）。

        时序约束：锚生成时刻 t_anchor 在此记录；调用方必须先完成
        PEFmod 状态更新（created_at ≤ t_anchor），否则登记时判时序倒置。
        域一致性由调用方在绑定层校验（不一致 → 拒绝绑定），
        本分配器禁止丢弃 π 锚重新分配。
        """
        with cls._lock:
            cls._counter += 1
            new_pi = cls._counter
            if new_pi in cls._active or new_pi in cls._archived:
                raise PEFBindingError('P0: Πₛ 冲突，禁止复用故障π')
            cls._active.add(new_pi)
            cls._alloc_ts[new_pi] = utc_now_iso()
            return new_pi, _DOMAIN_BY_R[new_pi % 3]

    @classmethod
    def is_active(cls, pi_s) -> bool:
        return isinstance(pi_s, int) and pi_s in cls._active

    @classmethod
    def is_known(cls, pi_s) -> bool:
        """锚是否曾被分配（活动或已归档）。用于 L1 π 合法性校验。"""
        return isinstance(pi_s, int) and (pi_s in cls._active or pi_s in cls._archived)

    @classmethod
    def get_alloc_time(cls, pi_s) -> Optional[str]:
        return cls._alloc_ts.get(pi_s)

    @classmethod
    def archive(cls, pi_s) -> bool:
        """归档锚：移出活动集、解散绑定，永不复用（铁律7 链路结束销毁上下文）。"""
        with cls._lock:
            if pi_s not in cls._active:
                return False
            cls._active.discard(pi_s)
            cls._archived.add(pi_s)
            cls._bound.pop(pi_s, None)
            return True

    @classmethod
    def active_count(cls) -> int:
        return len(cls._active)

    @classmethod
    def archived_count(cls) -> int:
        return len(cls._archived)

    # ---------------- 内部绑定注册（仅 PEFmod.bind 调用）----------------
    @classmethod
    def _register_binding(cls, pi_s, pefmod_id) -> None:
        """一对一不可共享注册。违反 → P0。"""
        with cls._lock:
            if pi_s not in cls._active:
                raise PEFBindingError('P0: Πₛ 无效或已归档，禁止绑定')
            existing = cls._bound.get(pi_s)
            if existing is not None and existing != pefmod_id:
                raise PEFBindingError('P0: Πₛ 不可共享，已被另一 PEFmod 绑定')
            if existing == pefmod_id:
                raise PEFBindingError('P0: PEFmod 重复绑定同一 Πₛ（不可变更）')
            cls._bound[pi_s] = pefmod_id


class PEFmod:
    """只读状态快照（PEF 原语，对齐公理 PEFmod 定义）。

    生命周期：创建(未绑定) → bind(Πₛ，一次性、不可变更) → 归档/销毁。
      - features   : 不可变元组（float list 主体快照 S_t）
      - domain_tag : 'P' / 'E' / 'F'
      - state_hash : SHA256 结构哈希（确定性，不含时间戳）
      - created_at : 状态更新时刻（UTC ISO 8601，第二步时序校验用）
      - pi_s       : 绑定凭证（None 或唯一 Πₛ）

    原始基准不可写：features 以元组暴露；运算必须使用 snapshot() 深拷贝副本。
    """

    __slots__ = (
        '_features', '_domain_tag', '_state_hash', '_created_at', '_pi_s',
        '__weakref__',
    )

    def __init__(self, features, domain_tag: str):
        try:
            feats = [float(x) for x in features]
        except (TypeError, ValueError):
            raise PEFBindingError('P0: features 必须为数值列表')
        if not feats:
            raise PEFBindingError('P0: features 为空，维度不匹配')
        for x in feats:
            if x != x or x in (float('inf'), float('-inf')):
                raise PEFBindingError('P0: features 含 NaN/Inf（全局兜底，终止链路）')
        dom = str(domain_tag).strip().upper()
        if dom not in _R_BY_DOMAIN:
            raise PEFBindingError(f'P0: 非法 domain_tag={domain_tag}，仅允许 P/E/F')
        self._features = tuple(feats)
        self._domain_tag = dom
        self._state_hash = _compute_state_hash(feats, dom)
        self._created_at = utc_now_iso()
        self._pi_s: Optional[int] = None

    # ---------------- 只读属性 ----------------
    @property
    def features(self) -> Tuple[float, ...]:
        return self._features

    @property
    def domain_tag(self) -> str:
        return self._domain_tag

    @property
    def state_hash(self) -> str:
        return self._state_hash

    @property
    def created_at(self) -> str:
        return self._created_at

    @property
    def pi_s(self) -> Optional[int]:
        return self._pi_s

    @property
    def is_bound(self) -> bool:
        return self._pi_s is not None

    def snapshot(self) -> 'PEFmod':
        """返回深拷贝副本（仅副本参与运算；副本不携带绑定）。"""
        c = copy.deepcopy(self)
        c._pi_s = None
        return c

    # ---------------- Πₛ 绑定契约 ----------------
    def bind(self, pi_s: int) -> int:
        """绑定唯一 Πₛ（一次性，不可变更，不可共享）。

        校验顺序（对齐 L1）：
          ① 本实例未绑定（不可变更）；
          ② Πₛ 凭证类型合法且处于活动集（未归档，不可复用故障π）；
          ③ 三重一致性：self.domain_tag == π%3 映射域（铁律1）；
          ④ 一对一不可共享：PiSDispatcher 绑定注册表校验。
        """
        if self._pi_s is not None:
            raise PEFBindingError('P0: PEFmod 已绑定 Πₛ，不可变更/重复绑定')
        if not isinstance(pi_s, int):
            raise PEFBindingError(f'P0: Πₛ 凭证非法类型 {type(pi_s).__name__}')
        if not PiSDispatcher.is_active(pi_s):
            raise PEFBindingError(f'P0: Πₛ={pi_s} 无效或已归档，禁止绑定')
        if _R_BY_DOMAIN[self._domain_tag] != pi_s % 3:
            raise PEFBindingError(
                f'P0: 三重一致性失败 domain_tag={self._domain_tag}, π%3={pi_s % 3}')
        PiSDispatcher._register_binding(pi_s, id(self))
        self._pi_s = pi_s
        return pi_s

    # ---------------- 自检辅助 ----------------
    def check_binding(self) -> Dict[str, Any]:
        """自检：本实例绑定状态核验（供登记簿自检复用）。"""
        if self._pi_s is None:
            return {'ok': False, 'reason': 'PEFmod 未绑定 Πₛ'}
        if not PiSDispatcher.is_known(self._pi_s):
            return {'ok': False, 'reason': f'Πₛ={self._pi_s} 未分配（引用未来态）'}
        if _R_BY_DOMAIN[self._domain_tag] != self._pi_s % 3:
            return {'ok': False, 'reason': '三重一致性失败'}
        return {'ok': True, 'reason': 'ok'}
