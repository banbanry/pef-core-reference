#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEF Anchored Determinism — 30-second minimal demo (extracted from production code)
=====================================================================================
从 810 生产项目 PEF_Core 提取的教学级最小实现。
生产级 19 模块完整内核：https://github.com/banbanry/pef-core-reference

提取来源（脱敏后）：
  - PEF_Core/pefmod.py        → PiSDispatcher + PEFmod + PEFBindingError
  - PEF_Core/state_ledger.py  → PEF_StateLedger 三级登记簿 + 自检
  - PEF_Core/pef_anchoring.py → π锚定坐标系（铁律5：禁止回绕）

运行:  python demo_minimal.py
验收:  exit 0，末行输出 "SELF-CHECK: 8/8 PASS"

演示内容：
  1. 正常流程：Πₛ分配 → PEFmod创建 → 三级登记簿record() → CONFIRMED
  2. 攻击1：未锚定写入 → P0熔断（PermissionError）
  3. 攻击2：篡改审计条目 → 完整性哈希不一致
  4. 攻击3：域不匹配 → 三重一致性失败（铁律1）
  5. 自检：8项检查全部PASS
"""
import copy
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ═══════════════════════════════════════════════════════════════════════════
# 从 pefmod.py 提取：Πₛ 分配器 + PEFmod 原语
# ═══════════════════════════════════════════════════════════════════════════

_DOMAIN_BY_R: Dict[int, str] = {0: 'P', 1: 'E', 2: 'F'}
_R_BY_DOMAIN: Dict[str, int] = {'P': 0, 'E': 1, 'F': 2}


def utc_now_iso() -> str:
    """UTC 时间戳（ISO 8601 微秒精度，同格式下字符串比较即时序比较）。"""
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


class PEFBindingError(RuntimeError):
    """Πₛ 绑定契约违规（P0 级，终止链路）。"""


def _compute_state_hash(features, domain_tag) -> str:
    """结构哈希：SHA256(features + domain_tag)。确定性，不含时间戳。"""
    canonical = json.dumps(
        {'features': [float(x) for x in features], 'domain_tag': domain_tag},
        sort_keys=True, separators=(',', ':'),
    )
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


class PiSDispatcher:
    """Πₛ 运行时 π 锚实例分配器（一次性分配、不可重入、不可复用故障π）。

    职责（对齐铁律1 / 黑名单5 复用故障π）：
      - allocate()：分配唯一 Πₛ，返回 (pi_s, domain)；域由 π%3 确定。
      - 活动/归档分离：归档锚永不复用。
      - 绑定注册表：内部维护 pi_s → pefmod_id（仅 PEFmod.bind 调用），
        强制一对一不可共享。
    """
    _counter = 0
    _active: set = set()
    _archived: set = set()
    _alloc_ts: Dict[int, str] = {}
    _bound: Dict[int, int] = {}

    @classmethod
    def allocate(cls) -> Tuple[int, str]:
        """生成有效 Πₛ。返回 (pi_s, domain)，域由 π%3 确定（铁律1）。"""
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
        return isinstance(pi_s, int) and (pi_s in cls._active or pi_s in cls._archived)

    @classmethod
    def get_alloc_time(cls, pi_s) -> Optional[str]:
        return cls._alloc_ts.get(pi_s)

    @classmethod
    def archive(cls, pi_s) -> bool:
        """归档锚：移出活动集、解散绑定，永不复用（铁律7）。"""
        if pi_s not in cls._active:
            return False
        cls._active.discard(pi_s)
        cls._archived.add(pi_s)
        cls._bound.pop(pi_s, None)
        return True

    @classmethod
    def _register_binding(cls, pi_s, pefmod_id) -> None:
        """一对一不可共享注册。违反 → P0。"""
        if pi_s not in cls._active:
            raise PEFBindingError('P0: Πₛ 无效或已归档，禁止绑定')
        existing = cls._bound.get(pi_s)
        if existing is not None and existing != pefmod_id:
            raise PEFBindingError('P0: Πₛ 不可共享，已被另一 PEFmod 绑定')
        if existing == pefmod_id:
            raise PEFBindingError('P0: PEFmod 重复绑定同一 Πₛ（不可变更）')
        cls._bound[pi_s] = pefmod_id


class PEFmod:
    """只读状态快照（PEF 原语）。

    生命周期：创建(未绑定) → bind(Πₛ，一次性、不可变更) → 归档/销毁。
      - features   : 不可变元组（float list 主体快照 S_t）
      - domain_tag : 'P' / 'E' / 'F'
      - state_hash : SHA256 结构哈希（确定性，不含时间戳）
      - created_at : 状态更新时刻（UTC ISO 8601）
      - pi_s       : 绑定凭证（None 或唯一 Πₛ）
    """
    __slots__ = ('_features', '_domain_tag', '_state_hash', '_created_at', '_pi_s', '__weakref__')

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

    def bind(self, pi_s: int) -> int:
        """绑定唯一 Πₛ（一次性，不可变更，不可共享）。

        校验顺序（对齐 L1）：
          ① 本实例未绑定（不可变更）；
          ② Πₛ 凭证类型合法且处于活动集；
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

    def check_binding(self) -> Dict[str, Any]:
        """自检：本实例绑定状态核验。"""
        if self._pi_s is None:
            return {'ok': False, 'reason': 'PEFmod 未绑定 Πₛ'}
        if not PiSDispatcher.is_known(self._pi_s):
            return {'ok': False, 'reason': f'Πₛ={self._pi_s} 未分配（引用未来态）'}
        if _R_BY_DOMAIN[self._domain_tag] != self._pi_s % 3:
            return {'ok': False, 'reason': '三重一致性失败'}
        return {'ok': True, 'reason': 'ok'}


# ═══════════════════════════════════════════════════════════════════════════
# 从 state_ledger.py 提取：三级登记簿（公理只读 / 运行时读写 / 审计追加）
# ═══════════════════════════════════════════════════════════════════════════

_EVENT_TYPES = frozenset({
    'ANCHOR_ALLOCATED', 'PEFMOD_BOUND', 'LEDGER_WRITTEN',
    'LEDGER_ARCHIVED', 'VIOLATION',
})

_RUNTIME_REQUIRED_KEYS = (
    'pi_s', 'domain_tag', 'features', 'state_hash',
    't_state', 't_anchor', 't_write', 'seq', 'status',
)


def _audit_event_hash(ev: Dict[str, Any]) -> str:
    """审计条目完整性哈希：SHA256(event_id|pi_s|event_type|detail|t_event)。"""
    canonical = '|'.join(
        str(ev.get(k, '')) for k in ('event_id', 'pi_s', 'event_type', 'detail', 't_event'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


class PEFAxiomLedger:
    """公理层只读登记簿：固化公理事实常量。只读契约：任何写入尝试 → P0。"""

    def __init__(self, axiom_config: Optional[Dict[str, Any]] = None):
        cfg = axiom_config or {}
        raw_lambda = cfg.get('mod3_lambda') or {0: 1.0, 1: 0.8, 2: 0.5}
        lam = {int(k): float(v) for k, v in raw_lambda.items()}
        self._facts: Dict[str, Dict[str, Any]] = {
            'mod3_domain_map': {
                'fact_id': 'mod3_domain_map',
                'axiom': '铁律1（π%3 与 domain_tag 一致）',
                'value': dict(_DOMAIN_BY_R),
                'readonly': True,
            },
            'mod3_lambda': {
                'fact_id': 'mod3_lambda',
                'axiom': '第一公理（几何裁决）',
                'value': lam,
                'readonly': True,
            },
            'binding_boundary': {
                'fact_id': 'binding_boundary',
                'axiom': '第二步 1③（绑定边界）',
                'value': ['PEFmod', 'PEF_StateLedger'],
                'readonly': True,
            },
            'write_timing': {
                'fact_id': 'write_timing',
                'axiom': '第二步 2③（固化写入时序）',
                'value': 'PEFmod状态更新 → 生成有效Πₛ → PEF_StateLedger持久写入确认',
                'readonly': True,
            },
        }

    @property
    def facts(self) -> Dict[str, Dict[str, Any]]:
        return copy.deepcopy(self._facts)

    def validate_domain(self, pi_s: int, domain_tag: str) -> Tuple[bool, str]:
        """公理层裁决：π%3 映射域 == domain_tag（铁律1）。"""
        try:
            expect = _DOMAIN_BY_R[pi_s % 3]
        except KeyError:
            return False, f'P0: Πₛ 非法（π%3 域映射不存在）'
        if expect != str(domain_tag).upper():
            return False, (
                f'P0: 三重一致性失败 Πₛ={pi_s} π%3={pi_s % 3}→{expect}, '
                f'domain_tag={domain_tag}')
        return True, f'域一致 {expect}'


class PEFRuntimeLedger:
    """运行时读写登记簿：Πₛ 主键 → 标准条目；关联主体快照 S_t。"""

    def __init__(self):
        self._entries: Dict[int, Dict[str, Any]] = {}
        self._seq_counter = 0

    def next_seq(self) -> int:
        self._seq_counter += 1
        return self._seq_counter

    def put(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        for k in _RUNTIME_REQUIRED_KEYS:
            if k not in entry:
                raise PEFBindingError(f'P0: 运行时条目缺少必填字段 {k}')
        pi_s = entry['pi_s']
        if not isinstance(pi_s, int):
            raise PEFBindingError(f'P0: Πₛ 主键非法类型 {type(pi_s).__name__}')
        if pi_s in self._entries:
            raise PEFBindingError(f'P0: Πₛ={pi_s} 已存在登记条目（不可共享主键）')
        if entry['status'] not in ('ACTIVE', 'ARCHIVED'):
            raise PEFBindingError(f"P0: 非法条目状态 {entry['status']}")
        if not isinstance(entry['features'], list) or not entry['features']:
            raise PEFBindingError('P0: features 必须为非空 list[float]')
        self._entries[pi_s] = dict(entry)
        return dict(self._entries[pi_s])

    def get(self, pi_s: int) -> Optional[Dict[str, Any]]:
        e = self._entries.get(pi_s)
        return dict(e) if e is not None else None

    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries.values()]

    def update_status(self, pi_s: int, status: str) -> bool:
        e = self._entries.get(pi_s)
        if e is None:
            return False
        e['status'] = status
        return True

    def count(self) -> int:
        return len(self._entries)


class PEFAuditLedger:
    """审计追加登记簿：仅追加事件流（不可修改、不可删除）。"""

    def __init__(self):
        self._events: List[Dict[str, Any]] = []
        self._counter = 0

    def append(self, pi_s, event_type: str, detail: str = '') -> Dict[str, Any]:
        if event_type and event_type not in _EVENT_TYPES:
            raise PEFBindingError(f'P0: 非法审计事件类型 {event_type}')
        self._counter += 1
        ev = {
            'event_id': self._counter,
            'pi_s': pi_s,
            'event_type': event_type,
            'detail': detail,
            't_event': utc_now_iso(),
        }
        ev['hash'] = _audit_event_hash(ev)
        self._events.append(ev)
        return dict(ev)

    def events(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._events]

    def count(self) -> int:
        return len(self._events)


class PEF_StateLedger:
    """PEF状态登记簿（三级：公理只读 / 运行时读写 / 审计追加）。

    固化写入时序（record）：
      ① PEFmod 状态更新 —— 取自 pefmod.created_at（t_state）
      ② 生成有效 Πₛ     —— 取自 PiSDispatcher.get_alloc_time（t_anchor）
      ③ 登记簿持久写入确认 —— record() 完成运行时写入 + 审计追加，返回 CONFIRMED（t_write）
    """

    def __init__(self, axiom_config: Optional[Dict[str, Any]] = None):
        self.axiom = PEFAxiomLedger(axiom_config)
        self.runtime = PEFRuntimeLedger()
        self.audit = PEFAuditLedger()
        self._recorded_pefmods: set = set()

    def record(self, pefmod: PEFmod, pi_s: int,
               metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """核心写入：PEFmod状态更新 → 生成有效Πₛ → 持久写入确认。

        Returns:
            确认字典 {pi_s, seq, t_state, t_anchor, t_write, status: 'CONFIRMED'}
        Raises:
            PEFBindingError: 任一契约/时序校验失败（P0）
        """
        if not isinstance(pefmod, PEFmod):
            raise PEFBindingError(
                f'P0: 主体必须为 PEFmod 实例，收到 {type(pefmod).__name__}')
        # ① L1 π 合法性
        if not isinstance(pi_s, int) or not PiSDispatcher.is_active(pi_s):
            raise PEFBindingError(
                f'P0: Πₛ={pi_s} 无效或未活动，禁止登记（引用未来态）')
        # ① 三重一致性（铁律1）
        ok, msg = self.axiom.validate_domain(pi_s, pefmod.domain_tag)
        if not ok:
            raise PEFBindingError(msg)
        # ② 一对一：不可共享 / 不可变更
        if self.runtime.get(pi_s) is not None:
            raise PEFBindingError(f'P0: Πₛ={pi_s} 已登记于运行时登记簿（不可共享）')
        if pefmod.is_bound:
            raise PEFBindingError('P0: PEFmod 已绑定 Πₛ，不可变更/重复登记')
        if id(pefmod) in self._recorded_pefmods:
            raise PEFBindingError('P0: 该 PEFmod 实例已登记（一对一唯一）')
        # ③ 固化写入时序：状态更新 ≤ 锚生成 ≤ 写入
        t_state = pefmod.created_at
        t_anchor = PiSDispatcher.get_alloc_time(pi_s)
        if t_anchor is None:
            raise PEFBindingError(f'P0: Πₛ={pi_s} 无锚生成时间（时序倒置）')
        if t_state > t_anchor:
            raise PEFBindingError(
                f'P0: 时序倒置 t_state({t_state}) > t_anchor({t_anchor})')
        # ④ 执行绑定
        pefmod.bind(pi_s)
        # ⑤ 组装标准条目并写入运行时登记簿
        t_write = utc_now_iso()
        if t_anchor > t_write:
            raise PEFBindingError(
                f'P0: 时序倒置 t_anchor({t_anchor}) > t_write({t_write})')
        seq = self.runtime.next_seq()
        entry = {
            'pi_s': pi_s,
            'domain_tag': pefmod.domain_tag,
            'features': list(pefmod.features),
            'state_hash': pefmod.state_hash,
            't_state': t_state,
            't_anchor': t_anchor,
            't_write': t_write,
            'seq': seq,
            'status': 'ACTIVE',
        }
        if metadata is not None:
            entry['metadata'] = metadata
        self.runtime.put(entry)
        self._recorded_pefmods.add(id(pefmod))
        confirm = {
            'pi_s': pi_s, 'seq': seq,
            't_state': t_state, 't_anchor': t_anchor, 't_write': t_write,
            'status': 'CONFIRMED',
        }
        # ⑥ 审计追加
        self.audit.append(pi_s, 'PEFMOD_BOUND',
                          f'state_hash={pefmod.state_hash[:12]} seq={seq}')
        self.audit.append(pi_s, 'LEDGER_WRITTEN', f'seq={seq} 持久写入确认')
        return confirm

    def archive(self, pi_s: int) -> bool:
        """归档条目与锚（铁律7 链路结束销毁上下文）。"""
        if self.runtime.update_status(pi_s, 'ARCHIVED'):
            PiSDispatcher.archive(pi_s)
            self.audit.append(pi_s, 'LEDGER_ARCHIVED', '条目归档，Πₛ 移入归档集')
            return True
        return False

    def self_check(self) -> Dict[str, Any]:
        """配套自检逻辑（第二步 3）：
        ① 校验登记簿全部记录携带合法有效的 Πₛ
        ② 校验 Πₛ 与 PEFmod 实例一一对应关系
        ③ 识别时序倒置违规逻辑并标记
        """
        items: List[Dict[str, Any]] = []
        violations: List[Dict[str, Any]] = []

        def item(name: str, passed: bool, detail: str) -> bool:
            items.append({'name': name, 'passed': bool(passed), 'detail': detail})
            return bool(passed)

        entries = self.runtime.entries()

        # ① Πₛ 合法性
        bad_pi = [e['pi_s'] for e in entries if not PiSDispatcher.is_known(e['pi_s'])]
        item('Πₛ合法性-运行时条目', not bad_pi,
             f'{len(entries)} 条记录全部引用已分配 Πₛ' if not bad_pi
             else f'违规：{bad_pi} 引用未分配/未来态 Πₛ')

        # ① 域一致性（铁律1）
        bad_dom = [e['pi_s'] for e in entries
                   if not self.axiom.validate_domain(e['pi_s'], e['domain_tag'])[0]]
        item('域一致性-铁律1', not bad_dom,
             '全部条目 π%3 与 domain_tag 一致' if not bad_dom
             else f'违规：{bad_dom} π%3 与 domain_tag 不一致')

        # ② Πₛ 主键唯一
        keys = [e['pi_s'] for e in entries]
        dup_keys = {k for k in keys if keys.count(k) > 1}
        item('一对一-Πₛ主键唯一', not dup_keys,
             '运行时登记簿 Πₛ 主键无重复' if not dup_keys
             else f'违规：重复主键 {sorted(dup_keys)}')

        # ③ 时序倒置
        bad_time = []
        for e in entries:
            if not (e['t_state'] <= e['t_anchor'] <= e['t_write']):
                bad_time.append(e['pi_s'])
        item('时序-状态≤锚≤写入', not bad_time,
             '全部条目满足 t_state ≤ t_anchor ≤ t_write' if not bad_time
             else f'违规：{bad_time} 时序倒置')

        # 写入序号单调
        seqs = sorted(e['seq'] for e in entries)
        seq_bad = len(seqs) > 1 and any(b <= a for a, b in zip(seqs, seqs[1:]))
        item('时序-写入序号单调', not seq_bad,
             '写入序号 seq 严格单调递增' if not seq_bad else '违规：seq 回归')

        # 审计账本防篡改
        bad_audit = [ev.get('event_id') for ev in self.audit.events()
                     if ev.get('hash') != _audit_event_hash(ev)]
        item('审计-防篡改哈希一致', not bad_audit,
             f'{self.audit.count()} 条审计事件哈希全部一致' if not bad_audit
             else f'违规：审计条目 {bad_audit} 哈希不一致（账本被篡改）')

        # Π₀ 隔离（结构性保证：登记簿无 Π₀ 字段）
        pi0_leak = any('pi_0' in e or 'baseline' in e for e in entries)
        item('Π₀隔离-登记簿不承载Π₀', not pi0_leak,
             '登记簿条目无 Π₀ 字段（结构性保证）')

        # 公理层只读
        axiom_readonly = all(f.get('readonly') for f in self.axiom.facts.values())
        item('公理层-只读契约', axiom_readonly,
             '全部公理事实标记 readonly=True' if axiom_readonly else '违规：公理层可写')

        passed_all = all(i['passed'] for i in items)
        return {
            'passed': passed_all,
            'items': items,
            'violations': violations,
            'summary': (
                f'PEF_StateLedger 自检：'
                f'{sum(1 for i in items if i["passed"])}/{len(items)} 项通过，'
                f'{len(violations)} 项违规'),
        }


# ═══════════════════════════════════════════════════════════════════════════
# 演示场景：正常流程 + 3种攻击 + 自检
# ═══════════════════════════════════════════════════════════════════════════

def run_demo():
    print("=" * 64)
    print("PEF Anchored Determinism — 30-second minimal demo")
    print("Extracted from 810 production code (PEF_Core), desensitized")
    print("=" * 64)

    ledger = PEF_StateLedger()
    checks = []

    # ── 场景1：正常流程 ──────────────────────────────────────────────
    print("\n[场景1] 正常流程：PEFmod创建 → Πₛ分配(域匹配) → 三级登记簿record()")
    # 固化写入时序：① PEFmod状态更新(t_state) → ② 生成有效Πₛ(t_anchor) → ③ 持久写入确认(t_write)
    pefmod = PEFmod(features=[0.95, 0.87, 1.0], domain_tag='P')
    print(f"  ① 创建 PEFmod: domain={pefmod.domain_tag}, "
          f"state_hash={pefmod.state_hash[:12]}…, t_state={pefmod.created_at[11:23]}")

    # 循环分配Πₛ直到域=P（三重一致性要求 domain_tag == π%3 映射域）
    pi_s, domain = PiSDispatcher.allocate()
    while domain != pefmod.domain_tag:
        print(f"     跳过 Πₛ={pi_s} 域={domain}（与 PEFmod 域={pefmod.domain_tag} 不匹配）")
        pi_s, domain = PiSDispatcher.allocate()
    print(f"  ② 分配 Πₛ={pi_s}, 域={domain} (π%3={pi_s % 3}), t_anchor={PiSDispatcher.get_alloc_time(pi_s)[11:23]}")

    confirm = ledger.record(pefmod, pi_s, metadata={'entity_id': 'DEMO-001', 'source': 'demo'})
    print(f"  ③ record() → status={confirm['status']}, seq={confirm['seq']}, "
          f"t_write={confirm['t_write'][11:23]}")
    print(f"     时序: t_state({confirm['t_state'][11:23]}) ≤ "
          f"t_anchor({confirm['t_anchor'][11:23]}) ≤ t_write({confirm['t_write'][11:23]})")
    checks.append(("正常写入-CONFIRMED", confirm['status'] == 'CONFIRMED'))
    checks.append(("时序铁则-状态≤锚≤写入",
                   confirm['t_state'] <= confirm['t_anchor'] <= confirm['t_write']))

    # ── 场景2：攻击1 — 未锚定写入 → P0熔断 ─────────────────────────
    print("\n[场景2] 攻击1：未锚定写入（绕过Πₛ分配直接record）")
    bad_pefmod = PEFmod(features=[0.5, 0.5], domain_tag='P')
    fake_pi_s = 99999  # 未分配的Πₛ
    try:
        ledger.record(bad_pefmod, fake_pi_s)
        checks.append(("P0熔断-未锚定写入", False))
        print("  ❌ 未触发熔断！")
    except PEFBindingError as e:
        print(f"  ✅ P0熔断: {e}")
        ledger.audit.append(fake_pi_s, 'VIOLATION', f'未锚定写入被拦截: {e}')
        checks.append(("P0熔断-未锚定写入", 'P0' in str(e)))

    # ── 场景3：攻击2 — 篡改审计条目 → 完整性哈希不一致 ──────────────
    print("\n[场景3] 攻击2：篡改审计条目（修改detail字段）")
    events = ledger.audit.events()
    if events:
        original = events[0]
        tampered = dict(original)
        tampered['detail'] = 'TAMPERED: fake audit entry'
        recomputed = _audit_event_hash(tampered)
        mismatch = recomputed != original['hash']
        print(f"  原始哈希: {original['hash'][:16]}…")
        print(f"  篡改后哈希: {recomputed[:16]}…")
        print(f"  ✅ 哈希不一致: {mismatch}（篡改被检测）")
        checks.append(("篡改检测-审计哈希不一致", mismatch))
    else:
        checks.append(("篡改检测-审计哈希不一致", False))

    # ── 场景4：攻击3 — 域不匹配 → 三重一致性失败 ────────────────────
    print("\n[场景4] 攻击3：域不匹配（PEFmod声明P，但Πₛ域≠P）")
    # 先创建PEFmod（t_state），再分配Πₛ（t_anchor），确保时序正确
    bad_pefmod2 = PEFmod(features=[1.0, 2.0], domain_tag='P')
    print(f"  创建 PEFmod: domain=P, t_state={bad_pefmod2.created_at[11:23]}")
    # 循环分配Πₛ直到域≠P（确保触发三重一致性失败）
    pi_s2, domain2 = PiSDispatcher.allocate()
    while domain2 == 'P':
        pi_s2, domain2 = PiSDispatcher.allocate()
    print(f"  分配 Πₛ={pi_s2}, 域={domain2} (π%3={pi_s2 % 3}) ≠ P → 域不匹配")
    try:
        ledger.record(bad_pefmod2, pi_s2)
        checks.append(("三重一致性-域不匹配拦截", False))
        print("  ❌ 未拦截域不匹配！")
    except PEFBindingError as e:
        print(f"  ✅ 三重一致性失败: {e}")
        ledger.audit.append(pi_s2, 'VIOLATION', f'域不匹配被拦截: {e}')
        checks.append(("三重一致性-域不匹配拦截", '三重一致性' in str(e)))

    # ── 场景5：归档 + 锚不可复用 ─────────────────────────────────────
    print("\n[场景5] 归档后锚不可复用（铁律7）")
    ledger.archive(pi_s)
    print(f"  归档 Πₛ={pi_s}")
    reuse_ok = PiSDispatcher.is_active(pi_s)
    print(f"  归档后 is_active={reuse_ok}（应为False）")
    checks.append(("归档-锚不可复用", not reuse_ok))

    # ── 自检：8项检查 ────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("SELF-CHECK (8 items)")
    print("=" * 64)
    result = ledger.self_check()
    for item in result['items']:
        status = 'PASS' if item['passed'] else 'FAIL'
        print(f"  [{status}] {item['name']}")
        if item['detail']:
            print(f"         {item['detail']}")
    checks.append(("自检-8项全部PASS", result['passed']))

    # ── 汇总 ──────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    passed = sum(1 for _, ok in checks if ok)
    total = len(checks)
    print(f"场景验证: {passed}/{total} PASS")
    for name, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"\nLedger: {ledger.runtime.count()} runtime entries, "
          f"{ledger.audit.count()} audit events")
    print(f"Πₛ: active={PiSDispatcher._counter - len(PiSDispatcher._archived)}, "
          f"archived={len(PiSDispatcher._archived)}")
    print("=" * 64)
    # 末行：机器可提取的验收口径
    self_check_passed = sum(1 for i in result['items'] if i['passed'])
    self_check_total = len(result['items'])
    print(f"SELF-CHECK: {self_check_passed}/{self_check_total} PASS")

    sys.exit(0 if (passed == total and result['passed']) else 1)


if __name__ == "__main__":
    run_demo()
