#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEF_StateLedger（PEF状态登记簿）— PEF 架构【第二步】交付物
================================================================
三级登记簿：
  1. 公理层只读登记簿（PEFAxiomLedger）  —— 固化公理事实，只读，写入即 P0
  2. 运行时读写登记簿（PEFRuntimeLedger）—— Πₛ 主键条目，关联主体快照 S_t
  3. 审计追加登记簿（PEFAuditLedger）    —— 仅追加事件流，不可修改/删除

写入时序固化（第二步 2③）：
  PEFmod状态更新 → 生成有效Πₛ → PEF_StateLedger持久写入确认

配套自检逻辑（第二步 3）：
  ① 校验登记簿全部记录携带合法有效的 Πₛ
  ② 校验 Πₛ 与 PEFmod 实例一一对应关系
  ③ 识别时序倒置违规逻辑并标记

Π₀ 隔离：本模块不导入 pi_constants（Π₀ 基准标尺常量），登记簿只承载
         运行时 Πₛ 锚实例，不存储、不绑定、不运算 Π₀。
绑定边界：仅 PEF_StateLedger.record() 与 PEFmod.bind() 创建 Πₛ 绑定；
         其余组件只可引用 Πₛ 凭证（int 锚号），禁止直接绑定。
"""
import copy
import hashlib
import json
import os
import threading
import weakref
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .pefmod import (
    PEFmod, PiSDispatcher, PEFBindingError, _DOMAIN_BY_R, utc_now_iso,
)

# ---------------------------------------------------------------------------
# 标准条目结构体定义（第二步交付物：登记簿完整结构体定义）
# ---------------------------------------------------------------------------
RUNTIME_ENTRY_SCHEMA = {
    'pi_s': 'int（Πₛ 核心索引主键，唯一）',
    'domain_tag': 'str（P/E/F）',
    'features': 'list[float]（主体快照 S_t）',
    'state_hash': 'str（SHA256）',
    't_state': 'ISO8601（PEFmod 状态更新时刻）',
    't_anchor': 'ISO8601（Πₛ 生成时刻）',
    't_write': 'ISO8601（登记簿持久写入时刻）',
    'seq': 'int（全局写入序号，单调递增）',
    'status': 'ACTIVE | ARCHIVED',
    'metadata': 'dict（可选，JSON 对象；业务溯源元数据，内核不解析其内部结构）',
}

AUDIT_EVENT_SCHEMA = {
    'event_id': 'int（追加序号）',
    'pi_s': 'int（Πₛ 凭证引用）',
    'event_type': 'str（ANCHOR_ALLOCATED/PEFMOD_BOUND/LEDGER_WRITTEN/'
                  'LEDGER_ARCHIVED/VIOLATION）',
    'detail': 'str',
    't_event': 'ISO8601',
    'hash': 'str（SHA256 完整性哈希，防篡改）',
}

AXIOM_FACT_SCHEMA = {
    'fact_id': 'str（唯一事实标识）',
    'axiom': 'str（对应公理/铁律编号）',
    'value': 'any（不可变常量）',
    'readonly': 'true（公理层一律只读）',
}

_EVENT_TYPES = frozenset({
    'ANCHOR_ALLOCATED', 'PEFMOD_BOUND', 'LEDGER_WRITTEN',
    'LEDGER_ARCHIVED', 'VIOLATION',
})

_RUNTIME_REQUIRED_KEYS = (
    'pi_s', 'domain_tag', 'features', 'state_hash',
    't_state', 't_anchor', 't_write', 'seq', 'status',
)


def _audit_event_hash(ev: Dict[str, Any]) -> str:
    """审计条目完整性哈希：SHA256(event_id|pi_s|event_type|detail|t_event)。

    用于审计账本防篡改自检：篡改任一字段 → 重算哈希不一致 → 标记 AUDIT_TAMPERED。
    """
    canonical = '|'.join(
        str(ev.get(k, '')) for k in ('event_id', 'pi_s', 'event_type', 'detail', 't_event'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


# ---------------------------------------------------------------------------
# 一级：公理层只读登记簿
# ---------------------------------------------------------------------------
class PEFAxiomLedger:
    """公理层只读登记簿：固化公理事实常量。

    只读契约：构造时一次性装载；不暴露任何写接口，任何写入尝试 → P0。
    事实来源：framework_config 的 pef 段 + 宪法默认值
    （域映射 / λ阈值 / 绑定边界 / Π₀ 隔离 / 写入时序）。
    """

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
            'pi_zero_isolation': {
                'fact_id': 'pi_zero_isolation',
                'axiom': '第二步 1②（Π₀ 隔离）',
                'value': 'Π₀ 不参与任何绑定、存储、运行时逻辑',
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
        """只读视图（深拷贝防篡改公理事实）。"""
        return copy.deepcopy(self._facts)

    def get_fact(self, fact_id: str) -> Dict[str, Any]:
        f = self._facts.get(fact_id)
        if f is None:
            raise PEFBindingError(f'P0: 公理事实不存在 fact_id={fact_id}')
        return copy.deepcopy(f)

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


# ---------------------------------------------------------------------------
# 二级：运行时读写登记簿
# ---------------------------------------------------------------------------
class PEFRuntimeLedger:
    """运行时读写登记簿：Πₛ 主键 → 标准条目；关联主体快照 S_t。

    读写契约：put/get/entries/update_status；主键唯一（同 Πₛ 二次写入 → P0）。
    put 仅做结构校验（RUNTIME_ENTRY_SCHEMA），L1 级校验（锚合法性/时序）
    由 PEF_StateLedger.record() 负责，自检负责兜底复核。
    """

    def __init__(self):
        self._entries: Dict[int, Dict[str, Any]] = {}
        self._seq_counter = 0
        self._lock = threading.RLock()

    def next_seq(self) -> int:
        with self._lock:
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
        with self._lock:
            self._entries[pi_s] = dict(entry)
        return dict(self._entries[pi_s])

    def get(self, pi_s: int) -> Optional[Dict[str, Any]]:
        e = self._entries.get(pi_s)
        return dict(e) if e is not None else None

    def entries(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._entries.values()]

    def update_status(self, pi_s: int, status: str) -> bool:
        with self._lock:
            e = self._entries.get(pi_s)
            if e is None:
                return False
            e['status'] = status
            return True

    def count(self) -> int:
        return len(self._entries)

    def remove(self, pi_s: int) -> bool:
        """移除条目（cleanup_by_age 使用）。"""
        with self._lock:
            return self._entries.pop(pi_s, None) is not None

    def load_all(self, entries: List[Dict[str, Any]]) -> int:
        """持久化恢复：逐条 put（主键已存在则跳过）。"""
        n = 0
        for e in entries:
            if not isinstance(e, dict) or e.get('pi_s') in self._entries:
                continue
            self.put(e)
            n += 1
        if self._entries:
            self._seq_counter = max(x['seq'] for x in self._entries.values())
        return n


# ---------------------------------------------------------------------------
# 三级：审计追加登记簿
# ---------------------------------------------------------------------------
class PEFAuditLedger:
    """审计追加登记簿：仅追加事件流（不可修改、不可删除）。

    对齐公理：七、审计日志（仅追加，Delta_V 无权修改）。
    """

    def __init__(self):
        self._events: List[Dict[str, Any]] = []
        self._counter = 0
        self._lock = threading.RLock()

    def append(self, pi_s, event_type: str, detail: str = '') -> Dict[str, Any]:
        if event_type and event_type not in _EVENT_TYPES:
            raise PEFBindingError(f'P0: 非法审计事件类型 {event_type}')
        with self._lock:
            self._counter += 1
            ev = {
                'event_id': self._counter,
                'pi_s': pi_s,
                'event_type': event_type,
                'detail': detail,
                't_event': utc_now_iso(),
            }
            ev['hash'] = _audit_event_hash(ev)   # 防篡改完整性哈希
            self._events.append(ev)
            return dict(ev)

    def append_raw(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        """恢复历史事件用：原样追加（保留原 t_event，重算完整性哈希）。"""
        with self._lock:
            ev = dict(ev)
            ev['hash'] = _audit_event_hash(ev)
            self._events.append(ev)
            return dict(ev)

    def events(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._events]

    def count(self) -> int:
        return len(self._events)


# ---------------------------------------------------------------------------
# PEF_StateLedger —— 三级登记簿门面（写入时序 + 自检 + 持久化）
# ---------------------------------------------------------------------------
class PEF_StateLedger:
    """PEF状态登记簿（三级：公理只读 / 运行时读写 / 审计追加）。

    固化写入时序（record）：
      ① PEFmod 状态更新 —— 取自 pefmod.created_at（t_state）
      ② 生成有效 Πₛ     —— 取自 PiSDispatcher.get_alloc_time（t_anchor），
                            record() 前置校验 Πₛ 合法性（L1）
      ③ 登记簿持久写入确认 —— record() 完成运行时写入 + 审计追加 + 持久化，
                            返回 CONFIRMED 确认（t_write）

    绑定边界：仅本 record() 与 PEFmod.bind() 创建 Πₛ 绑定；
    其余组件只可引用 Πₛ 凭证（int），禁止直接绑定。

    Π₀ 隔离：本模块不导入 pi_constants，不存储/绑定/运算 Π₀。
    """

    def __init__(self, axiom_config: Optional[Dict[str, Any]] = None,
                 persist_dir: Optional[str] = None):
        self.axiom = PEFAxiomLedger(axiom_config)
        self.runtime = PEFRuntimeLedger()
        self.audit = PEFAuditLedger()
        self._persist_dir: Optional[str] = None
        self._lock = threading.RLock()
        self._recorded_pefmods: weakref.WeakSet = weakref.WeakSet()
        self._audit_persisted = 0
        if persist_dir:
            self.attach_persistence(persist_dir)

    # ---------------- 绑定/写入（固化时序）----------------
    def record(self, pefmod: PEFmod, pi_s: int,
               metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """核心写入：PEFmod状态更新 → 生成有效Πₛ → 持久写入确认。

        Args:
            pefmod: 主体快照（PEFmod）
            pi_s: 已分配的有效 Πₛ
            metadata: 可选业务溯源元数据（JSON 对象，内核不解析其结构）

        Returns:
            确认字典 {pi_s, seq, t_state, t_anchor, t_write, status: 'CONFIRMED', metadata?}
        Raises:
            PEFBindingError: 任一契约/时序校验失败（P0）
        """
        if not isinstance(pefmod, PEFmod):
            raise PEFBindingError(
                f'P0: 主体必须为 PEFmod 实例，收到 {type(pefmod).__name__}')
        if metadata is not None:
            if not isinstance(metadata, dict):
                raise PEFBindingError('P0: metadata 必须为 dict（JSON 对象）')
            try:
                metadata = json.loads(json.dumps(metadata, ensure_ascii=False))
            except (TypeError, ValueError):
                raise PEFBindingError('P0: metadata 必须可 JSON 序列化')
        with self._lock:
            # ① L1 π 合法性（黑名单3：算子无绑定π）
            if not isinstance(pi_s, int) or not PiSDispatcher.is_active(pi_s):
                raise PEFBindingError(
                    f'P0: Πₛ={pi_s} 无效或未活动，禁止登记（引用未来态）')
            # ① 三重一致性（铁律1）
            ok, msg = self.axiom.validate_domain(pi_s, pefmod.domain_tag)
            if not ok:
                raise PEFBindingError(msg)
            # ② 一对一：不可共享 / 不可变更
            if self.runtime.get(pi_s) is not None:
                raise PEFBindingError(
                    f'P0: Πₛ={pi_s} 已登记于运行时登记簿（不可共享）')
            if pefmod.is_bound:
                raise PEFBindingError('P0: PEFmod 已绑定 Πₛ，不可变更/重复登记')
            if id(pefmod) in {id(p) for p in self._recorded_pefmods}:
                raise PEFBindingError('P0: 该 PEFmod 实例已登记（一对一唯一）')
            # ③ 固化写入时序：状态更新 ≤ 锚生成 ≤ 写入
            t_state = pefmod.created_at
            t_anchor = PiSDispatcher.get_alloc_time(pi_s)
            if t_anchor is None:
                raise PEFBindingError(
                    f'P0: Πₛ={pi_s} 无锚生成时间（时序倒置）')
            if t_state > t_anchor:
                raise PEFBindingError(
                    f'P0: 时序倒置 t_state({t_state}) > t_anchor({t_anchor})：'
                    'Πₛ 必须先于 PEFmod 状态绑定生成')
            # ④ 执行绑定（PEFmod 侧一次性绑定 + 分配器不可共享注册）
            pefmod.bind(pi_s)
            # ⑤ 组装标准条目并写入运行时登记簿
            t_write = utc_now_iso()
            if t_anchor > t_write:
                raise PEFBindingError(
                    f'P0: 时序倒置 t_anchor({t_anchor}) > t_write({t_write})')
            # ③.1 快照时间单调性（跨条目）：新快照 t_state 不得早于登记簿最新 t_state
            last_t_state = max((e['t_state'] for e in self.runtime.entries()), default=None)
            if last_t_state is not None and t_state < last_t_state:
                raise PEFBindingError(
                    f'P0: 快照时间单调性冲突 t_state({t_state}) < 登记簿最新 '
                    f't_state({last_t_state})：禁止回写更早历史快照')
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
            self._recorded_pefmods.add(pefmod)
            confirm = {
                'pi_s': pi_s, 'seq': seq,
                't_state': t_state, 't_anchor': t_anchor, 't_write': t_write,
                'status': 'CONFIRMED',
            }
            if metadata is not None:
                confirm['metadata'] = metadata
            # ⑥ 审计追加
            self.audit.append(pi_s, 'PEFMOD_BOUND',
                              f'state_hash={pefmod.state_hash[:12]} seq={seq}')
            self.audit.append(pi_s, 'LEDGER_WRITTEN', f'seq={seq} 持久写入确认')
            # ⑦ 持久写入确认
            self._persist()
            return confirm

    def archive(self, pi_s: int) -> bool:
        """归档条目与锚（铁律7 链路结束销毁上下文）。"""
        with self._lock:
            if self.runtime.update_status(pi_s, 'ARCHIVED'):
                PiSDispatcher.archive(pi_s)
                self.audit.append(pi_s, 'LEDGER_ARCHIVED', '条目归档，Πₛ 移入归档集')
                self._persist()
                return True
            return False

    def destroy_context(self) -> int:
        """销毁上下文：归档全部 ACTIVE 条目并切断记录引用（铁律7）。"""
        with self._lock:
            n = 0
            for e in self.runtime.entries():
                if e['status'] == 'ACTIVE' and self.archive(e['pi_s']):
                    n += 1
            self._recorded_pefmods.clear()
            return n

    # ---------------- 持久化 ----------------
    def attach_persistence(self, persist_dir: str) -> str:
        """显式挂载持久化目录（业务层显式选择后调用；模块加载不自动建目录）。"""
        d = os.path.abspath(persist_dir)
        os.makedirs(d, exist_ok=True)
        self._persist_dir = d
        return d

    def _runtime_path(self) -> Optional[str]:
        if not self._persist_dir:
            return None
        return os.path.join(self._persist_dir, 'state_ledger_runtime.json')

    def _audit_path(self) -> Optional[str]:
        if not self._persist_dir:
            return None
        return os.path.join(self._persist_dir, 'state_ledger_audit.jsonl')

    def _persist(self) -> bool:
        """运行时登记簿原子替换 + 审计登记簿 JSONL 仅追加。"""
        if not self._persist_dir:
            import warnings
            warnings.warn('PEF_StateLedger: 未配置持久化目录，跳过写入')
            return False
        os.makedirs(self._persist_dir, exist_ok=True)
        rpath = self._runtime_path()
        tmp = rpath + '.work.json'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(self.runtime.entries(), f, ensure_ascii=False, indent=2)
        os.replace(tmp, rpath)
        apath = self._audit_path()
        events = self.audit.events()
        new_events = events[self._audit_persisted:]
        if new_events:
            with open(apath, 'a', encoding='utf-8') as f:
                for ev in new_events:
                    f.write(json.dumps(ev, ensure_ascii=False) + '\n')
            self._audit_persisted = len(events)
        return True

    def load(self) -> Tuple[int, int]:
        """从持久化目录恢复运行时条目与审计事件（自检跨重启可追溯）。"""
        if not self._persist_dir:
            return 0, 0
        n = 0
        rpath = self._runtime_path()
        if rpath and os.path.exists(rpath):
            with open(rpath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            n = self.runtime.load_all(data if isinstance(data, list) else [])
        m = 0
        apath = self._audit_path()
        if apath and os.path.exists(apath):
            with open(apath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if not isinstance(ev, dict):
                        continue
                    self.audit.append_raw(ev)
                    m += 1
        return n, m

    def cleanup_by_age(self, days: int = 30) -> Tuple[int, int]:
        """基于 t_write 清理过期运行时条目（安全模式：内存筛选 → 原子重写）。

        返回 (扫描总条数, 清理条数)。需先 attach_persistence 挂载目录。
        配合既有归档机制：每次归档任务完成后调用（保留天数取业务配置 anchor_retention_days）。
        审计账本保持仅追加不被清理；被清理条目的 Πₛ 归档（永不复用，黑名单5）。
        无法解析时间的异常条目 → 保留（不误删）。
        """
        if not self._persist_dir:
            return (0, 0)
        with self._lock:
            entries = self.runtime.entries()
            cutoff = datetime.now(timezone.utc).timestamp() - max(1, int(days)) * 86400
            total = 0
            removed = 0
            for e in entries:
                total += 1
                tw = str(e.get('t_write', ''))
                try:
                    ts = datetime.fromisoformat(tw.replace('Z', '+00:00'))
                    if ts.timestamp() < cutoff:
                        removed += 1
                        PiSDispatcher.archive(e['pi_s'])
                        self.runtime.remove(e['pi_s'])
                except Exception:
                    pass   # 无法解析 → 保留（不误删）
            if removed:
                self.audit.append(0, 'LEDGER_ARCHIVED',
                                  f'cleanup_by_age: 扫描{total}条 清理{removed}条 保留{days}天')
                self._persist()
            return (total, removed)

    # ---------------- 配套自检逻辑 ----------------
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

        # ① Πₛ 合法性（L1 π合法性 + 引用未来态检测）
        bad_pi = [e['pi_s'] for e in entries if not PiSDispatcher.is_known(e['pi_s'])]
        item('Πₛ合法性-运行时条目', not bad_pi,
             f'{len(entries)} 条记录全部引用已分配 Πₛ' if not bad_pi
             else f'违规：{bad_pi} 引用未分配/未来态 Πₛ')
        for pi_s in bad_pi:
            violations.append({'pi_s': pi_s, 'kind': 'INVALID_PI_S',
                               'detail': '登记条目引用未分配 Πₛ（引用未来态）'})

        # ① 域一致性（铁律1）
        bad_dom = [e['pi_s'] for e in entries
                   if not self.axiom.validate_domain(e['pi_s'], e['domain_tag'])[0]]
        item('域一致性-铁律1', not bad_dom,
             '全部条目 π%3 与 domain_tag 一致' if not bad_dom
             else f'违规：{bad_dom} π%3 与 domain_tag 不一致')
        for pi_s in bad_dom:
            violations.append({'pi_s': pi_s, 'kind': 'DOMAIN_MISMATCH',
                               'detail': 'π%3 映射域与条目 domain_tag 不一致（铁律1）'})

        # ② Πₛ ↔ PEFmod 一一对应
        keys = [e['pi_s'] for e in entries]
        dup_keys = {k for k in keys if keys.count(k) > 1}
        item('一对一-Πₛ主键唯一', not dup_keys,
             '运行时登记簿 Πₛ 主键无重复' if not dup_keys
             else f'违规：重复主键 {sorted(dup_keys)}')
        for k in dup_keys:
            violations.append({'pi_s': k, 'kind': 'DUPLICATE_BINDING',
                               'detail': 'Πₛ 主键重复（不可共享）'})

        live_bad: List[str] = []
        for pm in list(self._recorded_pefmods):
            chk = pm.check_binding()
            if not chk['ok']:
                live_bad.append(f'pefmod<{id(pm)}> {chk["reason"]}')
                violations.append({'pi_s': pm.pi_s, 'kind': 'INVALID_BINDING',
                                   'detail': f'pefmod<{id(pm)}> {chk["reason"]}'})
                continue
            e = self.runtime.get(pm.pi_s)
            if e is None:
                live_bad.append(f'pefmod<{id(pm)}> 绑定 Πₛ={pm.pi_s} 但登记簿无条目')
                violations.append({'pi_s': pm.pi_s, 'kind': 'UNRECORDED_BINDING',
                                   'detail': 'PEFmod 已绑定但登记簿无对应条目'})
            elif e['state_hash'] != pm.state_hash:
                live_bad.append(f'pefmod<{id(pm)}> 状态哈希与条目不一致')
                violations.append({'pi_s': pm.pi_s, 'kind': 'STATE_HASH_MISMATCH',
                                   'detail': 'PEFmod 快照与登记条目状态哈希不一致'})
        item('一对一-PEFmod↔Πₛ', not live_bad,
             f'{len(self._recorded_pefmods)} 个活跃 PEFmod 全部一一对应'
             if not live_bad else f'违规：{live_bad}')

        # ③ 时序倒置识别与标记
        bad_time = []
        for e in entries:
            if not (e['t_state'] <= e['t_anchor'] <= e['t_write']):
                bad_time.append(e['pi_s'])
                violations.append({
                    'pi_s': e['pi_s'], 'kind': 'TEMPORAL_INVERSION',
                    'detail': (f"时序倒置 t_state({e['t_state']}) ≤ "
                               f"t_anchor({e['t_anchor']}) ≤ t_write({e['t_write']}) 不成立"),
                })
        item('时序-状态≤锚≤写入', not bad_time,
             '全部条目满足 t_state ≤ t_anchor ≤ t_write' if not bad_time
             else f'违规：{bad_time} 时序倒置')

        seqs = sorted(e['seq'] for e in entries)
        seq_bad = len(seqs) > 1 and any(b <= a for a, b in zip(seqs, seqs[1:]))
        item('时序-写入序号单调', not seq_bad,
             '写入序号 seq 严格单调递增' if not seq_bad else '违规：seq 回归')
        if seq_bad:
            violations.append({'pi_s': None, 'kind': 'SEQ_REGRESSION',
                               'detail': '写入序号 seq 非严格单调递增'})

        # Π₀ 隔离（结构性保证：登记簿无 Π₀ 字段）
        pi0_leak = any('pi_0' in e or 'baseline' in e for e in entries)
        item('Π₀隔离-登记簿不承载Π₀', not pi0_leak,
             '登记簿条目无 Π₀ 字段（模块不导入 pi_constants，结构性保证）')

        # 审计账本防篡改（完整性哈希一致）
        bad_audit = [ev.get('event_id') for ev in self.audit.events()
                     if ev.get('hash') != _audit_event_hash(ev)]
        item('审计-防篡改哈希一致', not bad_audit,
             f'{self.audit.count()} 条审计事件哈希全部一致' if not bad_audit
             else f'违规：审计条目 {bad_audit} 哈希不一致（账本被篡改）')
        for eid in bad_audit:
            violations.append({'pi_s': None, 'kind': 'AUDIT_TAMPERED',
                               'detail': f'审计条目 event_id={eid} 哈希不一致（账本被篡改）'})

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

    def self_check_report(self) -> str:
        r = self.self_check()
        lines = ['=' * 64, 'PEF_StateLedger 自检报告', '=' * 64]
        for i in r['items']:
            lines.append(f"  [{'PASS' if i['passed'] else 'FAIL'}] {i['name']}")
            if i['detail']:
                lines.append(f"        {i['detail']}")
        lines.append('-' * 64)
        if r['violations']:
            for v in r['violations']:
                lines.append(f"  [VIOLATION] Πₛ={v['pi_s']} {v['kind']} | {v['detail']}")
        else:
            lines.append('  [OK] 无违规')
        lines.append('-' * 64)
        lines.append(r['summary'])
        lines.append('=' * 64)
        return '\n'.join(lines)
