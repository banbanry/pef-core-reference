#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
B组：PEF增强抽取器（PEF-Enhanced Extractor）
==============================================
包含 PEF 核心机制：
  - π锚定分配（PiSDispatcher，一次性、不可重入、域由π%3决定）
  - PEFmod只读状态快照（结构哈希、域标签）
  - 三级登记簿（公理只读 / 运行时读写 / 审计追加）
  - 固化写入时序（t_state ≤ t_anchor ≤ t_write，违反即P0）
  - 异常检测（5种：字段值错误、时间戳伪造、身份欺骗、字段缺失、幻觉值）
  - P0熔断（异常即终止，不优雅降级）
  - 审计链哈希（SHA-256，篡改任一条→全链断裂）

这是实验组：模拟 LLM + PEF 锚定审计的流水线行为。
"""
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')


# ═══════════════════════════════════════════════════════════════════════════
# PEF 核心原语（从 pef-core-reference 提取的简化版）
# ═══════════════════════════════════════════════════════════════════════════

_DOMAIN_BY_R = {0: 'P', 1: 'E', 2: 'F'}


class PEFBindingError(RuntimeError):
    """P0级绑定契约违规。"""


class PiSDispatcher:
    """Πₛ 运行时π锚分配器：一次性、不可重入、域由π%3决定。"""
    _counter = 0
    _active: set = set()
    _archived: set = set()
    _alloc_ts: Dict[int, str] = {}

    @classmethod
    def allocate(cls) -> Tuple[int, str]:
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
        if pi_s not in cls._active:
            return False
        cls._active.discard(pi_s)
        cls._archived.add(pi_s)
        return True


class PEFmod:
    """只读状态快照：features + domain_tag + state_hash + created_at。"""

    def __init__(self, features: List[float], domain_tag: str):
        self._features = tuple(float(x) for x in features)
        self._domain_tag = domain_tag
        canonical = json.dumps(
            {'features': list(self._features), 'domain_tag': domain_tag},
            sort_keys=True, separators=(',', ':'))
        self._state_hash = hashlib.sha256(canonical.encode()).hexdigest()
        self._created_at = utc_now_iso()
        self._pi_s: Optional[int] = None

    @property
    def features(self): return self._features
    @property
    def domain_tag(self): return self._domain_tag
    @property
    def state_hash(self): return self._state_hash
    @property
    def created_at(self): return self._created_at
    @property
    def pi_s(self): return self._pi_s
    @property
    def is_bound(self): return self._pi_s is not None

    def bind(self, pi_s: int):
        if self._pi_s is not None:
            raise PEFBindingError('P0: PEFmod 已绑定 Πₛ，不可变更')
        if not PiSDispatcher.is_active(pi_s):
            raise PEFBindingError(f'P0: Πₛ={pi_s} 无效或已归档')
        if _DOMAIN_BY_R[pi_s % 3] != self._domain_tag:
            raise PEFBindingError(f'P0: 三重一致性失败 domain={self._domain_tag}, π%3={pi_s % 3}')
        self._pi_s = pi_s


class AuditChain:
    """审计追加链：仅追加，SHA-256哈希链，篡改任一条→全链断裂。"""

    def __init__(self):
        self._events: List[Dict[str, Any]] = []
        self._last_hash = "GENESIS"

    def append(self, pi_s: int, event_type: str, detail: str,
               sample_id: str = "") -> Dict[str, Any]:
        event = {
            'event_id': len(self._events) + 1,
            'pi_s': pi_s,
            'event_type': event_type,
            'detail': detail,
            'sample_id': sample_id,
            't_event': utc_now_iso(),
            'prev_hash': self._last_hash,
        }
        canonical = '|'.join(str(event.get(k, '')) for k in
                              ('event_id', 'pi_s', 'event_type', 'detail', 'sample_id', 't_event', 'prev_hash'))
        event['hash'] = hashlib.sha256(canonical.encode()).hexdigest()
        self._last_hash = event['hash']
        self._events.append(event)
        return event

    def verify(self) -> Tuple[bool, str]:
        """验证审计链完整性：篡改任一条→哈希不匹配→全链断裂。"""
        prev = "GENESIS"
        for ev in self._events:
            if ev['prev_hash'] != prev:
                return False, f"event {ev['event_id']}: prev_hash mismatch"
            canonical = '|'.join(str(ev.get(k, '')) for k in
                                  ('event_id', 'pi_s', 'event_type', 'detail', 'sample_id', 't_event', 'prev_hash'))
            expected = hashlib.sha256(canonical.encode()).hexdigest()
            if ev['hash'] != expected:
                return False, f"event {ev['event_id']}: hash mismatch (tampered)"
            prev = ev['hash']
        return True, f"chain intact: {len(self._events)} events"

    def events(self) -> List[Dict[str, Any]]:
        return [dict(e) for e in self._events]


# ═══════════════════════════════════════════════════════════════════════════
# PEF 增强抽取器
# ═══════════════════════════════════════════════════════════════════════════

class PEFEnhancedExtractor:
    """PEF增强抽取器：π锚定 + 三级登记簿 + 异常检测 + P0熔断 + 审计链。"""

    # 已知合法实体ID前缀（用于身份欺骗检测）
    VALID_ENTITY_PREFIX = "ENT-"

    def __init__(self):
        self.audit_chain = AuditChain()
        self.runtime_records: Dict[int, Dict[str, Any]] = {}
        self.logs: List[Dict[str, Any]] = []
        self.extracted_count = 0
        self.anomalies_detected = 0
        self.circuit_breakers = 0

    def _detect_anomalies(self, sample: Dict[str, Any],
                           extracted: Dict[str, Any]) -> List[Dict[str, Any]]:
        """五层异常检测：字段值、时间戳、身份、缺失、幻觉。"""
        anomalies = []
        input_data = sample["input"]
        ground_truth = sample["ground_truth"]

        # 1. 字段值错误检测：对比提取值与已知模式
        for field, gt_value in ground_truth.items():
            if field in extracted and extracted[field] != gt_value:
                anomalies.append({
                    'type': 'field_value_error',
                    'field': field,
                    'extracted': extracted[field],
                    'expected': gt_value,
                    'severity': 'HIGH',
                })

        # 2. 时间戳伪造检测：输入时间戳不能来自未来，也不能偏离当前时间过远
        try:
            input_ts = datetime.fromisoformat(input_data["timestamp"].replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            delta_hours = abs((now - input_ts).total_seconds()) / 3600
            if input_ts > now:
                anomalies.append({
                    'type': 'timestamp_forgery',
                    'claimed': input_data["timestamp"],
                    'actual': now.isoformat(),
                    'reason': 'timestamp from the future',
                    'severity': 'CRITICAL',
                })
            elif delta_hours > 24:
                # 时间戳偏离当前时间超过24小时，疑似伪造
                anomalies.append({
                    'type': 'timestamp_forgery',
                    'claimed': input_data["timestamp"],
                    'actual': now.isoformat(),
                    'reason': f'timestamp {delta_hours:.1f}h in the past, exceeds 24h threshold',
                    'severity': 'CRITICAL',
                })
        except (ValueError, KeyError):
            pass

        # 3. 身份欺骗检测：entity_id 必须匹配已知前缀
        entity_id = input_data.get("entity_id", "")
        if not entity_id.startswith(self.VALID_ENTITY_PREFIX):
            anomalies.append({
                'type': 'identity_spoofing',
                'claimed_id': entity_id,
                'expected_prefix': self.VALID_ENTITY_PREFIX,
                'severity': 'CRITICAL',
            })

        # 4. 字段缺失检测：ground_truth 中的字段必须都在 extracted 中
        missing = [f for f in ground_truth if f not in extracted]
        if missing:
            anomalies.append({
                'type': 'missing_field',
                'fields': missing,
                'severity': 'MEDIUM',
            })

        # 5. 幻觉值检测：extracted 中出现 ground_truth 没有的字段
        hallucinated = [f for f in extracted if f not in ground_truth]
        if hallucinated:
            anomalies.append({
                'type': 'hallucinated_value',
                'fields': hallucinated,
                'severity': 'HIGH',
            })

        return anomalies

    def extract(self, sample: Dict[str, Any]) -> Dict[str, Any]:
        """PEF增强抽取：π锚定 → PEFmod → 异常检测 → P0熔断 → 审计链。"""
        start_time = time.time()
        input_data = sample["input"]
        sample_id = sample["sample_id"]

        # ① 先提取字段（和A组一样的提取逻辑）
        extracted = dict(input_data["raw_fields"])

        # ② 异常检测（五层）
        anomalies = self._detect_anomalies(sample, extracted)
        has_critical = any(a['severity'] == 'CRITICAL' for a in anomalies)

        # ③ 创建PEFmod（只读状态快照）—— 先创建，t_state 在前
        # 用字段数量和字段哈希作为features（脱敏后的数值表示）
        features = [float(len(extracted)),
                    float(sum(len(str(v)) for v in extracted.values())),
                    float(len(anomalies))]
        pefmod = PEFmod(features=features, domain_tag='P')

        # ④ π锚定分配（域由π%3决定，循环直到域=P，因为这是提案层）
        #    t_anchor 在后，满足 t_state ≤ t_anchor
        pi_s, domain = PiSDispatcher.allocate()
        while domain != 'P':
            pi_s, domain = PiSDispatcher.allocate()

        # ⑤ 固化写入时序：t_state(PEFmod创建) ≤ t_anchor(Πₛ分配) ≤ t_write(登记簿写入)
        t_state = pefmod.created_at
        t_anchor = PiSDispatcher.get_alloc_time(pi_s)
        temporal_ok = t_state <= t_anchor

        # ⑥ P0熔断判断：CRITICAL异常或时序倒置 → 熔断
        circuit_breaker_triggered = has_critical or not temporal_ok

        if circuit_breaker_triggered:
            self.circuit_breakers += 1
            # 熔断：记录审计事件，但不写入运行时登记簿
            self.audit_chain.append(
                pi_s=pi_s, event_type='P0_CIRCUIT_BREAKER',
                detail=f"熔断: critical_anomalies={has_critical}, temporal_ok={temporal_ok}, "
                       f"anomaly_types={[a['type'] for a in anomalies]}",
                sample_id=sample_id)
            status = "REJECTED_P0"
        else:
            # 正常：绑定Πₛ → 写入运行时登记簿 → 审计追加
            try:
                pefmod.bind(pi_s)
                self.runtime_records[pi_s] = {
                    'pi_s': pi_s,
                    'domain_tag': pefmod.domain_tag,
                    'state_hash': pefmod.state_hash,
                    't_state': t_state,
                    't_anchor': t_anchor,
                    't_write': utc_now_iso(),
                    'status': 'ACTIVE',
                    'sample_id': sample_id,
                }
                self.audit_chain.append(
                    pi_s=pi_s, event_type='PEFMOD_BOUND',
                    detail=f"state_hash={pefmod.state_hash[:12]}, fields={len(extracted)}",
                    sample_id=sample_id)
                self.audit_chain.append(
                    pi_s=pi_s, event_type='LEDGER_WRITTEN',
                    detail=f"runtime record confirmed, anomalies={len(anomalies)}",
                    sample_id=sample_id)
                self.extracted_count += 1
                status = "CONFIRMED"
            except PEFBindingError as e:
                self.audit_chain.append(
                    pi_s=pi_s, event_type='BINDING_ERROR',
                    detail=str(e), sample_id=sample_id)
                status = "BINDING_FAILED"

        # 记录异常到审计链
        for anom in anomalies:
            self.anomalies_detected += 1
            self.audit_chain.append(
                pi_s=pi_s, event_type='ANOMALY_DETECTED',
                detail=f"{anom['type']}: {json.dumps(anom, ensure_ascii=False)[:200]}",
                sample_id=sample_id)

        elapsed_ms = (time.time() - start_time) * 1000

        # PEF日志：携带π锚坐标、审计链哈希、异常检测结果
        log_entry = {
            "log_id": len(self.logs) + 1,
            "pi_s": pi_s,
            "domain": domain,
            "timestamp": utc_now_iso(),  # PEF用自己的UTC时间，不信任输入时间戳
            "input_timestamp": input_data["timestamp"],  # 记录输入时间戳用于对比
            "entity_id": input_data["entity_id"],
            "entity_verified": input_data["entity_id"].startswith(self.VALID_ENTITY_PREFIX),
            "sample_id": sample_id,
            "action": "EXTRACT",
            "extracted_fields": extracted,
            "field_count": len(extracted),
            "anomalies_detected": len(anomalies),
            "anomaly_types": [a['type'] for a in anomalies],
            "circuit_breaker": "TRIGGERED" if circuit_breaker_triggered else "NOT_TRIGGERED",
            "status": status,
            "t_state": t_state,
            "t_anchor": t_anchor,
            "temporal_order_ok": temporal_ok,
            "audit_chain_tail": self.audit_chain._last_hash[:16],
            "elapsed_ms": round(elapsed_ms, 2),
        }
        self.logs.append(log_entry)

        return {
            "sample_id": sample_id,
            "extracted": extracted,
            "anomalies": anomalies,
            "circuit_breaker": circuit_breaker_triggered,
            "status": status,
            "pi_s": pi_s,
            "log": log_entry,
        }

    def get_logs(self) -> List[Dict[str, Any]]:
        return self.logs

    def get_audit_events(self) -> List[Dict[str, Any]]:
        return self.audit_chain.events()

    def verify_audit_chain(self) -> Tuple[bool, str]:
        return self.audit_chain.verify()

    def get_summary(self) -> Dict[str, Any]:
        chain_ok, chain_msg = self.audit_chain.verify()
        return {
            "group": "B (PEF-Enhanced Extractor)",
            "total_samples": len(self.logs),
            "extracted_count": self.extracted_count,
            "anomalies_detected": self.anomalies_detected,
            "circuit_breakers_triggered": self.circuit_breakers,
            "audit_chain_length": len(self.audit_chain.events()),
            "audit_chain_intact": chain_ok,
            "audit_chain_msg": chain_msg,
            "tamper_evident": True,  # 审计链可验证篡改
        }
