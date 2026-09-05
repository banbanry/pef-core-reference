#!/usr/bin/env python3
"""
CLE V3.8.2 公底层 (Single Source of Truth)
所有模块的统一常量、数据类型、协议接口和配置管理。
"""
from __future__ import annotations
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Set
from hashlib import sha256
import re

# === 1. 节点属性位掩码 ===
class NodeAttr:
    DANGER_SINK    = 0x001
    SAFE_SINK      = 0x002
    SOURCE_INPUT   = 0x004
    SANITIZER      = 0x008
    BLOCKER        = 0x010
    FLOAT_OP       = 0x020
    BLOCKING_DELAY = 0x040
    ALLOC_CALL     = 0x080
    DEALLOC_CALL   = 0x100
    LOCK_ACQUIRE   = 0x200
    LOCK_RELEASE   = 0x400
    TAINTED        = 0x800

# === 2. 严重级别与裁决类型 ===
class Severity(Enum):
    P0    = "P0"
    P1    = "P1"
    GAMMA = "GAMMA"
    INFO  = "INFO"

class Verdict(Enum):
    FAIL   = "FAIL"
    REVIEW = "REVIEW"
    PASS   = "PASS"
    GAMMA  = "GAMMA"

# === 3. 核心数据类型 ===
@dataclass
class CodeNode:
    node_id: int
    node_type: str
    source_line: str
    function_name: str
    line_number: int
    attributes: int = 0
    ast_node_type: str = ""
    variable_defs: Set[str] = field(default_factory=set)
    variable_uses: Set[str] = field(default_factory=set)
    children: List['CodeNode'] = field(default_factory=list)
    parent: Optional['CodeNode'] = None
    callee_function: str = ""

    def has_attribute(self, attr: int) -> bool:
        return (self.attributes & attr) != 0

    def add_attribute(self, attr: int) -> None:
        self.attributes |= attr

@dataclass
class AuditEvent:
    event_id: str
    node_id: int
    severity: str
    description: str
    causal_chain: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    file: str = ""
    line_range: List[int] = field(default_factory=list)

@dataclass
class AuditContext:
    """审计上下文：π调度+场景+分片+污点表的统一传递容器（设计第8章L813）"""
    pi_step: int = 0
    pi_digit: int = -1
    source_hash: str = ""
    scene: str = "generic"
    shard_id: int = 0
    taint_table: Dict[str, Any] = field(default_factory=dict)
    operator_results: Dict[str, Any] = field(default_factory=dict)
    parsed_nodes: int = 0
    total_nodes: int = 0
    edge_count: int = 0
    ast_parsed_nodes: int = 0
    unexpected_findings: int = 0
    total_findings: int = 0
    failed_byzantine: int = 0
    total_byzantine: int = 0

    def snapshot(self) -> Dict[str, Any]:
        return {
            "pi_step": self.pi_step, "pi_digit": self.pi_digit,
            "source_hash": self.source_hash, "scene": self.scene,
            "shard_id": self.shard_id, "parsed_nodes": self.parsed_nodes,
            "total_nodes": self.total_nodes, "edge_count": self.edge_count,
            "ast_parsed_nodes": self.ast_parsed_nodes,
            "unexpected_findings": self.unexpected_findings,
            "total_findings": self.total_findings,
            "failed_byzantine": self.failed_byzantine,
            "total_byzantine": self.total_byzantine,
        }

@dataclass
class StateVector:
    s1_parsability: float = 0.0
    s2_graph_integrity: float = 0.0
    s3_confidence: float = 0.0
    s4_deviation_rate: float = 0.0
    s5_byzantine_risk: float = 0.0
    s6_pi_coverage: float = 0.0
    s7_ast_coverage: float = 0.0

    def is_healthy(self) -> bool:
        return (self.s3_confidence >= 0.8 and
                self.s5_byzantine_risk <= 0.2 and
                self.s6_pi_coverage < 0.8)

# === 4. 系统配置 ===
class SystemConfig:
    MAX_PATHS = 1000
    TIMEOUT_SECONDS = 30
    PI_CACHE_SIZE = 100
    MAX_LINE_LENGTH = 10000
    NULL_CHECK_WINDOW = 3
    AST_COVERAGE_THRESHOLD = 0.5
    DS_CONFLICT_LOW = 0.5
    DS_CONFLICT_HIGH = 0.75
    BYZANTINE_TOTAL = 11
    BYZANTINE_RISK_THRESHOLD = 0.2

# === 5. PEF三层映射 ===
PEF_OPERATOR_MAP = {
    ("P", "P-INIT"):       "StateBoundedness",
    ("P", "P-PARAM"):      "StateBoundedness",
    ("P", "P-STATE"):      "StateBoundedness",
    ("P", "P-INPUT"):      "TaintPropagation",
    ("P", "P-CONFIG"):     "StateBoundedness",
    ("E", "E-ARITH"):      "StateBoundedness",
    ("E", "E-CONTROL"):    "StateBoundedness",
    ("E", "E-RESOURCE"):   "ResourceBound",
    ("E", "E-CONCURRENCY"): "ResourceBound",
    ("E", "E-TIMING"):     "TimeMonotonicity",
    ("F", "F-ERROR"):      "TimeMonotonicity",
    ("F", "F-LOG"):        "ResourceBound",
    ("F", "F-REPORT"):     "StateBoundedness",
    ("MOD", "MOD-FLOW"):     "TaintPropagation",
    ("MOD", "MOD-LOCK"):     "ResourceBound",
    ("MOD", "MOD-CONTRACT"): "StateBoundedness",
}

# === 6. 公共工具函数 ===
def sha256_hash(data: str) -> str:
    return sha256(data.encode('utf-8')).hexdigest()[:32]

def strip_c_comments(source: str) -> str:
    source = re.sub(r'/\*.*?\*/', '', source, flags=re.DOTALL)
    source = re.sub(r'//.*?$', '', source, flags=re.MULTILINE)
    return source

def strip_string_literals(source: str) -> str:
    return re.sub(r'"[^"]*"', '""', source)

def has_null_check_in_context(lines: List[str], line_num: int, var: str, window: int = 3) -> bool:
    start = max(0, line_num - window)
    end = min(len(lines), line_num + window + 1)
    patterns = [
        rf'if\s*\(\s*!?\s*{re.escape(var)}\s*\)',
        rf'if\s*\(\s*{re.escape(var)}\s*==\s*NULL\s*\)',
        rf'if\s*\(\s*{re.escape(var)}\s*<\s*0\s*\)',
        rf'if\s*\(\s*{re.escape(var)}\s*==\s*-1\s*\)',
        rf'if\s*\(\s*{re.escape(var)}\s*!=\s*NULL\s*\)',
    ]
    for i in range(start, end):
        for p in patterns:
            if re.search(p, lines[i], re.IGNORECASE):
                return True
    return False

# === 7. 模块注册 ===
class ModuleRegistry:
    _modules: Dict[str, Dict[str, Any]] = {}

    @classmethod
    def register(cls, name: str, phase: str, deps: List[str] = None):
        cls._modules[name] = {"phase": phase, "deps": deps or []}

    @classmethod
    def get_dependency_chain(cls, name: str) -> List[str]:
        if name not in cls._modules:
            return []
        chain = []
        for dep in cls._modules[name]["deps"]:
            chain.append(dep)
            chain.extend(cls.get_dependency_chain(dep))
        return [x for x in dict.fromkeys(chain)]

    @classmethod
    def list_modules(cls) -> Dict[str, Dict[str, Any]]:
        return dict(cls._modules)

# 注册所有模块
ModuleRegistry.register("cle_base_layer", "0", [])
ModuleRegistry.register("cle_probe_engine", "1", ["cle_base_layer"])
ModuleRegistry.register("ds_evidence_fusion", "2", ["cle_base_layer"])
ModuleRegistry.register("byzantine_tests", "3", ["cle_base_layer"])
ModuleRegistry.register("taint_propagation", "4", ["cle_base_layer"])
ModuleRegistry.register("integrated_pipeline", "4", ["cle_base_layer", "taint_propagation"])
ModuleRegistry.register("secure_pi_provider", "5", ["cle_base_layer"])
ModuleRegistry.register("pef_operators", "PEF", ["cle_base_layer"])
ModuleRegistry.register("layer2_cross_audit", "L2", ["cle_base_layer", "pef_operators"])
ModuleRegistry.register("layer3_injection_verifier", "L3", ["cle_base_layer"])
ModuleRegistry.register("cle_deploy", "deploy", ["cle_base_layer"])

# === 8. API入口 ===
def get_version() -> str:
    return "CLE V3.8.2"

def get_module_info() -> Dict[str, Any]:
    return {
        "version": "3.8.2",
        "modules": ModuleRegistry.list_modules(),
        "operators": ["TimeMonotonicity", "ResourceBound", "StateBoundedness", "TaintPropagation"],
        "pef_operators": 11,
        "gates": "Gate 0-8",
        "layers": "L1+L2+L3",
    }

__all__ = [
    'NodeAttr', 'Severity', 'Verdict', 'CodeNode', 'AuditEvent', 'AuditContext', 'StateVector',
    'SystemConfig', 'ModuleRegistry', 'PEF_OPERATOR_MAP',
    'sha256_hash', 'strip_c_comments', 'strip_string_literals', 'has_null_check_in_context',
    'get_version', 'get_module_info'
]
