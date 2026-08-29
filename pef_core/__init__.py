#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEF Core — Anchored Determinism Meta-Architecture Kernel
==========================================================
Reference implementation extracted from production deployment.
This package is business-agnostic: all domain-specific field names have
been replaced with generic placeholders. The PEF architecture patterns
(π-anchoring, three-tier ledger, triad P/E/F, MOD3 interrogation) are
preserved intact.

This package does NOT depend on any business module.
"""
from .semantic_error import SemanticError
from .pi_constants import (
    PI_SEQUENCE, PI_DIGITS, PI_TAIL_LIBRARY, get_pi_intensity,
    PEF_E_IN_FIELDS, PEF_E_OUT_FIELDS,
    ENTITY_ID_PREFIXES, FEATURE_KEYWORDS,
)
from .utils import (
    clean_input, string_normalize, is_blank,
    cmp_val, log_operation, TimedLock,
)
from .operator_combination import OperatorCombination
from .evidence_theory import EvidenceTheory
from .pef_shadow_graph import PEFShadowGraph
from .information_entropy import InformationEntropy
from .software_state_vector import SoftwareStateVector
from .pef_self_checklist import PEF_SelfCheckList
from .abstract_auditor import AbstractAuditor
from .pefmod import PEFmod, PiSDispatcher, PEFBindingError
from .state_ledger import (
    PEF_StateLedger, PEFAxiomLedger, PEFRuntimeLedger, PEFAuditLedger,
    RUNTIME_ENTRY_SCHEMA, AUDIT_EVENT_SCHEMA, AXIOM_FACT_SCHEMA,
)
from .pi_tools import (
    detect_header_row_by_pi_density, project_columns_to_pi_grid,
    compute_deviation_rate, register_anchor_verification,
)
from .config_loader import load_framework_config

__all__ = [
    'SemanticError',
    'PI_SEQUENCE', 'PI_DIGITS', 'PI_TAIL_LIBRARY', 'get_pi_intensity',
    'PEF_E_IN_FIELDS', 'PEF_E_OUT_FIELDS',
    'ENTITY_ID_PREFIXES', 'FEATURE_KEYWORDS',
    'clean_input', 'string_normalize', 'is_blank',
    'cmp_val', 'log_operation', 'TimedLock',
    'OperatorCombination', 'EvidenceTheory',
    'PEFShadowGraph', 'InformationEntropy',
    'SoftwareStateVector', 'PEF_SelfCheckList',
    'AbstractAuditor',
    'PEFmod', 'PiSDispatcher', 'PEFBindingError',
    'PEF_StateLedger', 'PEFAxiomLedger', 'PEFRuntimeLedger', 'PEFAuditLedger',
    'RUNTIME_ENTRY_SCHEMA', 'AUDIT_EVENT_SCHEMA', 'AXIOM_FACT_SCHEMA',
    'detect_header_row_by_pi_density', 'project_columns_to_pi_grid',
    'compute_deviation_rate', 'register_anchor_verification',
    'load_framework_config',
]
