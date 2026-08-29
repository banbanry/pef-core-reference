#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
π constants and PEF metadata — PEF kernel base constants
==========================================================
Contains π sequence, field classification sets, entity ID prefixes,
feature keywords, and other immutable constants.

NOTE: This is the desensitized reference version. All domain-specific
field names have been replaced with generic placeholders. Replace them
with your own schema when integrating into a specific domain.
"""
import os
# π sequence (A1 axiom: includes leading 3, indexing scheme A)
PI_SEQUENCE = [3, 1, 4, 1, 5, 9, 2, 6, 5, 3, 5, 8, 9, 7, 9, 3, 2, 3, 8, 4]

# ============================================================================
# PI_DIGITS split into two independent constants
# ============================================================================
# Π₀ baseline ruler constant — used only for system initialization self-check.
# Strong isolation constraints:
#   - No slicing/hashing/modulo/runtime numerical operations
#   - No writing into any PEF_StateLedger layer
#   - No binding with PEFmod or Πₛ
#   - Not participating in any runtime indexing, operation, slicing, hashing, MOD
# 1000 digits of π (including leading 3), total 1000 characters.
PI0_BASELINE = (
    '31415926535897932384626433832795028841971693993751'
    '05820974944592307816406286208998628034825342117067'
    '98214808651328230664709384460955058223172535940812'
    '84811174502841027019385211055596446229489549303819'
    '64428810975665933446128475648233786783165271201909'
    '14564856692346034861045432664821339360726024914127'
    '37245870066063155881748815209209628292540917153643'
    '67892590360011330530548820466521384146951941511609'
    '43305727036575959195309218611738193261179310511854'
    '80744623799627495673518857527248912279381830119491'
    '29833673362440656643086021394946395224737190702179'
    '86094370277053921717629317675238467481846766940513'
    '20005681271452635608277857713427577896091736371787'
    '21468440901224953430146549585371050792279689258923'
    '54201995611212902196086403441815981362977477130996'
    '05187072113499999983729780499510597317328160963185'
    '95024459455346908302642522308253344685035261931188'
    '17101000313783875288658753320838142061717766914730'
    '35982534904287554687311595628638823537875937519577'
    '81857780532171226806613001927876611195909216420198'
)

# π static library integrity fingerprint (4th axiom: hash mismatch /
# insufficient length → P0, no dynamic generation)
# PI_TABLE_SHA256: SHA-256 of pure digit string extracted from pi_table_10000.txt
PI_TABLE_SHA256 = '7406a2be66766f832c8d1e1b66491ef7b2f366b0393d21c4684181044b507ab5'
# PI0_BASELINE_SHA256: fingerprint of Π₀ baseline (1000 digits incl. leading 3),
# for initialization self-check comparison only, not in runtime chain
PI0_BASELINE_SHA256 = '2f77ba99f311974f0d188c0b19710260c11c70d6f4d96d78570d4a59c3b0dbe0'

# Πₛ π mantissa static library — for runtime lookup, length controlled by
# pi_digits_length in framework_config.json.
# Runtime code performs slicing/indexing/modulo through this constant.
_PI_TABLE_FILE = os.path.join(os.path.dirname(__file__), 'pi_table_10000.txt')
_PI_TAIL_LIBRARY_LENGTH = 2000  # default, overridden by framework_config.json

try:
    from .config_loader import load_framework_config
    _cfg = load_framework_config()
    _plen = _cfg.get('pef', {}).get('pi_digits_length', _PI_TAIL_LIBRARY_LENGTH)
    if isinstance(_plen, int) and _plen > 0:
        _PI_TAIL_LIBRARY_LENGTH = _plen
except Exception:
    pass  # use default when config load fails

if os.path.exists(_PI_TABLE_FILE):
    import hashlib as _hashlib
    with open(_PI_TABLE_FILE, 'r', encoding='utf-8') as _f:
        _raw = _f.read().strip()
    _digits = ''.join(ch for ch in _raw if ch.isdigit())
    # Integrity gate: insufficient length / hash mismatch → P0 termination,
    # no wraparound, no dynamic generation
    if len(_digits) < _PI_TAIL_LIBRARY_LENGTH:
        raise RuntimeError(
            f'P0: π mantissa static library insufficient length: '
            f'need ≥{_PI_TAIL_LIBRARY_LENGTH}, actual {len(_digits)} '
            f'(no dynamic generation, chain terminated)')
    _actual_sha = _hashlib.sha256(_digits.encode('ascii')).hexdigest()
    if _actual_sha != PI_TABLE_SHA256:
        raise RuntimeError(
            f'P0: π mantissa static library hash mismatch: '
            f'expected {PI_TABLE_SHA256[:16]}…, actual {_actual_sha[:16]}… '
            f'(suspected tampering/corruption, chain terminated)')
    # leading 3 (integer part) + specified length of fractional part
    _tail = '3' + _digits[:_PI_TAIL_LIBRARY_LENGTH]
    PI_TAIL_LIBRARY = _tail
else:
    # Fallback: use PI0_BASELINE (1000 digits)
    PI_TAIL_LIBRARY = PI0_BASELINE

# Legacy name (deprecated, for transition only; new code must not use)
PI_DIGITS = PI_TAIL_LIBRARY


def get_pi_intensity(step: int) -> int:
    """π sequence intensity: %3 result 0/1/2 distribution.
    Returns: 0=steady advance, 1=standard check, 2=deep review"""
    raw = PI_SEQUENCE[step % len(PI_SEQUENCE)] % 3
    return raw


# ============================================================================
# Generic field classification (desensitized — replace with domain schema)
# ============================================================================

# Entity ID prefixes (generic examples)
ENTITY_ID_PREFIXES = {
    'ENT', 'REF', 'DOC', 'BATCH', 'SYS', 'EXT', 'PROC', 'AUD', 'LOG',
}

# Feature keywords (generic examples)
FEATURE_KEYWORDS = {
    'type', 'category', 'status', 'priority', 'source', 'target',
    'amount', 'quantity', 'unit', 'code', 'label', 'flag',
    'timestamp', 'location', 'owner', 'version',
}

# PEF internal variables (E_in): standard fields populated by business layer
# (generic field names — replace with domain-specific schema)
PEF_E_IN_FIELDS = {
    'entity_id', 'item_no', 'section', 'project_id', 'order_no',
    'part_code', 'serial_no', 'description', 'quantity', 'unit',
    'category', 'mode', 'owner', 'transport_type', 'created_at',
    'pickup_date', 'delivery_date', 'ref_no', 'record_no',
    'remarks', 'gross_weight', 'net_weight', 'tracking_no',
    'echo_no', 'dimensions', 'box_no',
}

# PEF external variables (E_out): system-internal marker fields
PEF_E_OUT_FIELDS = {
    '__data_type__', '__seq_no__', '__batch_id__', '__file_name__',
    '__timestamp__', '__sys_time__', '__seq_label__', '__red_mark__',
    '__src__', '__doc_type__', '__order_no__', '__inherit_info__',
    '__extra__', 'anomaly_type', 'anomaly_desc',
}
