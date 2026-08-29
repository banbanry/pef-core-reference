#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEF Core — Minimal Demonstration
==================================
Demonstrates the core PEF architecture patterns in ~50 lines:
  1. π-anchor allocation (PiSDispatcher) — unforgeable, irreversible, unique
  2. PEFmod creation — read-only state snapshot with domain tag (P/E/F)
  3. Three-tier ledger recording — axiom / runtime / audit
  4. Self-check — verifies anchor validity, domain consistency, temporal ordering

Run:  python demo_minimal.py
"""
import sys
import os

# Ensure the package is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pef_core import (
    PiSDispatcher, PEFmod, PEF_StateLedger, PEFBindingError,
)


def main():
    print("=" * 64)
    print("PEF Core — Minimal Demonstration")
    print("=" * 64)

    # ---- 1. Create a PEFmod first (t_state) ----
    # Temporal causality (A4): the state snapshot must exist BEFORE the anchor
    # is allocated. t_state ≤ t_anchor ≤ t_write.
    # The first anchor counter=1 → 1%3=1 → domain E (precomputable from π sequence).
    features = [0.95, 0.87, 0.92, 0.78, 0.88]
    mod = PEFmod(features=features, domain_tag='E')
    print(f"\n[1] PEFmod created: domain={mod.domain_tag}, "
          f"state_hash={mod.state_hash[:16]}…")
    print(f"    features={list(mod.features)}")
    print(f"    t_state={mod.created_at[:23]}")
    print(f"    Bound? {mod.is_bound} (will bind during ledger.record)")

    # ---- 2. Allocate a π-anchor (t_anchor) ----
    # The anchor is unforgeable: its domain (P/E/F) is determined by counter%3,
    # not by the caller. Consumed anchors cannot be returned or reused.
    pi_s, domain = PiSDispatcher.allocate()
    print(f"\n[2] π-anchor allocated: Πₛ={pi_s}, domain={domain} (counter%3={pi_s % 3})")
    print(f"    t_anchor={PiSDispatcher.get_alloc_time(pi_s)[:23]}")
    print(f"    Active anchors: {PiSDispatcher.active_count()}")

    # ---- 3. Record into the three-tier ledger ----
    # The ledger enforces:
    #   - L1: π-anchor validity (no reference to future state)
    #   - Triple consistency: domain_tag == π%3 mapped domain
    #   - One-to-one binding: no sharing, no mutation
    #   - Temporal ordering: state_update ≤ anchor_generation ≤ write_time
    ledger = PEF_StateLedger()
    confirm = ledger.record(mod, pi_s, metadata={"demo": "minimal"})
    print(f"\n[3] Ledger record confirmed: status={confirm['status']}")
    print(f"    seq={confirm['seq']}, t_state={confirm['t_state'][:23]}")
    print(f"    t_anchor={confirm['t_anchor'][:23]}, t_write={confirm['t_write'][:23]}")
    print(f"    Runtime entries: {ledger.runtime.count()}")
    print(f"    Audit events:    {ledger.audit.count()}")

    # ---- 4. Self-check ----
    # Verifies all records carry valid anchors, one-to-one binding holds,
    # temporal ordering is consistent, and audit hashes are intact.
    report = ledger.self_check()
    print(f"\n[4] Self-check: {'PASS' if report['passed'] else 'FAIL'}")
    for item in report['items']:
        status = 'PASS' if item['passed'] else 'FAIL'
        print(f"    [{status}] {item['name']}: {item['detail'][:60]}")
    print(f"    Violations: {len(report['violations'])}")

    # ---- 5. Demonstrate circuit breaker ----
    # Attempting to bind the same anchor twice triggers P0 circuit breaker.
    print(f"\n[5] Circuit breaker demo: attempting duplicate bind…")
    try:
        mod2 = PEFmod(features=[1.0, 2.0], domain_tag=domain)
        ledger.record(mod2, pi_s)  # same anchor → should fail
        print("    ERROR: should have raised PEFBindingError!")
    except PEFBindingError as e:
        print(f"    P0熔断 triggered as expected: {str(e)[:70]}")

    # ---- 6. Archive ----
    ledger.archive(pi_s)
    print(f"\n[6] Anchor archived: active={PiSDispatcher.active_count()}, "
          f"archived={PiSDispatcher.archived_count()}")
    print("    Archived anchors can never be reused (iron law 7).")

    print("\n" + "=" * 64)
    print("Demo complete. The anchor is unforgeable, irreversible, and unique.")
    print("Every state record is traceable to (P, E, t) on the anchor coordinate.")
    print("=" * 64)


if __name__ == "__main__":
    main()
