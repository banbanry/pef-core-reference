# -*- coding: utf-8 -*-
"""
PEF 三级闭环引擎 — 端到端串联
================================
Tier1 (内生循环): pef_loop_miner.py — 已跑通，读取已有中间结果
Tier2 (外部校准): pef_cl_engine.py — 探针前置 + 多模型裁决
Tier3 (编译对齐): pef_cl_engine.py — 统一Schema + ρ + 熔断

本脚本串联三级：从 pef_loop_summary.json 取低置信(A级)文档的S块，
升级到 Tier2+3 做外部校准，输出完整流水线日志 + 审计账本。
"""
import json, sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pef_cl_engine import (build_probes, ModelVoter, run_tier2_3,
                           StateLedger, compute_rho, compile_schema,
                           allocate_anchor, onion_hash)

def load_tier1_results():
    """读取 tier1 中间结果（内生循环定案）"""
    base = r'D:\WorkBuddy'
    with open(os.path.join(base, 'pef_loop_summary.json'), encoding='utf-8') as f:
        summary = json.load(f)
    with open(os.path.join(base, 'pef_loop_pass1.json'), encoding='utf-8') as f:
        blocks = json.load(f)
    return summary, blocks

def main():
    print("=" * 66)
    print("PEF 三级闭环引擎 · 端到端串联（真实数据）")
    print("=" * 66)

    # ---- Tier1: 加载内生循环结果 ----
    summary, blocks = load_tier1_results()
    print(f"\n[Tier1 内生循环] 文档级定案: {len(summary)} 份")
    lv = {}
    for s in summary.values():
        lv[s['level']] = lv.get(s['level'], 0) + 1
    print(f"  定案分布: {lv}")

    # ---- 选低置信文档（A级）的S块升级校准 ----
    low_conf_docs = [d for d, s in summary.items() if s['level'] == 'A']
    print(f"\n[Tier2 外部校准] 低置信文档(A级): {len(low_conf_docs)} 份 → 升级")
    for d in low_conf_docs[:5]:
        print(f"    - {d[:60]}")

    # 取这些文档中最强的块做校准演示（A级文档无S块，取A级最强块）
    upgrade_blocks = []
    for d in low_conf_docs:
        doc_blocks = [b for b in blocks if b['doc'] == d and b['level'] in ('S', 'A')]
        if doc_blocks:
            strongest = max(doc_blocks, key=lambda b: b['scores']['total'])
            upgrade_blocks.append(strongest)
    print(f"  升级S块数: {len(upgrade_blocks)}")

    if not upgrade_blocks:
        print("  无升级块，取全局最强S块演示")
        upgrade_blocks = [max((b for b in blocks if b['level'] == 'S'),
                              key=lambda b: b['scores']['total'])]

    # ---- Tier2+3: 对升级块执行校准 ----
    print(f"\n[Tier2+3 校准+对齐] 对 {len(upgrade_blocks)} 个低置信块执行")
    probes = build_probes()
    voters = [ModelVoter('GLM', bias_seed=0),
              ModelVoter('Claude', bias_seed=1),
              ModelVoter('GPT', bias_seed=2)]

    global_ledger = StateLedger()
    results = []
    for i, b in enumerate(upgrade_blocks[:8]):
        r, ledger, pr, schemas = run_tier2_3(b, probes, voters)
        # 并入全局账本
        for e in ledger.entries:
            global_ledger.append(e)
        results.append({'block': b['hash'], 'doc': b['doc'][:40],
                        'verdict': r['verdict'], 'rho': r.get('rho', 'N/A'),
                        'reason': r['reason']})
        print(f"  [{i+1}] {b['doc'][:38]:<38} → {r['verdict']:<6} ρ={r.get('rho','—')}")

    # ---- 对照：S级（高置信）文档的块，期望 PASS 居多 ----
    print(f"\n[对照] S级(高置信)文档最强块 — 期望多为 PASS")
    high_conf_docs = [d for d, s in summary.items() if s['level'] == 'S'][:8]
    control_blocks = []
    for d in high_conf_docs:
        doc_blocks = [b for b in blocks if b['doc'] == d and b['level'] == 'S']
        if doc_blocks:
            control_blocks.append(max(doc_blocks, key=lambda b: b['scores']['total']))

    control_results = []
    for i, b in enumerate(control_blocks):
        r, ledger, pr, schemas = run_tier2_3(b, probes, voters)
        for e in ledger.entries:
            global_ledger.append(e)
        control_results.append({'block': b['hash'], 'doc': b['doc'][:40],
                                'verdict': r['verdict'], 'rho': r.get('rho', 'N/A')})
        print(f"  [{i+1}] {b['doc'][:38]:<38} → {r['verdict']:<6} ρ={r.get('rho','—')}")

    # ---- 汇总 ----
    print(f"\n[Tier3 编译对齐] 汇总")
    verdict_counts = {}
    for r in results + control_results:
        verdict_counts[r['verdict']] = verdict_counts.get(r['verdict'], 0) + 1
    print(f"  裁决分布: {verdict_counts}")
    print(f"  审计账本: {len(global_ledger.entries)} 条, 链完整={global_ledger.verify()[0]}")

    # 保存端到端结果
    out = {
        'tier1': {'docs': len(summary), 'levels': lv},
        'tier2_3': {'upgraded_blocks': len(upgrade_blocks),
                    'probes': len(probes), 'voters': [v.name for v in voters]},
        'low_conf_results': results,
        'control_results': control_results,
        'ledger': global_ledger.entries,
        'ledger_verified': global_ledger.verify()[0],
    }
    with open(r'D:\WorkBuddy\pef_cl_e2e_result.json', 'w', encoding='utf-8') as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(f"\n✅ 端到端串联完成 → D:\\WorkBuddy\\pef_cl_e2e_result.json")

if __name__ == '__main__':
    main()
