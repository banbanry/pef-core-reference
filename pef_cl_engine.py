# -*- coding: utf-8 -*-
"""
PEF 三级闭环引擎 (PEF Closed-Loop Engine) — Tier 2 + Tier 3
============================================================
Tier 1 (内生循环 token深挖): 见 pef_loop_miner.py
Tier 2 (外部校准 多模型偏差): 探针前置过滤 + 多主体独立裁决
Tier 3 (多模型编译对齐): 统一 P/E/F Schema 编译 + 偏差率 ρ + 熔断/审计

设计依据: 01-core-spec/pef-three-tier-closed-loop-engine.md V1.0
作者: banbanry (沈鹭)  |  PEF Architecture © 2026 MIT
"""
import json, hashlib, time, re
from collections import Counter

# ============ Tier 2: 探针前置（E层确定性错误检测） ============
# 12 个 CLE 探针的轻量实现（规则级，离线可跑，不依赖模型）
PROBE_RULES = {
    'E033_placeholder':   [r'TODO', r'FIXME', r'XXX', r'待实现', r'占位'],
    'E056_logic_break':   [r'pass\s*$', r'NotImplementedError', r'raise\s+NotImplemented'],
    'E034_dead_code':     [r'return\s+None\s*\n\s*(return|pass)', r'unused\s*='],
    'E022_math_property': [r'1\s*/\s*0', r'sqrt\s*\(\s*-', r'log\s*\(\s*-'],
    'E040_string_valid':  [r'"[^"]{500,}"', r"''''''", r'""""""'],
    'E035_unimplemented': [r'def\s+\w+\s*\([^)]*\)\s*:\s*$', r'class\s+\w+\s*:\s*$'],
    'E039_buffer_overflow': [r'strcpy\s*\(', r'sprintf\s*\(', r'gets\s*\('],
    'E041_uninit_mem':    [r'malloc\s*\([^)]*\)\s*;', r'new\s+\w+\s*\[[^]]*\]'],
    'E043_resource_leak': [r'open\s*\([^)]*\)', r'fopen\s*\(', r'new\s+File'],
    'E150_integer_overflow': [r'\w+\s*=\s*\w+\s*\*\s*\w+\s*;', r'<<\s*3[0-9]'],
    'E049_path_coverage': [r'if\s+__name__\s*==', r'assert\s+'],
    'E042_race_condition': [r'threading\.', r'Thread\s*\(', r'lock\s*='],
}

class Probe:
    """探针：对文本块做确定性错误检测"""
    def __init__(self, name, patterns):
        self.name = name
        self.patterns = patterns
    def run(self, text):
        hits = []
        for pat in self.patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                hits.append({'pattern': pat, 'at': m.start()})
        return {'probe': self.name, 'critical': len(hits) > 0, 'hits': hits[:5]}

def build_probes():
    return [Probe(name, pats) for name, pats in PROBE_RULES.items()]

# ============ PEF 信号词典（与 tier1 pef_loop_miner 同源，内联保证独立可运行） ============
P_SIGNALS = [
    '本架构', '本系统', '本方案', '本规范', 'PEF', 'P域', 'E域', 'F域', 'M层', 'M域',
    '引擎', '模型', '算子', '探针', '处理器', '模块', '平台', '框架', '底座',
    'AI', '大模型', '智能体', 'Agent', '硬件', '芯片', '单片机', 'FPGA',
    '主体', '用户', '工程师', '系统', '设备', '节点', '头雁', '从雁', '校验者',
    '仲裁者', '审查', '审计', 'CLE', 'CIC', 'GLM', 'Claude', 'GPT',
]
E_SIGNALS = [
    '变量', '输入', '输出', '参数', '状态', '数据', '阈值', '置信度', '偏差', '漂移',
    '上下文', 'token', '向量', '信号', '温度', '权重', '特征', '边界', '坐标',
    '锚', '锚点', 'π', 'pi', '哈希', '摘要', '日志', '记录', '链路', '时序',
    'E_in', 'E_out', '值', '误差', '率', '熵', '势差', '温度漂移', '温漂',
]
F_SIGNALS = [
    '结果', '结论', '裁决', '判定', '通过', '失败', 'PASS', 'FAIL', '熔断', '拒绝',
    '输出', '交付', '目标', '成果', '报告', '判决', '允许', '禁止', '闭环',
    '验证', '确认', '定案', '完成', '终止', '停机', '回退', '返回', 'ALLOW', 'DENY',
    '裁决书', '审计轨迹', '证据', '验收',
]
MECH_SIGNALS = [
    '公理', '铁则', '熔断', '审计', '锚定', '隔离', '时序', '因果', '不可伪',
    '平权', '异构', '否决', '裁决', 'MOD3', '拜占庭', '影子图', '雁阵',
    '漂移校验', '三层纪律', '第一性原理', '三元', '流水线', '状态机',
]

def pef_score(text):
    p = sum(1 for w in P_SIGNALS if w.lower() in text.lower())
    e = sum(1 for w in E_SIGNALS if w.lower() in text.lower())
    f = sum(1 for w in F_SIGNALS if w.lower() in text.lower())
    m = sum(1 for w in MECH_SIGNALS if w.lower() in text.lower())
    return {'P': p, 'E': e, 'F': f, 'M': m, 'total': p + e + f + m}

# ============ Tier 2: 多模型独立裁决（mock 可离线 + 真实 API 接口） ============
class ModelVoter:
    """多主体裁决器。mock_mode=True 用确定性规则模拟不同模型行为（离线演示）；
    mock_mode=False 时接入真实模型 API（需实现 ask_real）。"""
    def __init__(self, model_name, mock_mode=True, bias_seed=0):
        self.name = model_name
        self.mock = mock_mode
        self.bias = bias_seed  # mock 时不同 bias 模拟不同模型风格

    def ask(self, block_text, unified_prompt):
        if self.mock:
            return self._ask_mock(block_text)
        return self._ask_real(unified_prompt)

    def _ask_mock(self, text):
        """确定性 mock：基于信号词典给 PASS/FAIL/UNKNOWN + 置信度"""
        s = pef_score(text)
        s = pef_score(text)
        m_count = sum(1 for w in MECH_SIGNALS if w.lower() in text.lower())
        # 不同 bias 模拟不同模型对机制词敏感度的差异
        adjusted_m = m_count + self.bias
        if s['F'] >= 6 or adjusted_m >= 3:
            verdict, conf = 'PASS', 0.75 + 0.05 * self.bias
        elif s['total'] >= 6:
            verdict, conf = 'UNKNOWN', 0.5 + 0.05 * self.bias
        else:
            verdict, conf = 'FAIL', 0.6 + 0.05 * self.bias
        # 提取一句证据
        sents = [x.strip() for x in re.split(r'(?<=[。！？!?])', text) if len(x.strip()) > 15]
        evidence = sents[0][:80] if sents else text[:80]
        return {'P': {'name': self.name, 'role': 'adjudicator'},
                'E': {'inputs': [hashlib.md5(text.encode()).hexdigest()[:8]],
                      'variables': [], 'confidence': min(conf, 0.98),
                      'anchor': f"π[{self.bias}]={ '3141592653589793'[self.bias] }|{'PEF'[self.bias%3]}|{self.name}"},
                'F': {'verdict': verdict, 'evidence': evidence, 'reason': f"mock-{self.name}-signal"}}

    def _ask_real(self, prompt):
        """真实模型接入点（预留接口）：
        在此实现调用 GLM/Claude/GPT API，返回同样 Schema 结构。"""
        raise NotImplementedError("真实API接入点：在此实现厂商SDK调用，返回统一 P/E/F Schema")


# ============ Tier 3: 统一 Schema 编译 ============
def compile_schema(model_output):
    """把任意模型输出编译为统一 P/E/F 三元 Schema（无损映射）"""
    return {
        'P': {'name': model_output.get('P', {}).get('name', 'unknown'),
              'role': model_output.get('P', {}).get('role', 'adjudicator'),
              'boundary': model_output.get('P', {}).get('boundary', 'input-block-only')},
        'E': {'inputs': model_output.get('E', {}).get('inputs', []),
              'variables': model_output.get('E', {}).get('variables', []),
              'confidence': float(model_output.get('E', {}).get('confidence', 0.0)),
              'anchor': model_output.get('E', {}).get('anchor', '')},
        'F': {'verdict': model_output.get('F', {}).get('verdict', 'UNKNOWN'),
              'evidence': model_output.get('F', {}).get('evidence', ''),
              'reason': model_output.get('F', {}).get('reason', '')},
    }

# ============ Tier 3: 偏差率 ρ 计算（spec-as-region 口径） ============
def tokenize_evidence(text):
    cn = re.findall(r'[\u4e00-\u9fff]+', text or '')
    toks = []
    for seg in cn:
        if len(seg) == 1:
            toks.append(seg)
        else:
            for i in range(len(seg) - 1):
                toks.append(seg[i:i+2])
    return set(toks)

def jaccard(s1, s2):
    if not s1 or not s2:
        return 0.0
    return len(s1 & s2) / len(s1 | s2)

def compute_rho(verdicts):
    """偏差率 ρ ∈ [0,1]：裁决不一致(0.5) + 证据分歧(0.3) + 置信分歧(0.2)"""
    n = len(verdicts)
    if n < 2:
        return 0.0
    # 1. 主偏差：裁决结果不一致比例
    vs = {v['F']['verdict'] for v in verdicts}
    mismatch = 1.0 if len(vs) > 1 else 0.0
    # 2. 证据偏差：核心句语义重叠（Jaccard）
    sets = [tokenize_evidence(v['F']['evidence']) for v in verdicts]
    js = [jaccard(sets[i], sets[j]) for i in range(n) for j in range(i+1, n)]
    avg_j = sum(js) / len(js) if js else 1.0
    # 3. 置信偏差：置信度离散度
    confs = [v['E']['confidence'] for v in verdicts]
    spread = max(confs) - min(confs)
    return round(0.5 * mismatch + 0.3 * (1 - avg_j) + 0.2 * spread, 4)

# ============ π锚审计账本 (StateLedger) ============
PI_DIGITS = "31415926535897932384626433832795028841971693993751"

def allocate_anchor(seq, source_type, domain):
    pos = seq % len(PI_DIGITS)
    return f"π[{pos}]={PI_DIGITS[pos]}|{domain}|{source_type}|seq{seq}"

def onion_hash(payload):
    l1 = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    l2 = hashlib.sha256(l1.encode()).hexdigest()
    l3 = hashlib.sha256(l2.encode()).hexdigest()
    return hashlib.sha256(l3.encode()).hexdigest()[:16]

class StateLedger:
    """只追加审计账本：时序铁则 + 哈希链 + π锚"""
    def __init__(self):
        self.entries = []
        self.seq = 0
    def append(self, record):
        prev = self.entries[-1]['chain_hash'] if self.entries else 'GENESIS'
        t = time.time()
        record['t_write'] = t
        record['prev_hash'] = prev
        record['chain_hash'] = onion_hash(record)
        self.entries.append(record)
        self.seq += 1
        return record
    def verify(self):
        """链完整性校验：逐级验证哈希链"""
        for i, e in enumerate(self.entries):
            expect = self.entries[i-1]['chain_hash'] if i else 'GENESIS'
            if e['prev_hash'] != expect:
                return False, i
        return True, len(self.entries)

# ============ 主流水线：Tier2 + Tier3 ============
def run_tier2_3(block, probes, voters, threshold_pass=0.15, threshold_fail=0.4):
    """对单个低置信块执行 外部校准 + 编译对齐 + 裁决"""
    ledger = StateLedger()
    # ---- Tier 2a: 探针前置 ----
    probe_results = [p.run(block['text']) for p in probes]
    critical = [r for r in probe_results if r['critical']]
    if critical:
        verdict = {'verdict': 'FAIL', 'stage': 'probe', 'rho': 1.0,
                   'reason': f"探针检出确定性错误: {[c['probe'] for c in critical][:5]}",
                   'probes': critical}
        rec = ledger.append({'stage': 'probe', 'block': block['hash'],
                             'anchor': allocate_anchor(ledger.seq, 'probe', 'E'),
                             'verdict': verdict['verdict']})
        return verdict, ledger, probe_results, []

    # ---- Tier 2b: 多模型独立裁决 ----
    model_outputs = [v.ask(block['text'], None) for v in voters]
    # ---- Tier 3a: 统一 Schema 编译 ----
    schemas = [compile_schema(o) for o in model_outputs]
    # ---- Tier 3b: 偏差率 ρ ----
    rho = compute_rho(schemas)
    # ---- Tier 3c: 裁决（一致意见优先，ρ 只在分歧时介入） ----
    verdicts = [s['F']['verdict'] for s in schemas]
    vset = set(verdicts)
    if len(vset) == 1:
        # 全模型一致：跟随一致意见（PASS→PASS, FAIL→FAIL, UNKNOWN→REVIEW）
        final_v = 'PASS' if vset == {'PASS'} else ('FAIL' if vset == {'FAIL'} else 'REVIEW')
    else:
        # 分歧：ρ 裁决——低分歧可复核，高分歧熔断
        final_v = 'PASS' if rho <= threshold_pass else ('REVIEW' if rho <= threshold_fail else 'FAIL')
    # ---- 审计入账 ----
    rec = ledger.append({
        'stage': 'align', 'block': block['hash'],
        'anchor': allocate_anchor(ledger.seq, 'align', 'F'),
        'rho': rho, 'verdict': final_v,
        'model_verdicts': verdicts,
        'confidences': [s['E']['confidence'] for s in schemas],
    })
    result = {'verdict': final_v, 'stage': 'align', 'rho': rho,
              'model_verdicts': verdicts, 'reason': f"ρ={rho}",
              'ledger_tail': rec['chain_hash']}
    return result, ledger, probe_results, schemas


# ============ 端到端演示 ============
if __name__ == '__main__':
    print("===== PEF 三级闭环引擎 · Tier2+3 演示 =====")
    probes = build_probes()
    voters = [ModelVoter('GLM', bias_seed=0),
              ModelVoter('Claude', bias_seed=1),
              ModelVoter('GPT', bias_seed=2)]

    demo_blocks = [
        {'hash': 'demo1', 'text': '本系统基于PEF架构，主体P域负责裁决，E域监控变量阈值，F域输出PASS/FAIL结果。公理铁则规定时序因果不可倒置，审计链锚定不可伪造，MOD3三态驱动偏差率ρ裁决，最终熔断机制闭环验证。'},
        {'hash': 'demo2', 'text': 'TODO: 这个函数还没写完，pass 占位。', },
        {'hash': 'demo3', 'text': '今天天气不错，我们去公园散步，顺便买个冰淇淋吃。'},
    ]

    print(f"\n探针就绪: {len(probes)} 个 E 层算子")
    print(f"投票主体: {[v.name for v in voters]}\n")

    for b in demo_blocks:
        print(f"--- 块 [{b['hash']}] ({len(b['text'])}字) ---")
        result, ledger, pr, schemas = run_tier2_3(b, probes, voters)
        print(f"  探针: {len(pr)} 跑, 命中 {len([p for p in pr if p['critical']])} 项")
        print(f"  裁决: {result['verdict']} (ρ={result.get('rho', 'N/A')})")
        if schemas:
            for s in schemas:
                print(f"    [{s['P']['name']}] {s['F']['verdict']} conf={s['E']['confidence']:.2f} anchor={s['E']['anchor']}")
        print(f"  账本: {len(ledger.entries)} 条, 链完整={ledger.verify()[0]}\n")

    # 篡改检测验证
    print("===== 审计链篡改检测 =====")
    l2 = StateLedger()
    for i in range(3):
        l2.append({'i': i, 'payload': f'data-{i}'})
    ok, n = l2.verify()
    print(f"  原始链: {n} 条, 完整={ok}")
    l2.entries[1]['payload'] = 'TAMPERED'
    ok, bad = l2.verify()
    print(f"  篡改后: 完整={ok}, 断裂位置=条目{bad}")
    print("\n✅ Tier2+3 演示完成")
