#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pef-prompt-optimizer · 提示词锚定优化器
========================================
理论来源: 《开放案提示词工程系统》(面向终端/本地化/APP大模型场景强逻辑注意力锚定与长文本防漂移方案)

核心机制 (文档第七章-第十四章):
  1) 强逻辑作为注意力锚点: 锚点密度决定防漂移效果 (7.2/7.3)
  2) 结构化输出作为注意力检查点: 字段顺序/字段标记聚焦注意力 (8.1-8.3)
  3) 检查点回溯与滑动窗口: 长文本防 Lost-in-the-Middle (9.1-9.3)
  4) 场景判定决策树: 终端/本地化/在线 三场景 (10.3)
  5) 强逻辑降级方案: 终端精简、量化模型适配 (11/12)
  6) 混合架构: LLM + 确定性脚本协作 (13)

功能:
  - 场景自动判定 (决策树) 或用户指定
  - 锚点密度诊断 (强逻辑锚点词命中/千字)
  - 结构化输出检查 (编号列表/字段标记/表格)
  - 检查点与滑动窗口建议 (长文本)
  - 按场景输出超参推荐 (temperature/top_p/max_tokens)
  - 降级方案建议 (终端/量化/混合架构)

用法:
  python pef_prompt_optimizer.py <提示词文件或文本> [--scenario terminal|local|online] [--verbose] [--json]
零第三方依赖 (stdlib only) · 确定性执行
"""
# 指纹水印
# © 2026 沈鹭 (banbanry) · 厦门恒元架构科技有限公司 · MIT License
# Github: https://github.com/banbanry (pef-architecture / pef-core-reference)

import argparse, json, re, sys, time

# ---- 强逻辑锚点词库 (文档 7.2 注意力锚点: 约束性/条件性/强制性表达) ----
ANCHOR_WORDS = [
    "必须", "禁止", "不得", "仅允许", "只能", "强制", "固定", "严格",
    "如果", "否则", "条件", "当且仅当", "边界", "约束", "限制", "一律",
    "无论", "除非", "保证", "至少", "至多", "要求", "规定", "明确",
    "首先", "其次", "最后", "步骤", "编号", "顺序", "按照",
    "IF", "THEN", "ELSE", "WHEN", "UNLESS", "MUST", "SHALL", "MUST NOT",
    "FOREACH", "FOR EACH", "ONLY", "ALWAYS", "NEVER",
]

# ---- 结构化输出标记 ----
STRUCT_MARKERS = [
    (r"^\s*\d+[\.\)、]\s+", "编号列表 (1. 2. 3.)"),
    (r"^\s*[①②③④⑤⑥⑦⑧⑨⑩]\s*", "中文圈号列表 (①②③)"),
    (r"^\s*[-*•]\s+", "项目符号列表 (-/*/•)"),
    (r"[A-Za-z_\u4e00-\u9fff]{2,16}\s*[:：]\s*\S+", "字段标记 (名称: 值)"),
    (r"^\s*\|.*\|", "表格行 (| ... |)"),
    (r"\*\*[^*]+\*\*", "粗体强调 (**...**)"),
]

# ---- 场景判定关键词 (文档 10.3 场景判定决策树) ----
SCENE_KEYWORDS = {
    "terminal": ["终端", "APP", "移动端", "手机", "离线", "端侧", "嵌入式", "本地推理", "量化", "内存受限", "低延迟"],
    "local": ["本地化", "私有化", "内网", "部署", "本地部署", "GPU服务器", "自建", "局域网", "数据不出域"],
    "online": ["在线", "云端", "API", "联网", "SaaS", "远程", "公网", "云服务"],
}

# ---- 超参推荐 (文档 11.3/12.3: 场景专属超参数配置) ----
HYPERPARAMS = {
    "terminal": {"temperature": 0.1, "top_p": 0.2, "max_tokens": 2048,
                 "note": "量化模型建议 temperature<=0.1 防抖动; max_tokens 受内存约束"},
    "local": {"temperature": 0.2, "top_p": 0.5, "max_tokens": 4096,
              "note": "本地 GPU 可略放宽; 建议开启 KV Cache 优化"},
    "online": {"temperature": 0.0, "top_p": 0.1, "max_tokens": 8192,
               "note": "在线服务推荐 temperature=0.0 确定性输出; 长文本用滑动窗口"},
}

# ---- 降级建议 (文档 11.2/12.3/13) ----
DEGRADE_NOTES = {
    "terminal": [
        "提示词精简: 锚点词保留必须/禁止级, 删除解释性文字 (11.1)",
        "强逻辑降级: 结构化输出模板压缩为单层编号 (11.2)",
        "混合架构: LLM 只做分类/抽取, 计算交确定性脚本 (13)",
        "离线推理: 检查点回溯改为本地缓存, 滑动窗口长度减半",
    ],
    "local": [
        "量化适配: INT4/INT8 下温度阈值收紧, 减少采样随机性 (12.3)",
        "KV Cache 优化: 长上下文开启 prefix caching (14)",
        "混合架构: 校验类任务交确定性脚本, LLM 专注语义 (13)",
    ],
    "online": [
        "在线服务: temperature=0.0 + 结构化输出模板锁定格式",
        "长文本: 滑动窗口摘要 + 关键信息重复锚定 (9.3/9.4)",
        "降级路径: API 超时 → 重试退避 → 缓存回退",
    ],
}


def detect_scenario(text):
    """场景判定决策树 (文档 10.3): 关键词命中加权."""
    scores = {s: 0 for s in SCENE_KEYWORDS}
    for scene, kws in SCENE_KEYWORDS.items():
        for kw in kws:
            if kw in text:
                scores[scene] += 1
    best = max(scores, key=lambda s: scores[s])
    if scores[best] == 0:
        return "online", scores  # 默认在线
    return best, scores


def anchor_density(text):
    """锚点密度: 强逻辑锚点词命中数 / 千字 (文档 7.3 锚点密度与防漂移)."""
    total_chars = len(text)
    hits = []
    for w in ANCHOR_WORDS:
        c = len(re.findall(re.escape(w), text, re.IGNORECASE))
        if c:
            hits.append((w, c))
    total_hits = sum(c for _, c in hits)
    density = total_hits / max(1, total_chars) * 1000  # 每千字锚点数
    if density >= 8:
        level, verdict = "高", "PASS"
    elif density >= 4:
        level, verdict = "中", "WARN"
    else:
        level, verdict = "低", "FAIL"
    return {"density": round(density, 1), "total_hits": total_hits,
            "level": level, "verdict": verdict, "top_words": hits[:10]}


def structure_check(text):
    """结构化输出检查 (文档 8.1-8.3): 发现检查点标记."""
    found = []
    for pat, name in STRUCT_MARKERS:
        if re.search(pat, text, re.MULTILINE):
            found.append(name)
    if found:
        return {"status": "PASS", "found": found}
    return {"status": "WARN", "found": [],
            "suggest": "未发现结构化输出模板 — 建议增加字段标记/编号列表作为注意力检查点 (8.1)"}


def length_check(text):
    """长文本检查 (文档 9.1-9.3): >3000 字建议检查点回溯 + 滑动窗口."""
    total = len(text)
    if total > 3000:
        return {"status": "WARN", "chars": total,
                "suggest": "长文本建议: 检查点回溯(每500字) + 滑动窗口摘要 + 关键信息重复锚定 (9.1-9.4)"}
    return {"status": "PASS", "chars": total}


def run(input_text, scenario=None, verbose=False):
    text = input_text.strip()
    if scenario is None:
        scene, scores = detect_scenario(text)
        scene_auto = True
    else:
        scene, scores, scene_auto = scenario, {}, False
    out = {
        "input_chars": len(text),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "scenario": {"detected": scene, "auto": scene_auto, "scores": scores},
        "checks": [],
    }
    ad = anchor_density(text)
    sc = structure_check(text)
    lc = length_check(text)
    out["checks"] = [
        {"name": "锚点密度诊断", "status": ad["verdict"],
         "detail": f"{ad['density']}/千字 ({ad['level']}) 命中{ad['total_hits']}次, 强逻辑锚点词: {[w for w,_ in ad['top_words'][:6]]}"},
        {"name": "结构化输出检查点", "status": sc["status"],
         "detail": (f"发现: {', '.join(sc['found'])}" if sc["status"] == "PASS" else sc["suggest"])},
        {"name": "长文本检查点建议", "status": lc["status"],
         "detail": (f"{lc['chars']} 字, 无需滑动窗口" if lc["status"] == "PASS" else lc["suggest"])},
    ]
    hp = HYPERPARAMS[scene]
    out["hyperparams"] = hp
    out["degrade_notes"] = DEGRADE_NOTES[scene]
    fails = [c for c in out["checks"] if c["status"] == "FAIL"]
    warns = [c for c in out["checks"] if c["status"] == "WARN"]
    out["verdict"] = "FAIL" if fails else ("PASS_WITH_WARN" if warns else "PASS")
    out["seal"] = __import__("hashlib").sha256(
        json.dumps(out["checks"], sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
    if verbose:
        print("═══ pef-prompt-optimizer · 提示词锚定优化 ═══")
        print(f"输入: {len(text)} 字 | 场景: {scene}{' (自动判定)' if scene_auto else ' (指定)'}")
        print()
        for c in out["checks"]:
            mark = {"PASS": "✓", "FAIL": "✗", "WARN": "△"}[c["status"]]
            print(f"  [{mark}] {c['name']}")
            print(f"        {c['detail']}")
        print(f"\n推荐超参: {hp}")
        print("降级方案:")
        for n in DEGRADE_NOTES[scene]:
            print(f"  · {n}")
        print(f"\n裁决: {out['verdict']}  |  π锚印章: {out['seal']}")
    return out


def main():
    ap = argparse.ArgumentParser(description="PEF 提示词锚定优化器")
    ap.add_argument("input", help="提示词文件路径或直接输入文本(短文本)")
    ap.add_argument("--scenario", choices=["terminal", "local", "online"], help="指定场景")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    # 文件或文本
    try:
        with open(a.input, encoding="utf-8-sig") as f:
            text = f.read()
    except OSError:
        text = a.input  # 视为直接文本
    out = run(text, scenario=a.scenario, verbose=not a.json)
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=1))
    sys.exit(0 if out["verdict"] != "FAIL" else 1)


if __name__ == "__main__":
    main()
