#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pef-operator-library · 算子库引擎
==================================
理论来源: 《PEF算子库完整细分 V2.0》(680条) + 《PEF算子库扩展版 V3.0》(800条)

核心机制:
  1) 算子按 P/E/F/M 域分类 (P=策略生成/E=否决审计/F=证据裁决/M=终审维护)
  2) π-Mod3 相位映射: 算子编号数字 mod3 → 推荐域 (0=P/1=E/2=F)
  3) 检索: 按名称/机制/角色/来源关键词匹配
  4) 建议: 按代码场景关键词推荐算子

用法:
  python pef_operator_library.py build <txt1> <txt2> -o operator_library.json
  python pef_operator_library.py search <关键词> -o operator_library.json
  python pef_operator_library.py list --domain P -o operator_library.json
  python pef_operator_library.py phase P306
  python pef_operator_library.py match <场景关键词>
零第三方依赖 (stdlib only) · 确定性执行
"""
# 指纹水印
# © 2026 沈鹭 (banbanry) · 厦门恒元架构科技有限公司 · MIT License
# Github: https://github.com/banbanry (pef-architecture / pef-core-reference)

import argparse, hashlib, json, os, re, sys

PI_DIGITS = "3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067"
DOMAINS = {0: "P", 1: "E", 2: "F"}
DOMAIN_DESC = {"P": "策略生成(建议域)", "E": "否决审计(否决域)", "F": "证据裁决(裁决域)", "M": "终审维护(M层)"}

# ---- 解析: 完整版 5 行块格式 ----
BLOCK_RE = re.compile(r"^\s*([PEFMC])(\d{3})\s*$")

# ---- 解析: 扩展版 管道单行格式 ----
PIPE_RE = re.compile(r"^\s*([PEFMC])(\d{3})\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|\s*([^|]*)\s*\|\s*([^|]*)")

# ---- 场景 → 算子族映射 (match 用) ----
SCENE_MAP = {
    "优化": ["CMA-ES", "差分进化", "遗传", "粒子群", "Nelder", "Bayesian"],
    "求解": ["牛顿", "迭代", "Runge", "Gauss", "共轭", "梯度"],
    "拟合": ["最小二乘", "回归", "插值", "Taylor", "Fourier"],
    "概率": ["Monte", "随机", "马尔可夫", "贝叶斯", "泊松"],
    "符号": ["符号回归", "表达式", "PySR", "遗传编程"],
    "数值积分": ["Simpson", "Romberg", "梯形", "外推"],
    "微分方程": ["ODE", "PDE", "Runge", "Euler"],
    "安全审计": ["异常", "越界", "漏洞", "污染", "违约"],
    "证据融合": ["Dempster", "证据", "Yager", "置信"],
}


def parse_blocks(text):
    """解析 5 行块格式 (完整版): 编号行 + 后续 4 行字段."""
    ops = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = BLOCK_RE.match(lines[i].strip())
        if m:
            domain, num = m.group(1), int(m.group(2))
            fields = []
            for j in range(1, 5):
                if i + j < len(lines):
                    fields.append(lines[i + j].strip().rstrip("|").strip())
            while len(fields) < 4:
                fields.append("")
            ops[f"{domain}{num:03d}"] = {
                "id": f"{domain}{num:03d}", "domain": domain,
                "name": fields[0], "mechanism": fields[1],
                "role": fields[2], "source": fields[3],
            }
            i += 5
        else:
            i += 1
    return ops


def parse_pipes(text):
    """解析管道单行格式 (扩展版): P306 | 名称 | 机制 | 角色 | 来源."""
    ops = {}
    for line in text.splitlines():
        m = PIPE_RE.match(line)
        if m:
            domain, num = m.group(1), int(m.group(2))
            ops[f"{domain}{num:03d}"] = {
                "id": f"{domain}{num:03d}", "domain": domain,
                "name": m.group(3).strip(), "mechanism": m.group(4).strip(),
                "role": m.group(5).strip(), "source": m.group(6).strip(),
            }
    return ops


def build(files):
    ops = {}
    for fn in files:
        with open(fn, encoding="utf-8") as f:
            text = f.read()
        a = parse_blocks(text)
        b = parse_pipes(text)
        merged = {**a, **b}
        ops.update(merged)
        print(f"  {os.path.basename(fn)}: 块格式{len(a)} + 管道格式{len(b)} = {len(merged)}")
    return ops


def phase_of(op_id):
    """π-Mod3 相位映射: 编号数字 mod3 → 域 (0=P/1=E/2=F)."""
    m = re.match(r"^[PEFMC](\d{3})$", op_id)
    if not m:
        return None
    num = int(m.group(1))
    return DOMAINS[num % 3]


def search(ops, kw):
    kwl = kw.lower()
    hits = []
    for op in ops.values():
        hay = (op["name"] + " " + op["mechanism"] + " " + op["role"] + " " + op["source"]).lower()
        if kwl in hay:
            hits.append(op)
    hits.sort(key=lambda o: o["id"])
    return hits


def match(ops, scene):
    """按场景关键词推荐算子族."""
    kws = []
    for k, v in SCENE_MAP.items():
        if k in scene or any(w.lower() in scene.lower() for w in v[:2]):
            kws.extend(v)
    if not kws:
        return []
    hits = []
    for op in ops.values():
        hay = op["name"] + op["mechanism"] + op["role"]
        if any(w.lower() in hay.lower() for w in kws):
            hits.append(op)
    return hits[:10]


def main():
    ap = argparse.ArgumentParser(description="PEF 算子库引擎")
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build")
    b.add_argument("inputs", nargs="+", help="算子库 txt 文件")
    b.add_argument("-o", default="operator_library.json")

    s = sub.add_parser("search")
    s.add_argument("kw")
    s.add_argument("-o", default="operator_library.json")

    l = sub.add_parser("list")
    l.add_argument("--domain", choices=["P", "E", "F", "M"])
    l.add_argument("-o", default="operator_library.json")

    p = sub.add_parser("phase")
    p.add_argument("op_id")

    m = sub.add_parser("match")
    m.add_argument("scene")
    m.add_argument("-o", default="operator_library.json")

    a = ap.parse_args()

    if a.cmd == "build":
        ops = build(a.inputs)
        with open(a.o, "w", encoding="utf-8") as f:
            json.dump({"count": len(ops), "operators": ops}, f, ensure_ascii=False, indent=0)
        dom = {}
        for op in ops.values():
            dom[op["domain"]] = dom.get(op["domain"], 0) + 1
        digest = hashlib.sha256(json.dumps(ops, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:16]
        print(f"构建完成: {len(ops)} 条 域分布={dom} π锚印章={digest}")
        return 0

    if a.cmd == "phase":
        ph = phase_of(a.op_id)
        if ph is None:
            print(f"无效编号: {a.op_id}")
            return 1
        print(f"{a.op_id} → π-Mod3 相位域: {ph} ({DOMAIN_DESC[ph]})")
        return 0

    with open(a.o, encoding="utf-8") as f:
        db = json.load(f)
    ops = db["operators"]

    if a.cmd == "search":
        hits = search(ops, a.kw)
        print(f"检索 '{a.kw}': {len(hits)} 条")
        for op in hits[:15]:
            ph = phase_of(op["id"])
            print(f"  {op['id']} [{op['domain']}] {op['name']} | {op['mechanism'][:40]} | π相位→{ph}")
        return 0

    if a.cmd == "list":
        sel = [op for op in ops.values() if not a.domain or op["domain"] == a.domain]
        print(f"{a.domain or '全部'} 域: {len(sel)} 条")
        for op in sel[:20]:
            print(f"  {op['id']} {op['name']} | {op['role'][:40]}")
        return 0

    if a.cmd == "match":
        hits = match(ops, a.scene)
        print(f"场景 '{a.scene}': 推荐 {len(hits)} 条算子")
        for op in hits:
            print(f"  {op['id']} [{op['domain']}] {op['name']}")
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
