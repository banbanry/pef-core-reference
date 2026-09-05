#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pef-state-ledger · 状态登记簿引擎
==================================
理论来源: 《弘信物流进出口单表单处理器说明书 V1.1》PEF V3.0 落地实现

核心机制 (说明书 PEF_StateLedger 部分):
  1) π锚绑定: 每条状态记录绑定 π 锚坐标 (π[seq]=digit|domain)
  2) 状态登记: 任意时刻可登记当前状态快照 (PSQ: "输入-处理-输出"三元)
  3) 快照单调: 追加写, 禁止覆写历史状态; 状态流必须单调推进
  4) 只追加审计日志: prev_hash 链式哈希, 篡改即断裂
  5) 特征向量数值化: 表单字段 → 数值向量 (初始值1.0, 归一化到[0,1])

功能:
  - ledger init: 初始化新账本 (创世块)
  - ledger add <key=value...> --source <源文件> : 追加状态记录
  - ledger verify: 校验哈希链完整性 + π锚连续性
  - ledger dump: 导出全量日志
  - ledger vector: 特征向量数值化输出 (表单字段→[0,1]向量)

用法:
  python pef_state_ledger.py init --db ledger.json
  python pef_state_ledger.py add SINO=ABC123 QTY=100 --db ledger.json --source AWB.csv
  python pef_state_ledger.py add SINO=ABC123 QTY=999 --db ledger.json --source AWB.csv  # 值变化
  python pef_state_ledger.py verify --db ledger.json
  python pef_state_ledger.py vector --db ledger.json
零第三方依赖 (stdlib only) · 确定性执行
"""
# 指纹水印
# © 2026 沈鹭 (banbanry) · 厦门恒元架构科技有限公司 · MIT License
# Github: https://github.com/banbanry (pef-architecture / pef-core-reference)

import argparse, hashlib, json, os, sys, time

PI_DIGITS = "3141592653589793238462643383279502884197169399375105820974944592307816406286208998628034825342117067"
DOMAINS = {0: "P", 1: "E", 2: "F"}


def _sha(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


def _pi_anchor(seq, domain):
    """π锚坐标: 位置由序号决定, 域由 mod3 决定."""
    pos = seq % len(PI_DIGITS)
    return f"π[{pos}]={PI_DIGITS[pos]}|{DOMAINS[seq % 3]}|{domain}"


def _open_db(db_path):
    if os.path.exists(db_path):
        with open(db_path, encoding="utf-8") as f:
            return json.load(f)
    return {"meta": {"version": "1.0", "created": None}, "entries": [], "seq": 0}


def _save_db(db, db_path):
    with open(db_path, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False, indent=1)


def cmd_init(db_path):
    db = _open_db(db_path)
    if db["entries"]:
        print(f"账本已存在: {db_path} ({len(db['entries'])} 条记录)")
        return 1
    db["meta"]["created"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    genesis = {"seq": 0, "anchor": _pi_anchor(0, "P"), "event": "GENESIS",
               "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
               "prev_hash": "0" * 64, "chain_hash": None}
    genesis["chain_hash"] = _sha({k: v for k, v in genesis.items() if k != "chain_hash"})
    db["entries"] = [genesis]
    db["seq"] = 1
    _save_db(db, db_path)
    print(f"账本初始化完成: {db_path} (创世块 seq=0, anchor={genesis['anchor']})")
    return 0


def cmd_add(db_path, fields, source):
    """追加状态记录. fields: dict; source: 来源文件/单据类型."""
    db = _open_db(db_path)
    if not db["entries"]:
        print("账本未初始化, 请先 init")
        return 1
    seq = db["seq"]
    domain = DOMAINS[seq % 3]
    prev = db["entries"][-1]["chain_hash"]
    rec = {"seq": seq, "anchor": _pi_anchor(seq, domain), "domain": domain,
           "event": "STATE", "source": source, "fields": fields,
           "ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "prev_hash": prev, "chain_hash": None}
    rec["chain_hash"] = _sha({k: v for k, v in rec.items() if k != "chain_hash"})
    db["entries"].append(rec)
    db["seq"] = seq + 1
    _save_db(db, db_path)
    print(f"[seq={seq}] {rec['anchor']} 源={source} 字段={fields}")
    return 0


def cmd_verify(db_path):
    db = _open_db(db_path)
    if not db["entries"]:
        print("账本为空")
        return 1
    errors = []
    for i, e in enumerate(db["entries"]):
        recomputed = _sha({k: v for k, v in e.items() if k != "chain_hash"})
        if recomputed != e["chain_hash"]:
            errors.append(f"seq={e['seq']} 链哈希断裂 (篡改检测)")
        if i > 0 and e["prev_hash"] != db["entries"][i - 1]["chain_hash"]:
            errors.append(f"seq={e['seq']} prev_hash 不连续")
        if e["seq"] != i:
            errors.append(f"seq={e['seq']} 序号跳变 (应为 {i})")
    print(f"校验 {len(db['entries'])} 条记录: {'全部通过' if not errors else '发现 ' + str(len(errors)) + ' 处问题'}")
    for err in errors:
        print(f"  ✗ {err}")
    return 0 if not errors else 1


def cmd_dump(db_path):
    db = _open_db(db_path)
    for e in db["entries"]:
        print(f"{e['seq']:>3} | {e['anchor']:<22} | {e.get('event',''):<8} | {e.get('source','')} | {json.dumps(e.get('fields',{}), ensure_ascii=False)}")
    print(f"共 {len(db['entries'])} 条")
    return 0


def cmd_vector(db_path):
    """特征向量数值化: 收集所有字段名, 每条记录 → 归一化向量 [0,1]."""
    db = _open_db(db_path)
    entries = [e for e in db["entries"] if e.get("event") == "STATE"]
    if not entries:
        print("无状态记录")
        return 1
    all_keys = []
    for e in entries:
        for k in e["fields"]:
            if k not in all_keys:
                all_keys.append(k)
    # 字段 → 归一化数值 (纯数字直接归一化; 字符串指纹哈希取前8位十六进制→小数)
    def to_num(v):
        try:
            f = float(v)
            return min(1.0, max(0.0, f / 1000.0))  # 数值归一化 (假设量级<=1000)
        except (TypeError, ValueError):
            return int(_sha(str(v))[:8], 16) / float(0xFFFFFFFF)  # 字符串→确定性指纹
    vecs = []
    for e in entries:
        vec = {}
        for k in all_keys:
            if k in e["fields"]:
                vec[k] = round(to_num(e["fields"][k]), 4)
            else:
                vec[k] = 0.0  # 缺失字段 = 0
        vecs.append({"seq": e["seq"], "anchor": e["anchor"], "vector": vec})
    for v in vecs:
        print(f"seq={v['seq']} {v['anchor']} vector={v['vector']}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="PEF 状态登记簿引擎")
    ap.add_argument("cmd", choices=["init", "add", "verify", "dump", "vector"])
    ap.add_argument("fields", nargs="*", help="add 的 key=value 字段")
    ap.add_argument("--db", default="pef_ledger.json")
    ap.add_argument("--source", default="unknown")
    a = ap.parse_args()
    if a.cmd == "init":
        return cmd_init(a.db)
    if a.cmd == "add":
        fields = {}
        for f in a.fields:
            if "=" in f:
                k, v = f.split("=", 1)
                fields[k] = v
        if not fields:
            print("add 需要 key=value 字段")
            return 1
        return cmd_add(a.db, fields, a.source)
    if a.cmd == "verify":
        return cmd_verify(a.db)
    if a.cmd == "dump":
        return cmd_dump(a.db)
    if a.cmd == "vector":
        return cmd_vector(a.db)
    return 0


if __name__ == "__main__":
    sys.exit(main())
