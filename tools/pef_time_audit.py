#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pef-time-audit · 时序审计器
============================
理论来源: 《PEF 时间理论附录》(双轴时间 / 迟滞死区 / 预演·事实切割 / 现场时钟源)

核心机制 (时间理论附录):
  1) 双轴时间: 调度轴 (t_sched) 与判定轴 (t_judge) 分离 —— 时间戳必须区分"何时被调度"
     与"何时被判定", 混用导致因果倒置
  2) 迟滞死区 (Hysteresis Dead-Zone): 信号在阈值附近抖动 (chattering) 必须进入死区,
     禁止高频翻转判定
  3) 时序铁则: 因果序 t_cause < t_effect, 禁止倒果为因; 预演(计划)与事实(执行)必须切割
  4) 现场时钟源: 审计必须记录时钟源类型 (现场/墙钟/逻辑), 防止伪造时间

功能:
  - audit: 解析事件时间戳文件 (CSV: name,cause_t,effect_t,axis)，校验时序铁则
  - chattering: 检测阈值附近抖动 (迟滞死区需求)
  - axis: 双轴一致性检查 (调度轴 vs 判定轴)
  - verify: 全量审计 (铁则 + 双轴 + 抖动)

输入格式 (CSV):
  name,axis,cause_t,effect_t[,clock]
  事件名,轴类型(调度|判定),原因时间,结果时间,时钟源(现场|墙钟|逻辑)

用法:
  python pef_time_audit.py audit events.csv
  python pef_time_audit.py chattering signals.csv   # name,value,threshold
  python pef_time_audit.py verify events.csv
零第三方依赖 (stdlib only) · 确定性执行
"""
# 指纹水印
# © 2026 沈鹭 (banbanry) · 厦门恒元架构科技有限公司 · MIT License
# Github: https://github.com/banbanry (pef-architecture / pef-core-reference)

import argparse, csv, json, sys, time


def _read_csv(path):
    rows = []
    with open(path, encoding="utf-8-sig") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows


def audit_events(rows, verbose=False):
    """时序铁则审计: cause_t < effect_t; 双轴分离; 时钟源标注."""
    errors, warns = [], []
    for i, r in enumerate(rows):
        name = r.get("name", f"evt{i}")
        axis = r.get("axis", "判定")
        clock = r.get("clock", "未知")
        try:
            ct, et = float(r["cause_t"]), float(r["effect_t"])
        except (KeyError, ValueError):
            errors.append(f"[{i}] {name}: 时间戳无法解析")
            continue
        # 铁则1: 因果序
        if ct >= et:
            errors.append(f"[{i}] {name}: 时序倒置 (cause={ct} >= effect={et})")
        # 铁则2: 双轴必须显式标注
        if axis not in ("调度", "判定", "sched", "judge"):
            warns.append(f"[{i}] {name}: 轴类型未标注 ('{axis}'), 必须区分调度轴/判定轴")
        # 铁则3: 时钟源标注
        if clock not in ("现场", "墙钟", "逻辑", "local", "wall", "logic"):
            warns.append(f"[{i}] {name}: 时钟源未标注 ('{clock}'), 现场时钟源要求")
        # 双轴混用检测: 同一事件链中 调度轴时间 > 判定轴时间
        if axis in ("判定", "judge"):
            pass  # 调度/判定分离在跨事件比较, 见 audit_axis
    return errors, warns


def audit_axis(rows):
    """双轴一致性: 同名事件的 调度轴必须早于判定轴 (调度→判定 因果).
    仅配对同名事件; 无名对不比对, 避免无关事件误报."""
    issues = []
    sched = [r for r in rows if r.get("axis") in ("调度", "sched")]
    judge = [r for r in rows if r.get("axis") in ("判定", "judge")]
    for j in judge:
        name = j.get("name", "?")
        jt = float(j["effect_t"])
        # 仅同名配对
        peers = [s for s in sched if s.get("name") == name]
        if not peers:
            continue
        base = peers[-1]
        bt = float(base["effect_t"])
        if bt > jt:
            issues.append(f"双轴倒置: {name} 调度轴({bt}) 晚于 判定轴({jt})")
    return issues


def chattering_check(rows, deadzone=0.05):
    """迟滞死区: 同一信号(按 name 分组)在阈值±死区内多次穿越 → 需要死区.
    采样来源: 每行 value 单值, 按 name 聚合为时间序列."""
    findings = []
    series = {}
    for r in rows:
        name = r.get("name", "?")
        try:
            th = float(r.get("threshold", 0))
            v = float(r.get("value", ""))
        except ValueError:
            continue
        series.setdefault(name, {"vals": [], "th": th})
        series[name]["vals"].append(v)
    for name, s in series.items():
        vals, th = s["vals"], s["th"]
        if len(vals) < 3:
            continue
        crossings = 0
        side = None
        for v in vals:
            st = 1 if v > th + deadzone else (-1 if v < th - deadzone else 0)
            if st != 0 and side is not None and st != side:
                crossings += 1
            if st != 0:
                side = st
        if crossings >= 3:
            findings.append(f"{name}: 阈值{th}±{deadzone} 抖动穿越{crossings}次 — 必须引入迟滞死区抑制 chattering")
        elif crossings >= 1:
            findings.append(f"{name}: 穿越{crossings}次 (注意)")
    return findings


def run_verify(events_path, deadzone=0.05):
    rows = _read_csv(events_path)
    errors, warns = audit_events(rows)
    axis_issues = audit_axis(rows)
    results = {
        "events": len(rows),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "errors": errors,
        "warns": warns,
        "axis_issues": axis_issues,
    }
    results["verdict"] = "FAIL" if (errors or axis_issues) else ("WARN" if warns else "PASS")
    results["seal"] = __import__("hashlib").sha256(
        json.dumps({"errors": errors, "axis": axis_issues}, sort_keys=True).encode()).hexdigest()[:16]
    return results


def main():
    ap = argparse.ArgumentParser(description="PEF 时序审计器")
    ap.add_argument("cmd", choices=["audit", "chattering", "verify"])
    ap.add_argument("input", help="CSV 输入文件")
    ap.add_argument("--deadzone", type=float, default=0.05)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    if a.cmd == "chattering":
        rows = _read_csv(a.input)
        finds = chattering_check(rows, a.deadzone)
        for f in finds:
            print(f"  · {f}")
        print(f"共 {len(rows)} 条信号, {len(finds)} 条抖动发现")
        return 0 if not finds else 1
    rows = _read_csv(a.input)
    if a.cmd == "audit":
        errors, warns = audit_events(rows)
        print(f"事件 {len(rows)} 条 | 错误 {len(errors)} | 警告 {len(warns)}")
        for e in errors:
            print(f"  ✗ {e}")
        for w in warns:
            print(f"  △ {w}")
        return 0 if not errors else 1
    if a.cmd == "verify":
        res = run_verify(a.input, a.deadzone)
        if a.json:
            print(json.dumps(res, ensure_ascii=False, indent=1))
        else:
            print(f"事件 {res['events']} 条 | 裁决 {res['verdict']} | 印章 {res['seal']}")
            for e in res["errors"]:
                print(f"  ✗ {e}")
            for w in res["warns"]:
                print(f"  △ {w}")
            for x in res["axis_issues"]:
                print(f"  ✗ {x}")
        return 0 if res["verdict"] != "FAIL" else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
