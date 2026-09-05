#!/usr/bin/env python3
"""
CLE V3.8 720条特征库骨架数据（设计第11章L1091）
分片：通用250(π0-3) + DOC100(π4) + MOD80(π5) + LLM120(π6) + WEB100(π7) + EVASION70(π8-9)
诚实声明：所有条目为骨架，trigger_pattern/fix需人工有效性验证（设计L2611）
"""
from signature_library import Signature, SignatureLibraryRegistry


def build_library() -> SignatureLibraryRegistry:
    """构建720条特征库骨架"""
    reg = SignatureLibraryRegistry()

    # === 通用特征库 250条 (π=0-3) ===
    _generic_patterns = [
        # P层 (Process) - 初始化/参数/状态/输入/配置
        ("P-INIT", "未初始化变量使用", "P0", "StateBoundedness", r'\w+\s*=\s*\w+;\s*//\s*uninit', "初始化所有变量", 0),
        ("P-PARAM", "函数参数未校验", "P1", "StateBoundedness", r'void\s+\w+\s*\([^)]*\)\s*\{', "添加参数边界检查", 0),
        ("P-STATE", "状态机缺省状态未处理", "P1", "StateBoundedness", r'switch\s*\([^)]*\)\s*\{[^}]*\}', "添加default分支", 1),
        ("P-INPUT", "外部输入未归一化", "P0", "TaintPropagation", r'(scanf|gets|recv)\s*\(', "输入校验+清洗", 1),
        ("P-CONFIG", "配置缺失无默认值", "P2", "StateBoundedness", r'config\s*\.\w+\s*=', "提供默认配置值", 2),
        # E层 (Execute) - 算术/控制/资源/并发/时序
        ("E-ARITH", "整数溢出未检查", "P1", "StateBoundedness", r'\w+\s*\+=\s*\w+;', "溢出检查或使用安全库", 2),
        ("E-CONTROL", "控制流可达性缺陷", "P1", "StateBoundedness", r'if\s*\([^)]*\)\s*\{[^}]*\}\s*else\s*\{', "检查所有分支可达性", 2),
        ("E-RESOURCE", "资源分配未检查返回值", "P0", "ResourceBound", r'(malloc|fopen|socket)\s*\(', "检查返回值NULL", 3),
        ("E-CONCURRENCY", "锁获取释放不配对", "P1", "ResourceBound", r'(pthread_mutex_lock|pthread_mutex_unlock)', "确保锁配对释放", 3),
        ("E-TIMING", "时间戳乘法溢出", "P0", "TimeMonotonicity", r'Hal_GetTick\(\)\s*\*\s*\d+', "使用64位时间或检查溢出", 3),
        # F层 (Feedback) - 错误/日志/报告
        ("F-ERROR", "错误路径未处理", "P1", "TimeMonotonicity", r'return\s*-1\s*;', "完善错误处理路径", 0),
        ("F-LOG", "日志资源泄漏", "P2", "ResourceBound", r'fopen\s*\([^)]*\)[^;]*;', "日志文件句柄及时关闭", 1),
        ("F-REPORT", "状态报告不一致", "P2", "StateBoundedness", r'printf\s*\([^)]*\)', "报告与实际状态对齐", 2),
    ]

    # 生成250条通用特征（13个模板 × 约20个变体编号）
    variant_count = 0
    for base in _generic_patterns:
        for v in range(20):
            if variant_count >= 250:
                break
            fid = f"{base[0]}-{v:03d}"
            pi = base[6] + (v % 4)  # 分散到π=0-3
            pi = min(pi, 3)
            sig = Signature(
                fault_id=fid,
                name=f"{base[1]} (变体{v})",
                severity=base[2],
                operator=base[3],
                trigger_pattern=base[4],
                fix=base[5],
                pi_binding=pi,
                category=base[0].split('-')[0],
                verified=False,
            )
            reg.register(sig)
            variant_count += 1
        if variant_count >= 250:
            break

    # === DOC库 100条 (π=4) ===
    for i in range(100):
        sig = Signature(
            fault_id=f"DOC-{i:03d}",
            name=f"文档字符串缺陷-{i}",
            severity="P2" if i % 3 == 0 else "P1",
            operator="DocChecker",
            trigger_pattern=r'/\*\*.*?\*/',
            fix="完善文档注释",
            pi_binding=4,
            category="DOC",
            verified=False,
        )
        reg.register(sig)

    # === MOD库 80条 (π=5) ===
    for i in range(80):
        sig = Signature(
            fault_id=f"MOD-{i:03d}",
            name=f"架构契约缺陷-{i}",
            severity="P1" if i % 2 == 0 else "P2",
            operator="ModContractChecker",
            trigger_pattern=r'class\s+\w+',
            fix="修复架构契约违反",
            pi_binding=5,
            category="MOD",
            verified=False,
        )
        reg.register(sig)

    # === LLM库 120条 (π=6) ===
    for i in range(120):
        sig = Signature(
            fault_id=f"LLM-{i:03d}",
            name=f"AI生成代码缺陷-{i}",
            severity="P1" if i % 4 == 0 else "P2",
            operator="LLMCodeChecker",
            trigger_pattern=r'#\s*AI generated',
            fix="人工审查AI生成代码",
            pi_binding=6,
            category="LLM",
            verified=False,
        )
        reg.register(sig)

    # === WEB库 100条 (π=7) ===
    for i in range(100):
        sig = Signature(
            fault_id=f"WEB-{i:03d}",
            name=f"Web安全缺陷-{i}",
            severity="P0" if i % 5 == 0 else "P1",
            operator="WebSecurityChecker",
            trigger_pattern=r'(request|response|session)',
            fix="修复Web安全漏洞",
            pi_binding=7,
            category="WEB",
            verified=False,
        )
        reg.register(sig)

    # === EVASION库 70条 (π=8-9) ===
    for i in range(70):
        pi = 8 if i < 35 else 9
        sig = Signature(
            fault_id=f"EVASION-{i:03d}",
            name=f"逃逸检测缺陷-{i}",
            severity="P0" if i % 7 == 0 else "P1",
            operator="EvasionDetector",
            trigger_pattern=r'(\\x[0-9a-f]{2}|\\u[0-9a-f]{4})',
            fix="检测编码逃逸攻击",
            pi_binding=pi,
            category="EVASION",
            verified=False,
        )
        reg.register(sig)

    return reg


if __name__ == "__main__":
    lib = build_library()
    stats = lib.get_stats()
    integrity = lib.verify_integrity()
    print(f"特征库总量: {stats['total']} (目标720)")
    print(f"按π分片: {stats['by_pi']}")
    print(f"按严重级: {stats['by_severity']}")
    print(f"哈希完整性: {'OK' if integrity['integrity_ok'] else 'FAIL'}")
    assert stats['total'] == 720, f"特征库数量错误: {stats['total']}"
    assert integrity['integrity_ok'], "哈希校验失败"
    print("720条特征库骨架构建完成")
