#!/usr/bin/env python3
"""
CLE V3.8.2 PEF算子库扩展 — 11个E层算子
从PEF算子库500+条中筛选适配，填补原始4大算子的检测盲区。
"""
import re
from typing import List, Dict
from cle_base_layer import AuditEvent, strip_c_comments

# ============================================================
# 第一批: 空包占位符/逻辑链断裂/死代码
# ============================================================

class PlaceholderDetector:
    """E033 Frama-C适配: 空包占位符检测"""
    PLACEHOLDER_PATTERNS = [
        (r'TODO|FIXME|HACK|XXX', 'TODO/FIXME占位符标记'),
        (r'暂不实现|待实现|not.implemented', '未实现占位符标记'),
        # 排除Python常量名 _PLACEHOLDER_xxx = '...'（这是正常的常量定义，不是未实现标记）
        (r'(?<!_)placeholder(?!_)|stub(?!\s*=)', '未实现占位符标记'),
    ]
    EMPTY_BODY_PATTERNS = [
        (r'\w+\s*\([^)]*\)\s*\{\s*\}', '空函数体(仅有花括号)'),
        (r'\w+\s*\([^)]*\)\s*\{\s*return\s+(?:true|false|0|1|nullptr|NULL)\s*;\s*\}', '仅返回常量的空函数'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        # 注释剥离前检测占位符
        for i, line in enumerate(lines):
            for pat, desc in self.PLACEHOLDER_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({
                        'event_id': f'PEF_PLACEHOLDER_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PLACEHOLDER',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '实现该占位符标记的完整逻辑'
                    })
        # 空函数体检测
        for i, line in enumerate(lines):
            for pat, desc in self.EMPTY_BODY_PATTERNS:
                if re.search(pat, line.strip()):
                    findings.append({
                        'event_id': f'PEF_EMPTY_BODY_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PLACEHOLDER',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '补充函数体实现'
                    })
        return findings


class LogicChainVerifier:
    """E056 CEGAR适配: 逻辑链断裂检测"""
    RETURN_CHECK_PATTERNS = [
        (r'(\w+)\s*=\s*(?:load|init|configure|setup|create|open)\s*\(', 'load/init返回值未检查'),
        (r'(\w+)\s*=\s*(?:new\s+\w+)', 'new返回值未检查'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.RETURN_CHECK_PATTERNS:
                m = re.search(pat, line)
                if m:
                    var = m.group(1)
                    # 检查后续3行是否有if检查
                    has_check = False
                    for j in range(i+1, min(i+4, len(lines))):
                        if re.search(rf'if\s*\(\s*!?\s*{re.escape(var)}\b', lines[j]):
                            has_check = True
                            break
                    if not has_check:
                        findings.append({
                            'event_id': f'PEF_LOGIC_CHAIN_{i+1}',
                            'line': i+1, 'severity': 'P1',
                            'category': 'LOGIC_CHAIN',
                            'description': f'{desc}: 变量{var}在第{i+1}行',
                            'suggestion': f'检查{var}的返回值是否有效'
                        })
        return findings


class DeadCodeDetector:
    """E034 Astree适配: 死代码检测"""
    DEAD_PARAM_PATTERNS = [
        (r'kd\s*=\s*0\.0|threshold\s*=\s*0\.0', '参数设为0.0导致路径失效'),
    ]
    UNREACHABLE_PATTERNS = [
        (r'return\s+[;\n]', 'return后不可达代码'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.DEAD_PARAM_PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        'event_id': f'PEF_DEAD_CODE_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'DEAD_CODE',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '检查参数值是否合理'
                    })
        return findings


class MathPropertyVerifier:
    """E022 Z3 SMT适配: 数学性质检测"""
    NARROWING_PATTERNS = [
        (r'static_cast\s*<\s*(?:uint8_t|uint16_t|int8_t|int16_t)\s*>\s*\(', 'static_cast窄化转换'),
        (r'\b(?:int8_t|int16_t)\s+\w+\s*=\s*\w+\s*%', '取模可能碰撞窄类型'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.NARROWING_PATTERNS:
                if re.search(pat, line):
                    findings.append({
                        'event_id': f'PEF_MATH_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'MATH_PROPERTY',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '检查数值范围是否溢出'
                    })
        return findings


class StringLiteralValidator:
    """E040 UBSan适配: 字符串有效性检测"""
    INVALID_PATTERNS = [
        (r'\.find\s*\(\s*"NULL_check"', '搜索不存在的字符串"NULL_check"'),
        (r'\.find\s*\(\s*"null_check"', '搜索不存在的字符串"null_check"'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.INVALID_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({
                        'event_id': f'PEF_INVALID_STR_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'INVALID_PATTERN',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '检查搜索字符串是否正确'
                    })
        return findings


class UnimplementedDeclDetector:
    """E035 CBMC适配: 未实现声明检测"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        # 检测.h中的函数声明
        decl_pattern = re.compile(r'(\w+)\s+(\w+)\s*\([^)]*\)\s*;')
        # 检测.cpp中的函数定义
        def_pattern = re.compile(r'(\w+)\s+(\w+)\s*\([^)]*\)\s*\{')

        declarations = set()
        for i, line in enumerate(lines):
            m = decl_pattern.search(line)
            if m and not line.strip().startswith('//'):
                declarations.add(m.group(2))

        definitions = set()
        for i, line in enumerate(lines):
            m = def_pattern.search(line)
            if m:
                definitions.add(m.group(2))

        unimplemented = declarations - definitions
        for name in unimplemented:
            findings.append({
                'event_id': f'PEF_UNIMPL_{name}',
                'line': 0, 'severity': 'P1',
                'category': 'UNIMPLEMENTED',
                'description': f'函数{name}已声明但未实现',
                'suggestion': f'实现函数{name}的定义'
            })
        return findings


# ============================================================
# 第二批: 内存安全/资源泄漏/路径覆盖
# ============================================================

class BufferOverflowDetector:
    """E039 ASan适配: 缓冲区溢出检测"""
    NPOS_RISK_PATTERN = re.compile(r'\.find\s*\([^)]+\)\s*;\s*\n\s*(\w+)\.substr\s*\(')
    UNSAFE_STR_OPS = [
        (r'strcpy\s*\(', 'strcpy无边界检查'),
        (r'sprintf\s*\(', 'sprintf无边界限制'),
        (r'strcat\s*\(', 'strcat无边界检查'),
    ]
    ARRAY_NO_BOUNDS = re.compile(r'\b(\w+)\s*\[\s*\w+\s*\]\s*[=;]')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            # find()返回npos后直接substr
            if '.find(' in line and 'npos' not in line:
                for j in range(i+1, min(i+3, len(lines))):
                    if '.substr(' in lines[j] and 'npos' not in lines[j]:
                        findings.append({
                            'event_id': f'BUF_NPOS_{i+1}',
                            'line': i+1, 'severity': 'P0',
                            'category': 'BUFFER_OVERFLOW',
                            'description': f'find()返回值未检查npos, 直接用于substr可能越界访问',
                            'suggestion': 'find()后检查 pos != string::npos 再使用substr'
                        })
                        break
            # 不安全的字符串操作
            for pat, desc in self.UNSAFE_STR_OPS:
                if re.search(pat, line):
                    findings.append({
                        'event_id': f'BUF_UNSAFE_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'BUFFER_OVERFLOW',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '使用strncpy/snprintf等安全版本'
                    })
        return findings


class UninitMemoryDetector:
    """E041 MSan适配: 未初始化内存检测"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        decl_pattern = re.compile(r'\b(?:int|float|double|char|bool|auto)\s+(\w+)\s*;')
        for i, line in enumerate(lines):
            m = decl_pattern.search(line)
            if m:
                var = m.group(1)
                # 检查后续行是否有赋值
                has_init = False
                for j in range(i+1, min(i+5, len(lines))):
                    if re.search(rf'\b{re.escape(var)}\s*=', lines[j]):
                        has_init = True
                        break
                # 检查是否在同一行使用
                for j in range(i+1, min(i+3, len(lines))):
                    if re.search(rf'\b{re.escape(var)}\b', lines[j]) and '=' not in lines[j].split(var)[0]:
                        if not has_init:
                            findings.append({
                                'event_id': f'PEF_UNINIT_{i+1}',
                                'line': i+1, 'severity': 'P1',
                                'category': 'UNINIT_MEMORY',
                                'description': f'变量{var}声明后未初始化可能被使用',
                                'suggestion': f'声明{var}时赋予初始值'
                            })
                            break
        return findings


class ResourceLeakDetector:
    """E043 Valgrind适配: 资源泄漏检测"""
    FILE_OPEN_PATTERNS = [
        (r'(\w+)\s*=\s*fopen\s*\(', 'fopen'),
        (r'std::ifstream\s+(\w+)\s*\(', 'ifstream'),
    ]
    NEW_PATTERN = re.compile(r'new\s+\w+')
    DELETE_PATTERN = re.compile(r'delete\s+')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, label in self.FILE_OPEN_PATTERNS:
                m = re.search(pat, line)
                if m:
                    var = m.group(1) if m.lastindex else ''
                    has_close = False
                    for j in range(i+1, len(lines)):
                        close_pat = rf'(?:fclose|close|\.close\s*\(\s*)\s*{re.escape(var)}' if var else r'(?:fclose|close|\.close\s*\()'
                        if re.search(close_pat, lines[j]):
                            has_close = True
                            break
                    if not has_close:
                        findings.append({
                            'event_id': f'PEF_LEAK_{i+1}',
                            'line': i+1, 'severity': 'P1',
                            'category': 'RESOURCE_LEAK',
                            'description': f'{label}打开后未见关闭',
                            'suggestion': f'确保在所有路径上关闭资源'
                        })
            # new without delete
            if self.NEW_PATTERN.search(line):
                has_delete = False
                for j in range(i+1, min(i+50, len(lines))):
                    if self.DELETE_PATTERN.search(lines[j]):
                        has_delete = True
                        break
                if not has_delete:
                    findings.append({
                        'event_id': f'PEF_NEW_LEAK_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'RESOURCE_LEAK',
                        'description': 'new分配后未见delete',
                        'suggestion': '确保释放动态分配的内存'
                    })
        return findings


class IntegerOverflowDetector:
    """E150 CBMC适配: 整数溢出检测"""
    MUL_PATTERNS = [
        (r'(\w+)\s*\*\s*(\d+)', '乘法运算无范围检查'),
    ]
    SHIFT_PATTERNS = [
        (r'<<\s*(\d+)', '左移可能丢失符号位'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.MUL_PATTERNS:
                if re.search(pat, line) and 'check' not in line.lower():
                    findings.append({
                        'event_id': f'PEF_INT_OVERFLOW_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'INTEGER_OVERFLOW',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '添加乘法结果的范围检查'
                    })
        return findings


class PathCoverageAnalyzer:
    """E049 KLEE适配: 路径覆盖检测"""
    ALWAYS_TRUE = re.compile(r'if\s*\(\s*(?:true|1|!0)\s*\)')
    ALWAYS_FALSE = re.compile(r'if\s*\(\s*(?:false|0)\s*\)')
    NO_DEFAULT = re.compile(r'switch\s*\(')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if self.ALWAYS_TRUE.search(line):
                findings.append({
                    'event_id': f'PEF_PATH_{i+1}',
                    'line': i+1, 'severity': 'P1',
                    'category': 'PATH_COVERAGE',
                    'description': '恒真条件: 分支永远执行',
                    'suggestion': '检查条件是否应为变量'
                })
            if self.ALWAYS_FALSE.search(line):
                findings.append({
                    'event_id': f'PEF_PATH_DEAD_{i+1}',
                    'line': i+1, 'severity': 'P1',
                    'category': 'PATH_COVERAGE',
                    'description': '恒假条件: 分支永不执行(死代码)',
                    'suggestion': '删除恒假分支或修正条件'
                })
            if self.NO_DEFAULT.search(line):
                # 检查后续是否有default
                has_default = False
                for j in range(i+1, min(i+30, len(lines))):
                    if 'default' in lines[j] and ('case' in lines[j] or ':' in lines[j]):
                        has_default = True
                        break
                    if '}' in lines[j] and 'case' not in lines[j]:
                        break
                if not has_default:
                    findings.append({
                        'event_id': f'PEF_SWITCH_DEFAULT_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PATH_COVERAGE',
                        'description': 'switch缺少default分支',
                        'suggestion': '添加default处理未知情况'
                    })
        return findings


class RaceConditionDetector:
    """E042 TSan适配: 数据竞争检测"""
    STATIC_VAR_PATTERNS = [
        (r'static\s+(?:int|float|double|char|bool|auto)\s+(\w+)', '静态变量无锁保护'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.STATIC_VAR_PATTERNS:
                m = re.search(pat, line)
                if m:
                    var = m.group(1)
                    has_lock = False
                    for j in range(max(0, i-3), min(i+10, len(lines))):
                        if re.search(r'(?:lock|mutex|atomic|guard)', lines[j], re.IGNORECASE):
                            has_lock = True
                            break
                    if not has_lock:
                        findings.append({
                            'event_id': f'PEF_RACE_{i+1}',
                            'line': i+1, 'severity': 'P1',
                            'category': 'RACE_CONDITION',
                            'description': f'{desc}: 变量{var}',
                            'suggestion': '使用锁或atomic保护静态变量'
                        })
        return findings


# ============================================================
# 统一入口
# ============================================================

ALL_OPERATORS = [
    PlaceholderDetector(),
    LogicChainVerifier(),
    DeadCodeDetector(),
    MathPropertyVerifier(),
    StringLiteralValidator(),
    UnimplementedDeclDetector(),
    BufferOverflowDetector(),
    UninitMemoryDetector(),
    ResourceLeakDetector(),
    IntegerOverflowDetector(),
    PathCoverageAnalyzer(),
    RaceConditionDetector(),
]

def run_pef_operators(source_code: str) -> List[Dict]:
    """运行全部11个PEF算子并返回合并的发现列表"""
    all_findings = []
    for op in ALL_OPERATORS:
        try:
            findings = op.detect(source_code)
            all_findings.extend(findings)
        except Exception as e:
            all_findings.append({
                'event_id': f'PEF_ERROR_{op.__class__.__name__}',
                'line': 0, 'severity': 'INFO',
                'category': 'OPERATOR_ERROR',
                'description': f'算子{op.__class__.__name__}执行异常: {e}',
                'suggestion': '检查算子实现'
            })
    return all_findings

__all__ = [
    'PlaceholderDetector', 'LogicChainVerifier', 'DeadCodeDetector',
    'MathPropertyVerifier', 'StringLiteralValidator', 'UnimplementedDeclDetector',
    'BufferOverflowDetector', 'UninitMemoryDetector', 'ResourceLeakDetector',
    'IntegerOverflowDetector', 'PathCoverageAnalyzer', 'RaceConditionDetector',
    'run_pef_operators', 'ALL_OPERATORS'
]
