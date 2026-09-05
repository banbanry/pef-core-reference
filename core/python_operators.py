#!/usr/bin/env python3
"""
CLE V3.8.2 Python算子库扩展 — 12个Python特有的审计算子
基于生产代码审计项目(T-01~T-19)实际缺陷 + Python通用安全问题设计。
与C算子并行运行，自动检测.py文件后加载。
"""
import re
import os
from typing import List, Dict


# ============================================================
# P0级: 崩溃/数据丢失/安全漏洞
# ============================================================

class PySilentExceptionDetector:
    """P0: 静默吞异常 — except: pass / except Exception: pass
    项目实证: T-07 P0 (域不匹配时except Exception: pass吞掉PEFBindingError)
    """
    SILENT_PATTERNS = [
        (r'except\s*:\s*(?:pass|continue)\s*(?:#.*)?$', '裸except静默吞错(含KeyboardInterrupt/SystemExit)'),
        (r'except\s+Exception\s*:\s*(?:pass|continue)\s*(?:#.*)?$', 'except Exception静默吞错'),
        (r'except\s+\w+\s*:\s*(?:pass|continue)\s*(?:#.*)?$', 'except指定类型静默吞错'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            code_part = re.sub(r'#.*$', '', stripped).strip()
            # 模式1：单行 except: pass（支持行尾注释）
            for pat, desc in self.SILENT_PATTERNS:
                if re.search(pat, code_part):
                    findings.append({
                        'event_id': f'PY_SILENT_EXCEPT_{i+1}',
                        'line': i+1, 'severity': 'P0',
                        'category': 'PY_EXCEPTION',
                        'description': f'{desc}: {code_part[:80]}',
                        'causal_chain': 'P[异常发生] -> E[except吞掉] -> F[错误不可见/状态不一致]',
                        'suggestion': '捕获具体异常类型，记录日志或重新抛出'
                    })
                    break
            else:
                # 模式2：except: 后跟注释，下一行是 pass/continue
                # 先剥离行内注释，避免注释中的pass/continue误判
                code_part = re.sub(r'#.*$', '', stripped).strip()
                if re.match(r'except\s*(?:Exception|BaseException)?\s*(?:as\s+\w+)?\s*:', code_part) and 'pass' not in code_part and 'continue' not in code_part:
                    # 检查后续行（最多5行）是否只有 pass/continue
                    for j in range(i+1, min(len(lines), i+6)):
                        next_stripped = lines[j].strip()
                        if not next_stripped:
                            continue
                        # 剥离下一行注释
                        next_code = re.sub(r'#.*$', '', next_stripped).strip()
                        if re.match(r'(?:pass|continue)\s*$', next_code):
                            findings.append({
                                'event_id': f'PY_SILENT_EXCEPT_{i+1}',
                                'line': i+1, 'severity': 'P0',
                                'category': 'PY_EXCEPTION',
                                'description': f'except块内仅pass/continue(静默吞错): {code_part[:60]} -> {next_code[:40]}',
                                'causal_chain': 'P[异常发生] -> E[except吞掉] -> F[错误不可见/状态不一致]',
                                'suggestion': '捕获具体异常类型，记录日志或重新抛出'
                            })
                        break  # 第一个非空行不是pass/continue就停止
        return findings


class PyCodeInjectionDetector:
    """P0: 代码注入 — eval/exec/compile使用用户输入"""
    DANGER_FUNCS = ['eval(', 'exec(', 'compile(']
    # 排除 re.compile（正则编译，非代码执行）
    SAFE_COMPILE_PREFIXES = ['re.compile', 'regex.compile', 'pattern.compile']

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            for func in self.DANGER_FUNCS:
                if func in stripped:
                    # 排除 re.compile 等安全的 compile
                    if func == 'compile(':
                        if any(prefix in stripped for prefix in self.SAFE_COMPILE_PREFIXES):
                            continue
                    # 检查是否有变量输入（非纯字符串常量）
                    m = re.search(rf'{func[:-1]}\s*\(([^)]+)\)', stripped)
                    if m:
                        arg = m.group(1).strip()
                        # 纯字符串常量相对安全，但仍标记
                        if not (arg.startswith("'") or arg.startswith('"')):
                            findings.append({
                                'event_id': f'PY_CODE_INJECT_{i+1}',
                                'line': i+1, 'severity': 'P0',
                                'category': 'PY_INJECTION',
                                'description': f'{func}使用非常量参数，可能代码注入: {stripped[:80]}',
                                'causal_chain': 'P[外部输入] -> E[eval/exec执行] -> F[任意代码执行]',
                                'suggestion': '避免使用eval/exec，用ast.literal_eval或显式解析'
                            })
                        else:
                            findings.append({
                                'event_id': f'PY_CODE_INJECT_WARN_{i+1}',
                                'line': i+1, 'severity': 'P1',
                                'category': 'PY_INJECTION',
                                'description': f'{func}使用(纯字符串常量，仍建议避免): {stripped[:80]}',
                                'suggestion': '考虑用ast.literal_eval替代'
                            })
        return findings


class PyUnsafeDeserializationDetector:
    """P0: 不安全反序列化 — pickle.load / yaml.load(无Loader)"""
    UNSAFE_PATTERNS = [
        (r'pickle\.loads?\s*\(', 'pickle反序列化(任意代码执行风险)'),
        (r'yaml\.load\s*\([^)]*\)(?!.*Loader)', 'yaml.load未指定SafeLoader'),
        (r'marshal\.loads?\s*\(', 'marshal反序列化(不可信数据风险)'),
        (r'shelve\.open\s*\(', 'shelve打开(基于pickle，任意代码执行风险)'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            for pat, desc in self.UNSAFE_PATTERNS:
                if re.search(pat, stripped):
                    findings.append({
                        'event_id': f'PY_UNSAFE_DESERIAL_{i+1}',
                        'line': i+1, 'severity': 'P0',
                        'category': 'PY_DESERIALIZATION',
                        'description': f'{desc}: {stripped[:80]}',
                        'causal_chain': 'P[不可信数据] -> E[反序列化执行__reduce__] -> F[任意代码执行]',
                        'suggestion': '用json替代pickle；yaml用yaml.safe_load'
                    })
                    break
        return findings


class PyCommandInjectionDetector:
    """P0: 命令注入 — os.system / subprocess shell=True / os.popen"""
    INJECTION_PATTERNS = [
        (r'os\.system\s*\(', 'os.system(命令注入风险)'),
        (r'os\.popen\s*\(', 'os.popen(命令注入风险)'),
        (r'shell\s*=\s*True', 'subprocess shell=True(命令注入风险)'),
        (r'os\.exec[vl]p?e?\s*\(', 'os.exec系列(进程替换风险)'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            for pat, desc in self.INJECTION_PATTERNS:
                if re.search(pat, stripped):
                    findings.append({
                        'event_id': f'PY_CMD_INJECT_{i+1}',
                        'line': i+1, 'severity': 'P0',
                        'category': 'PY_INJECTION',
                        'description': f'{desc}: {stripped[:80]}',
                        'causal_chain': 'P[外部输入拼接命令] -> E[shell执行] -> F[任意命令执行]',
                        'suggestion': '用subprocess.run([...], shell=False)，参数列表传递'
                    })
                    break
        return findings


class PyBadZipFileDetector:
    """P0: 损坏文件未捕获 — zipfile操作未捕获BadZipFile
    项目实证: T-17 P0 (identify_subformat未捕获BadZipFile，空文件/伪Excel直接崩溃)
    """
    ZIP_OPEN_PATTERN = re.compile(r'zipfile\.ZipFile\s*\(|openpyxl\.load_workbook\s*\(|pd\.read_excel\s*\(')
    BADZIP_CATCH_PATTERN = re.compile(r'BadZipFile|InvalidFileException|zipfile\.BadZipFile')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if self.ZIP_OPEN_PATTERN.search(stripped):
                # 检查当前行是否在try块内（向前找try，向后找except）
                current_indent = len(line) - len(line.lstrip())
                in_try = False
                has_badzip_catch = False
                # 向前找try（同缩进或更少缩进）
                for j in range(i, max(0, i-20), -1):
                    j_indent = len(lines[j]) - len(lines[j].lstrip())
                    if j_indent <= current_indent and re.search(r'\btry\s*:', lines[j]):
                        in_try = True
                        break
                # 向后找except（同缩进）
                if in_try:
                    for j in range(i+1, min(len(lines), i+30)):
                        j_indent = len(lines[j]) - len(lines[j].lstrip())
                        if j_indent <= current_indent and 'except' in lines[j]:
                            if self.BADZIP_CATCH_PATTERN.search(lines[j]):
                                has_badzip_catch = True
                            # 检查是否是宽泛的except（支持 except Exception / except Exception as e / 裸except）
                            elif re.search(r'except\s*(?:Exception|BaseException)?\s*(?:as\s+\w+)?\s*:', lines[j]):
                                has_badzip_catch = True  # 宽泛except也能捕获BadZipFile
                            break
                if not in_try or not has_badzip_catch:
                    findings.append({
                        'event_id': f'PY_BADZIP_{i+1}',
                        'line': i+1, 'severity': 'P0',
                        'category': 'PY_EXCEPTION',
                        'description': f'zip/excel打开未被BadZipFile捕获，损坏文件将崩溃: {stripped[:80]}',
                        'causal_chain': 'P[损坏xlsx] -> E[BadZipFile未捕获] -> F[程序崩溃]',
                        'suggestion': 'load_workbook放入try块，except中加入zipfile.BadZipFile，返回rejected而非崩溃'
                    })
        return findings


class PyResourceLeakDetector:
    """P1: 资源泄漏 — open()无with且无close
    项目实证: T-10 H-02 (exporter load_workbook后无wb.close())
    """
    OPEN_PATTERN = re.compile(r'(\w+)\s*=\s*open\s*\(')
    LOAD_WORKBOOK_PATTERN = re.compile(r'(\w+)\s*=\s*(?:openpyxl\.)?load_workbook\s*\(')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            # 检查是否在with语句中
            in_with = 'with ' in stripped and ('open(' in stripped or 'load_workbook(' in stripped)
            if in_with:
                continue

            for pat in [self.OPEN_PATTERN, self.LOAD_WORKBOOK_PATTERN]:
                m = pat.search(stripped)
                if m:
                    var = m.group(1)
                    # 检查后续是否有close
                    has_close = False
                    for j in range(i+1, min(len(lines), i+30)):
                        if re.search(rf'{re.escape(var)}\.close\s*\(\s*\)', lines[j]):
                            has_close = True
                            break
                        # 如果遇到函数定义/类定义，认为超出范围
                        if re.match(r'^\s*(def |class )', lines[j]) and not lines[j].startswith(' ' * (len(line) - len(line.lstrip()) + 1)):
                            break
                    if not has_close:
                        findings.append({
                            'event_id': f'PY_RES_LEAK_{i+1}',
                            'line': i+1, 'severity': 'P1',
                            'category': 'PY_RESOURCE',
                            'description': f'文件/工作簿打开后未见close()，可能资源泄漏: {stripped[:80]}',
                            'causal_chain': 'P[open/load_workbook] -> E[无close/无with] -> F[句柄泄漏/文件锁定]',
                            'suggestion': '用with语句自动关闭，或在finally中close()'
                        })
                    break
        return findings


# ============================================================
# P1级: 隐患/不规范/潜在问题
# ============================================================

class PyBroadExceptionDetector:
    """P1: 过宽异常捕获 — except Exception / 裸except
    项目实证: T-10 H-04 / T-16 H-04 (integrate_with_anchor三处except Exception过宽)
    """
    BROAD_PATTERNS = [
        (r'except\s*:', '裸except(捕获所有异常含KeyboardInterrupt)'),
        (r'except\s+Exception\s*(?:as\s+\w+)?\s*:', 'except Exception(过宽，应捕获具体类型)'),
        (r'except\s+BaseException\s*(?:as\s+\w+)?\s*:', 'except BaseException(极宽，含SystemExit)'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            for pat, desc in self.BROAD_PATTERNS:
                if re.search(pat, stripped):
                    # 排除已经是pass的（由SilentExceptionDetector处理P0）
                    if 'pass' in stripped or 'continue' in stripped:
                        continue
                    findings.append({
                        'event_id': f'PY_BROAD_EXCEPT_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PY_EXCEPTION',
                        'description': f'{desc}: {stripped[:80]}',
                        'suggestion': '捕获具体异常类型，如(ValueError, KeyError, OSError)'
                    })
                    break
        return findings


class PyMutableDefaultDetector:
    """P1: 可变默认参数 — def func(x=[]) / def func(x={})"""
    MUTABLE_DEFAULT = re.compile(r'def\s+\w+\s*\([^)]*=\s*(\[\]|\{\}|set\(\))')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            m = self.MUTABLE_DEFAULT.search(stripped)
            if m:
                default = m.group(1)
                findings.append({
                    'event_id': f'PY_MUTABLE_DEFAULT_{i+1}',
                    'line': i+1, 'severity': 'P1',
                    'category': 'PY_BUG',
                    'description': f'可变默认参数{default}，多次调用共享同一对象: {stripped[:80]}',
                    'causal_chain': 'P[默认参数在函数定义时求值] -> E[多次调用共享] -> F[状态污染/数据错乱]',
                    'suggestion': '用None作默认值，函数内初始化: if x is None: x = []'
                })
        return findings


class PyHardcodedPathDetector:
    """P1: 硬编码绝对路径 — frozen EXE中__file__指向临时目录
    项目实证: T-16 H-01 / T-19 H-01 (converter_parser用__file__计算路径，EXE中指向sys._MEIPASS)
    """
    HARDCODED_PATH = re.compile(r'[\'"]?[A-Za-z]:[\\/][^\'"\s)]*[\'"]?')
    FROZEN_SAFE = re.compile(r'sys\.(?:_MEIPASS|executable|frozen)|getattr\s*\(\s*sys')

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        in_docstring = False
        for i, line in enumerate(lines):
            stripped = line.strip()
            # 跟踪三引号文档字符串状态
            triple_count = stripped.count('"""') + stripped.count("'''")
            if triple_count % 2 == 1:
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue
            if stripped.startswith('#'):
                continue
            # 先剥离行内注释，避免注释中的路径误报
            code_part = re.sub(r'#.*$', '', stripped).strip()
            if not code_part:
                continue
            # 排除纯字符串常量赋值（版本号/文档字符串中的路径引用）
            if re.match(r'^[A-Z_][A-Z0-9_]*\s*=\s*[\'"]', code_part):
                continue
            # 排除 __VERSION__ / __BUILD_VERSION__ 等版本常量
            if re.match(r'^__\w+__\s*=', code_part):
                continue
            # 检查是否有硬编码绝对路径
            if self.HARDCODED_PATH.search(code_part):
                # 检查是否有frozen安全处理（前后5行）
                has_frozen_guard = False
                for j in range(max(0, i-5), min(len(lines), i+6)):
                    if self.FROZEN_SAFE.search(lines[j]):
                        has_frozen_guard = True
                        break
                if not has_frozen_guard:
                    findings.append({
                        'event_id': f'PY_HARDCODED_PATH_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PY_PORTABILITY',
                        'description': f'硬编码绝对路径，EXE frozen模式下可能失效: {code_part[:80]}',
                        'causal_chain': 'P[硬编码路径] -> E[EXE中__file__指向_MEIPASS] -> F[资源找不到/数据丢失]',
                        'suggestion': '用getattr(sys, "frozen", False)判断，frozen时用sys._MEIPASS或sys.executable'
                    })
        return findings


class PyDeadCodeDetector:
    """P1: 死代码 — 保存但不调用的变量/方法
    项目实证: T-19 H-04 (self._on_close保存但全文件无调用点)
    """
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        # 检测 self._xxx 赋值但从未使用
        assign_pattern = re.compile(r'self\.(_\w+)\s*=')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            m = assign_pattern.search(stripped)
            if m:
                var = m.group(1)
                # 跳过 __init__ 方法中的赋值（可能是初始化）
                # 检查整个文件中该变量是否被使用（除了赋值行）
                usage_count = 0
                for j, other_line in enumerate(lines):
                    if j == i:
                        continue
                    if f'self.{var}' in other_line and not re.search(rf'self\.{var}\s*=', other_line):
                        usage_count += 1
                if usage_count == 0:
                    findings.append({
                        'event_id': f'PY_DEAD_CODE_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PY_DEAD_CODE',
                        'description': f'self.{var}赋值后从未使用(死代码): {stripped[:80]}',
                        'suggestion': '移除未使用的变量，或补充调用逻辑'
                    })
        return findings


class PyAssertInProductionDetector:
    """P1: assert用于生产校验 — python -O 会被移除"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            if re.match(r'^assert\s+', stripped):
                # 检查是否是测试文件
                findings.append({
                    'event_id': f'PY_ASSERT_{i+1}',
                    'line': i+1, 'severity': 'P1',
                    'category': 'PY_BUG',
                    'description': f'assert用于校验，python -O时被移除: {stripped[:80]}',
                    'causal_chain': 'P[assert校验] -> E[python -O移除] -> F[校验失效]',
                    'suggestion': '生产代码用if+raise显式校验，assert仅用于测试/调试'
                })
        return findings


class PyFinallyReturnDetector:
    """P1: finally块中return — 覆盖异常"""
    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        in_finally = False
        finally_indent = 0
        for i, line in enumerate(lines):
            stripped = line.strip()
            if 'finally:' in stripped:
                in_finally = True
                finally_indent = len(line) - len(line.lstrip())
                continue
            if in_finally:
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= finally_indent and stripped:
                    in_finally = False
                elif stripped.startswith('return ') or stripped == 'return':
                    findings.append({
                        'event_id': f'PY_FINALLY_RETURN_{i+1}',
                        'line': i+1, 'severity': 'P1',
                        'category': 'PY_BUG',
                        'description': f'finally块中return，会覆盖未处理的异常: {stripped[:80]}',
                        'causal_chain': 'P[try中抛异常] -> E[finally return] -> F[异常被静默覆盖]',
                        'suggestion': 'finally中只做清理，不要return'
                    })
        return findings


# ============================================================
# P2/P3级: 代码质量
# ============================================================

class PySqlInjectionDetector:
    """P0/P1: SQL字符串拼接"""
    SQL_PATTERNS = [
        (r'execute\s*\(\s*["\'].*%s.*["\']\s*%', 'SQL字符串%格式化(注入风险)'),
        (r'execute\s*\(\s*["\'].*\+.*["\']', 'SQL字符串+拼接(注入风险)'),
        (r'execute\s*\(\s*f["\']', 'SQL f-string拼接(注入风险)'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            for pat, desc in self.SQL_PATTERNS:
                if re.search(pat, stripped):
                    findings.append({
                        'event_id': f'PY_SQL_INJECT_{i+1}',
                        'line': i+1, 'severity': 'P0',
                        'category': 'PY_INJECTION',
                        'description': f'{desc}: {stripped[:80]}',
                        'causal_chain': 'P[外部输入拼接SQL] -> E[execute执行] -> F[SQL注入/数据泄露]',
                        'suggestion': '用参数化查询: execute("SELECT * WHERE id=?", (user_input,))'
                    })
                    break
        return findings


class PyTodoPlaceholderDetector:
    """P3: TODO/FIXME占位符"""
    TODO_PATTERNS = [
        (r'TODO|FIXME|HACK|XXX', 'TODO/FIXME占位符'),
        (r'暂不实现|待实现|not.implemented', '未实现占位符'),
        # 排除Python常量名 _PLACEHOLDER_xxx = '...'（正常的常量定义）
        (r'(?<!_)placeholder(?!_)|stub(?!\s*=)', '未实现占位符'),
    ]

    def detect(self, source: str) -> List[Dict]:
        findings = []
        lines = source.split('\n')
        for i, line in enumerate(lines):
            for pat, desc in self.TODO_PATTERNS:
                if re.search(pat, line, re.IGNORECASE):
                    findings.append({
                        'event_id': f'PY_TODO_{i+1}',
                        'line': i+1, 'severity': 'P3',
                        'category': 'PY_PLACEHOLDER',
                        'description': f'{desc}: {line.strip()[:80]}',
                        'suggestion': '实现或移除占位标记'
                    })
                    break
        return findings


# ============================================================
# 统一入口
# ============================================================

PY_OPERATORS = [
    PySilentExceptionDetector(),
    PyCodeInjectionDetector(),
    PyUnsafeDeserializationDetector(),
    PyCommandInjectionDetector(),
    PyBadZipFileDetector(),
    PySqlInjectionDetector(),
    PyResourceLeakDetector(),
    PyBroadExceptionDetector(),
    PyMutableDefaultDetector(),
    PyHardcodedPathDetector(),
    PyDeadCodeDetector(),
    PyAssertInProductionDetector(),
    PyFinallyReturnDetector(),
    PyTodoPlaceholderDetector(),
]


def is_python_file(filename: str) -> bool:
    """判断是否为Python文件"""
    return filename.lower().endswith('.py')


def strip_python_comments(source: str) -> str:
    """剥离Python注释（保留字符串中的#）"""
    result = []
    for line in source.split('\n'):
        # 简单处理：行内#前如果不在字符串中则为注释
        in_string = False
        string_char = None
        clean = []
        for ch in line:
            if ch in ('"', "'") and not in_string:
                in_string = True
                string_char = ch
            elif ch == string_char and in_string:
                in_string = False
                string_char = None
            elif ch == '#' and not in_string:
                break
            clean.append(ch)
        result.append(''.join(clean))
    return '\n'.join(result)


def run_python_operators(source_code: str, filename: str = "source.py") -> List[Dict]:
    """运行全部Python算子并返回合并的发现列表"""
    if not is_python_file(filename):
        return []
    # 剥离注释后再检测（避免注释中的模式误报）
    clean_source = strip_python_comments(source_code)
    all_findings = []
    for op in PY_OPERATORS:
        try:
            findings = op.detect(clean_source)
            all_findings.extend(findings)
        except Exception as e:
            all_findings.append({
                'event_id': f'PY_ERROR_{op.__class__.__name__}',
                'line': 0, 'severity': 'INFO',
                'category': 'OPERATOR_ERROR',
                'description': f'Python算子{op.__class__.__name__}执行异常: {e}',
                'suggestion': '检查算子实现'
            })
    return all_findings


__all__ = [
    'PySilentExceptionDetector', 'PyCodeInjectionDetector',
    'PyUnsafeDeserializationDetector', 'PyCommandInjectionDetector',
    'PyBadZipFileDetector', 'PySqlInjectionDetector',
    'PyResourceLeakDetector', 'PyBroadExceptionDetector',
    'PyMutableDefaultDetector', 'PyHardcodedPathDetector',
    'PyDeadCodeDetector', 'PyAssertInProductionDetector',
    'PyFinallyReturnDetector', 'PyTodoPlaceholderDetector',
    'run_python_operators', 'is_python_file', 'strip_python_comments',
    'PY_OPERATORS'
]
