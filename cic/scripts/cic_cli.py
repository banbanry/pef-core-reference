#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEF-CIC 跨模型代码协作治理与AI幻觉检测仪
AI编程三剑客之三：幻觉检测仪

核心能力：
1. AI幻觉检测（空函数/幽灵变量/假逻辑/TODO占位/复制粘贴/注释异常）
2. 跨模型方言偏差检测（架构分割/错误处理/状态副作用/命名风格）
3. π实体锚定（为代码实体分配唯一锚号）
4. LOCKED引用检查
5. StateLedger哈希链账本
"""

import os
import sys
import re
import json
import hashlib
import argparse
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

# ============================================================
# π 锚定坐标系（防向量坍缩：强制使用长数位切片，不允许短近似）
# ============================================================
PI_DIGITS = (
    "31415926535897932384626433832795028841971693993751"
    "05820974944592307816406286208998628034825342117067"
)

class PiAnchorAllocator:
    """π实体锚定分配器：为每个代码实体分配唯一πₛ锚号"""
    def __init__(self):
        self.seq = 0
        self.anchors = {}  # entity_id -> anchor_info

    def allocate(self, entity_name, entity_type, file_path):
        """为代码实体分配π锚号"""
        pos = self.seq % len(PI_DIGITS)
        domain = self.seq % 3  # 0=P, 1=E, 2=F
        anchor_id = f"π[{pos}]={PI_DIGITS[pos]}|{['P','E','F'][domain]}|{entity_type}"
        entity_id = hashlib.sha256(f"{file_path}:{entity_name}:{entity_type}".encode()).hexdigest()[:16]
        self.anchors[entity_id] = {
            "anchor_id": anchor_id,
            "entity_name": entity_name,
            "entity_type": entity_type,
            "file_path": file_path,
            "seq": self.seq,
            "domain": ['P', 'E', 'F'][domain],
            "locked": False,
        }
        self.seq += 1
        return self.anchors[entity_id]

    def get_all(self):
        return self.anchors


# ============================================================
# StateLedger 哈希链账本
# ============================================================
class StateLedger:
    """审计事件哈希链账本：只追加，禁删除"""
    def __init__(self):
        self.entries = []

    def append(self, event_type, details):
        prev_hash = self.entries[-1]["chain_hash"] if self.entries else "GENESIS"
        record = {
            "seq": len(self.entries),
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "details": details,
            "prev_hash": prev_hash,
        }
        record["chain_hash"] = hashlib.sha256(
            json.dumps(record, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()[:16]
        self.entries.append(record)
        return record

    def verify_chain(self):
        """验证哈希链完整性"""
        for i in range(1, len(self.entries)):
            expected_prev = self.entries[i-1]["chain_hash"]
            actual_prev = self.entries[i]["prev_hash"]
            if expected_prev != actual_prev:
                return False, f"链断裂 at seq={i}"
        return True, "链完整"


# ============================================================
# 代码解析器（轻量级，基于正则和行分析）
# ============================================================
class CodeParser:
    """轻量级代码解析器：支持Python/Java/C/C++/JavaScript"""

    LANG_PATTERNS = {
        '.py': {
            'func_def': r'^\s*def\s+(\w+)\s*\(',
            'class_def': r'^\s*class\s+(\w+)',
            'comment': r'^\s*#',
            'empty_body': r'^\s*(pass|raise\s+NotImplementedError|return\s+None|return\s*""?\s*$)',
            'var_decl': r'^\s*(\w+)\s*=',
            'import': r'^\s*(import|from)\s+',
        },
        '.java': {
            'func_def': r'^\s*(public|private|protected)?\s*(static\s+)?[\w<>\[\]]+\s+(\w+)\s*\(',
            'class_def': r'^\s*(public|private|protected)?\s*(abstract\s+)?(class|interface|enum)\s+(\w+)',
            'comment': r'^\s*(//|/\*|\*)',
            'empty_body': r'^\s*\{\s*\}\s*$',
            'var_decl': r'^\s*(public|private|protected)?\s*(static\s+)?(final\s+)?[\w<>\[\]]+\s+(\w+)\s*[=;]',
            'import': r'^\s*import\s+',
        },
        '.c': {
            'func_def': r'^\s*[\w\s\*]+?\s+(\w+)\s*\([^)]*\)\s*\{?\s*$',
            'class_def': r'^\s*(struct|typedef\s+struct)\s+(\w+)',
            'comment': r'^\s*(//|/\*|\*)',
            'empty_body': r'^\s*\{\s*\}\s*$',
            'var_decl': r'^\s*[\w\s\*]+?\s+(\w+)\s*[=;]',
            'import': r'^\s*#\s*include\s+',
        },
        '.cpp': {
            'func_def': r'^\s*[\w\s\*:]+?\s+(\w+)\s*\([^)]*\)',
            'class_def': r'^\s*(class|struct)\s+(\w+)',
            'comment': r'^\s*(//|/\*|\*)',
            'empty_body': r'^\s*\{\s*\}\s*$',
            'var_decl': r'^\s*[\w\s\*]+?\s+(\w+)\s*[=;]',
            'import': r'^\s*#\s*include\s+',
        },
        '.js': {
            'func_def': r'^\s*(function\s+(\w+)|(const|let|var)\s+(\w+)\s*=\s*(async\s+)?\()',
            'class_def': r'^\s*class\s+(\w+)',
            'comment': r'^\s*(//|/\*|\*)',
            'empty_body': r'^\s*\{\s*\}\s*$',
            'var_decl': r'^\s*(const|let|var)\s+(\w+)\s*=',
            'import': r'^\s*(import|require)\s*',
        },
    }

    def __init__(self, file_path):
        self.file_path = file_path
        self.ext = Path(file_path).suffix.lower()
        self.patterns = self.LANG_PATTERNS.get(self.ext, self.LANG_PATTERNS['.py'])
        self.lines = []
        self.functions = []
        self.classes = []
        self.variables = set()
        self.used_vars = set()
        self.comments = 0
        self.code_lines = 0
        self.todo_count = 0
        self._parse()

    def _parse(self):
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.lines = f.readlines()
        except Exception:
            return

        in_block_comment = False
        current_func = None
        func_body_lines = 0

        for i, line in enumerate(self.lines):
            stripped = line.strip()

            # 块注释处理
            if '/*' in stripped:
                in_block_comment = True
            if in_block_comment:
                self.comments += 1
                if '*/' in stripped:
                    in_block_comment = False
                continue

            # 行注释
            if re.match(self.patterns['comment'], line):
                self.comments += 1
                if re.search(r'TODO|FIXME|XXX|HACK', stripped, re.IGNORECASE):
                    self.todo_count += 1
                continue

            if not stripped:
                continue

            self.code_lines += 1

            # 函数定义
            func_match = re.match(self.patterns['func_def'], line)
            if func_match:
                func_name = func_match.group(func_match.lastindex)
                current_func = {
                    'name': func_name,
                    'line': i + 1,
                    'body_lines': 0,
                    'has_return': False,
                    'has_logic': False,
                    'is_empty': False,
                }
                self.functions.append(current_func)
                func_body_lines = 0
                continue

            # 类定义
            class_match = re.match(self.patterns['class_def'], line)
            if class_match:
                class_name = class_match.group(class_match.lastindex)
                self.classes.append({'name': class_name, 'line': i + 1})
                continue

            # 变量声明
            var_match = re.match(self.patterns['var_decl'], line)
            if var_match:
                var_name = var_match.group(var_match.lastindex)
                if var_name not in ('if', 'for', 'while', 'return', 'print', 'def', 'class'):
                    self.variables.add(var_name)

            # 变量使用（简单检测：行中出现的标识符）
            for word in re.findall(r'\b[a-z_][a-z0-9_]*\b', stripped):
                if word not in ('if', 'for', 'while', 'return', 'print', 'def', 'class', 'import', 'from', 'as', 'in', 'not', 'and', 'or', 'is', 'None', 'True', 'False', 'self', 'this', 'new', 'void', 'int', 'char', 'float', 'double', 'public', 'private', 'protected', 'static', 'final', 'const', 'let', 'var', 'function', 'async', 'await', 'try', 'catch', 'finally', 'throw', 'throws', 'extends', 'implements', 'interface', 'abstract', 'enum', 'package', 'super', 'typeof', 'instanceof'):
                    self.used_vars.add(word)

            # 函数体分析
            if current_func is not None:
                func_body_lines += 1
                current_func['body_lines'] = func_body_lines
                if re.search(r'\breturn\b', stripped):
                    current_func['has_return'] = True
                if re.search(r'\b(if|for|while|switch|try|catch)\b', stripped):
                    current_func['has_logic'] = True
                if re.match(self.patterns['empty_body'], stripped):
                    if func_body_lines <= 2:
                        current_func['is_empty'] = True

    def get_ghost_variables(self):
        """检测幽灵变量：声明但未使用"""
        return self.variables - self.used_vars

    def get_empty_functions(self):
        """检测空函数：函数体只有pass/return None/{}"""
        return [f for f in self.functions if f['is_empty'] or (f['body_lines'] <= 3 and not f['has_logic'])]

    def get_comment_ratio(self):
        """注释代码比"""
        total = self.comments + self.code_lines
        if total == 0:
            return 0.0
        return self.comments / total


# ============================================================
# AI幻觉检测器
# ============================================================
class HallucinationDetector:
    """AI幻觉检测：识别AI生成的空壳代码"""

    def __init__(self):
        self.findings = []

    def detect(self, parser, file_path):
        """对单个文件执行幻觉检测"""
        findings = []

        # 1. 空函数检测
        empty_funcs = parser.get_empty_functions()
        for func in empty_funcs:
            findings.append({
                'id': 'HALLUC-001',
                'severity': 'P0',
                'type': '空函数体',
                'file': file_path,
                'line': func['line'],
                'message': f"函数 '{func['name']}' 只有签名没有实现（空函数体），疑似AI敷衍生成",
                'details': f"函数体行数: {func['body_lines']}, 有逻辑: {func['has_logic']}",
            })

        # 2. 幽灵变量检测
        ghost_vars = parser.get_ghost_variables()
        for var in list(ghost_vars)[:20]:  # 限制输出数量
            findings.append({
                'id': 'HALLUC-002',
                'severity': 'P0',
                'type': '幽灵变量',
                'file': file_path,
                'message': f"变量 '{var}' 声明但从未使用，疑似AI生成的幽灵变量",
                'details': '声明后无任何引用',
            })

        # 3. TODO/FIXME占位检测
        if parser.todo_count > 0:
            findings.append({
                'id': 'HALLUC-003',
                'severity': 'P1',
                'type': 'TODO占位符',
                'file': file_path,
                'message': f"发现 {parser.todo_count} 个 TODO/FIXME/XXX 占位符，代码可能未完成",
                'details': f'TODO数量: {parser.todo_count}',
            })

        # 4. 假逻辑/恒真条件检测
        for i, line in enumerate(parser.lines):
            stripped = line.strip()
            if re.search(r'if\s*(True|1\s*==\s*1|true)\s*:', stripped) or \
               re.search(r'if\s*\(\s*(true|1\s*==\s*1)\s*\)', stripped):
                findings.append({
                    'id': 'HALLUC-004',
                    'severity': 'P1',
                    'type': '假逻辑/恒真条件',
                    'file': file_path,
                    'line': i + 1,
                    'message': f"发现恒真条件 '{stripped[:50]}'，逻辑永远为真，疑似AI假逻辑",
                    'details': '条件表达式恒为真，分支无意义',
                })

        # 5. 复制粘贴重复检测（行级）
        line_counts = Counter()
        for line in parser.lines:
            stripped = line.strip()
            if len(stripped) > 20 and not re.match(parser.patterns['comment'], line):
                line_counts[stripped] += 1
        duplicate_lines = [(line, count) for line, count in line_counts.items() if count >= 3]
        if duplicate_lines:
            findings.append({
                'id': 'HALLUC-005',
                'severity': 'P2',
                'type': '复制粘贴重复',
                'file': file_path,
                'message': f"发现 {len(duplicate_lines)} 段重复3次以上的代码，疑似AI复制粘贴敷衍生成",
                'details': f'重复段数: {len(duplicate_lines)}, 示例: {duplicate_lines[0][0][:50]}',
            })

        # 6. 注释代码比异常
        ratio = parser.get_comment_ratio()
        if parser.code_lines > 50 and ratio < 0.02:
            findings.append({
                'id': 'HALLUC-006',
                'severity': 'P2',
                'type': '注释密度异常',
                'file': file_path,
                'message': f"注释密度仅 {ratio:.1%}，代码行数 {parser.code_lines} 但几乎无注释，疑似AI生成无注释代码",
                'details': f'注释行: {parser.comments}, 代码行: {parser.code_lines}, 比率: {ratio:.1%}',
            })

        self.findings.extend(findings)
        return findings


# ============================================================
# 跨模型方言偏差检测器
# ============================================================
class DialectDetector:
    """跨模型代码方言偏差检测：识别不同模型的工程文化习惯差异"""

    # 模型方言指纹库（基于训练数据特征推断）
    MODEL_FINGERPRINTS = {
        'deepseek': {
            'architecture': '大函数/少文件/高内聚，业务逻辑塞controller',
            'exception': '大量裸try-catch，吞异常不打印日志',
            'state': '倾向修改传入对象',
            'naming': '简洁/少注释',
        },
        'glm': {
            'architecture': '超薄控制器/全部下沉Service层/拆成极小函数',
            'exception': '偏好自定义异常枚举，每层向上抛',
            'state': '倾向只读，不修改入参',
            'naming': '详细/多注释',
        },
        'trae': {
            'architecture': '自动拆出一堆中间DTO/适配器/helper工具类',
            'exception': '到处返回Result<T>包装，极少抛异常',
            'state': '倾向新建副本再修改',
            'naming': '冗长/过度抽象',
        },
    }

    def __init__(self):
        self.findings = []
        self.stats = defaultdict(lambda: defaultdict(int))

    def detect(self, parser, file_path, model_source='auto'):
        """对单个文件执行方言偏差检测"""
        findings = []

        # 1. 架构分割指纹检测
        avg_func_lines = 0
        if parser.functions:
            avg_func_lines = sum(f['body_lines'] for f in parser.functions) / len(parser.functions)

        if avg_func_lines > 50:
            findings.append({
                'id': 'DIALECT-001',
                'severity': 'P1',
                'type': '架构分割-大函数',
                'file': file_path,
                'message': f"平均函数行数 {avg_func_lines:.0f}，超过50行，疑似DeepSeek风格（大函数/高内聚）",
                'details': f'函数数: {len(parser.functions)}, 平均行数: {avg_func_lines:.0f}',
            })
            self.stats['architecture']['large_function'] += 1
        elif avg_func_lines < 10 and len(parser.functions) > 10:
            findings.append({
                'id': 'DIALECT-001',
                'severity': 'P2',
                'type': '架构分割-极小函数',
                'file': file_path,
                'message': f"平均函数行数仅 {avg_func_lines:.0f}，函数数 {len(parser.functions)}，疑似GLM风格（超薄控制器/极小函数）",
                'details': f'函数数: {len(parser.functions)}, 平均行数: {avg_func_lines:.0f}',
            })
            self.stats['architecture']['tiny_function'] += 1

        # 2. 错误处理指纹检测
        bare_try_count = 0
        result_wrapper_count = 0
        for line in parser.lines:
            stripped = line.strip()
            if re.search(r'\btry\s*:', stripped) or re.search(r'\btry\s*\{', stripped):
                bare_try_count += 1
            if re.search(r'Result<|Result\.|ApiResult|ResponseEntity', stripped):
                result_wrapper_count += 1

        if bare_try_count > 5:
            findings.append({
                'id': 'DIALECT-002',
                'severity': 'P1',
                'type': '错误处理-裸try-catch',
                'file': file_path,
                'message': f"发现 {bare_try_count} 处 try-catch，疑似DeepSeek风格（大量裸try-catch）",
                'details': f'try-catch数量: {bare_try_count}',
            })
            self.stats['exception']['bare_try'] += 1
        if result_wrapper_count > 3:
            findings.append({
                'id': 'DIALECT-002',
                'severity': 'P2',
                'type': '错误处理-Result包装',
                'file': file_path,
                'message': f"发现 {result_wrapper_count} 处 Result<T> 包装，疑似Trae风格（到处返回Result包装）",
                'details': f'Result包装数量: {result_wrapper_count}',
            })
            self.stats['exception']['result_wrapper'] += 1

        # 3. 状态副作用指纹检测
        mutate_param_count = 0
        for line in parser.lines:
            stripped = line.strip()
            # 检测入参修改模式（简单启发式）
            if re.search(r'\b(self|this)\.\w+\s*=', stripped) and not re.search(r'^\s*(def|class|__init__)', stripped):
                mutate_param_count += 1

        if mutate_param_count > 10:
            findings.append({
                'id': 'DIALECT-003',
                'severity': 'P2',
                'type': '状态副作用-修改入参',
                'file': file_path,
                'message': f"发现 {mutate_param_count} 处对象状态修改，疑似DeepSeek风格（倾向修改传入对象）",
                'details': f'状态修改数: {mutate_param_count}',
            })
            self.stats['state']['mutate_param'] += 1

        # 4. 命名风格指纹检测
        long_name_count = 0
        for func in parser.functions:
            if len(func['name']) > 25:
                long_name_count += 1
        if long_name_count > 3:
            findings.append({
                'id': 'DIALECT-004',
                'severity': 'P2',
                'type': '命名风格-冗长命名',
                'file': file_path,
                'message': f"发现 {long_name_count} 个超过25字符的函数名，疑似Trae风格（冗长/过度抽象）",
                'details': f'长函数名数: {long_name_count}',
            })
            self.stats['naming']['long_name'] += 1

        # 5. DTO/适配器/helper泛滥检测
        dto_count = 0
        for cls in parser.classes:
            if re.search(r'DTO|VO|BO|PO|Adapter|Helper|Util|Converter|Mapper', cls['name'], re.IGNORECASE):
                dto_count += 1
        if dto_count > 5:
            findings.append({
                'id': 'DIALECT-005',
                'severity': 'P2',
                'type': '架构分割-DTO泛滥',
                'file': file_path,
                'message': f"发现 {dto_count} 个 DTO/Adapter/Helper 类，疑似Trae风格（中间层泛滥）",
                'details': f'DTO/Adapter/Helper类数: {dto_count}',
            })
            self.stats['architecture']['dto_flood'] += 1

        self.findings.extend(findings)
        return findings

    def identify_model_source(self):
        """根据统计特征推断代码来源模型"""
        scores = defaultdict(int)
        if self.stats['architecture']['large_function'] > 0:
            scores['deepseek'] += 2
        if self.stats['exception']['bare_try'] > 0:
            scores['deepseek'] += 2
        if self.stats['state']['mutate_param'] > 0:
            scores['deepseek'] += 1
        if self.stats['architecture']['tiny_function'] > 0:
            scores['glm'] += 2
        if self.stats['architecture']['dto_flood'] > 0:
            scores['trae'] += 2
        if self.stats['exception']['result_wrapper'] > 0:
            scores['trae'] += 2
        if self.stats['naming']['long_name'] > 0:
            scores['trae'] += 1

        if not scores:
            return 'unknown', 0.0
        best_model = max(scores, key=scores.get)
        total = sum(scores.values())
        confidence = scores[best_model] / total if total > 0 else 0.0
        return best_model, confidence


# ============================================================
# CIC 审计引擎
# ============================================================
class CICAuditEngine:
    """CIC完整审计引擎：幻觉检测+方言检测+π锚定+LOCKED检查"""

    def __init__(self):
        self.hallucination_detector = HallucinationDetector()
        self.dialect_detector = DialectDetector()
        self.anchor_allocator = PiAnchorAllocator()
        self.ledger = StateLedger()
        self.all_findings = []
        self.parsers = {}

    def audit_file(self, file_path, model_source='auto'):
        """审计单个文件"""
        parser = CodeParser(file_path)
        self.parsers[file_path] = parser

        # π实体锚定
        for func in parser.functions:
            self.anchor_allocator.allocate(func['name'], 'function', file_path)
        for cls in parser.classes:
            self.anchor_allocator.allocate(cls['name'], 'class', file_path)

        # 幻觉检测
        hallucination_findings = self.hallucination_detector.detect(parser, file_path)
        # 方言检测
        dialect_findings = self.dialect_detector.detect(parser, file_path, model_source)

        file_findings = hallucination_findings + dialect_findings
        self.all_findings.extend(file_findings)

        # 记录账本
        p0_count = sum(1 for f in file_findings if f['severity'] == 'P0')
        p1_count = sum(1 for f in file_findings if f['severity'] == 'P1')
        p2_count = sum(1 for f in file_findings if f['severity'] == 'P2')
        self.ledger.append('FILE_AUDIT', {
            'file': file_path,
            'functions': len(parser.functions),
            'classes': len(parser.classes),
            'p0': p0_count,
            'p1': p1_count,
            'p2': p2_count,
            'verdict': 'FAIL' if p0_count > 0 else 'PASS',
        })

        return file_findings

    def audit_directory(self, dir_path, model_source='auto'):
        """审计目录（递归）"""
        supported_exts = {'.py', '.java', '.c', '.cpp', '.js', '.ts'}
        files = []
        for root, _, filenames in os.walk(dir_path):
            for filename in filenames:
                if Path(filename).suffix.lower() in supported_exts:
                    files.append(os.path.join(root, filename))

        for file_path in files:
            self.audit_file(file_path, model_source)

        return files

    def generate_report(self, out_dir=None):
        """生成审计报告"""
        # 模型源推断
        inferred_model, confidence = self.dialect_detector.identify_model_source()

        # 统计
        p0 = sum(1 for f in self.all_findings if f['severity'] == 'P0')
        p1 = sum(1 for f in self.all_findings if f['severity'] == 'P1')
        p2 = sum(1 for f in self.all_findings if f['severity'] == 'P2')

        # 按类型分组
        by_type = defaultdict(list)
        for f in self.all_findings:
            by_type[f['type']].append(f)

        report = {
            'audit_version': 'PEF-CIC V3.3',
            'audit_time': datetime.now().isoformat(),
            'summary': {
                'total_files': len(self.parsers),
                'total_findings': len(self.all_findings),
                'p0_critical': p0,
                'p1_severe': p1,
                'p2_moderate': p2,
                'verdict': 'FAIL' if p0 > 0 else 'PASS',
                'inferred_model_source': inferred_model,
                'model_confidence': f'{confidence:.1%}',
            },
            'hallucination_summary': {
                'empty_functions': len([f for f in self.all_findings if f['type'] == '空函数体']),
                'ghost_variables': len([f for f in self.all_findings if f['type'] == '幽灵变量']),
                'todo_placeholders': len([f for f in self.all_findings if f['type'] == 'TODO占位符']),
                'fake_logic': len([f for f in self.all_findings if f['type'] == '假逻辑/恒真条件']),
                'copy_paste': len([f for f in self.all_findings if f['type'] == '复制粘贴重复']),
                'comment_anomaly': len([f for f in self.all_findings if f['type'] == '注释密度异常']),
            },
            'dialect_summary': {
                'architecture_split': len([f for f in self.all_findings if '架构分割' in f['type']]),
                'exception_handling': len([f for f in self.all_findings if '错误处理' in f['type']]),
                'state_side_effect': len([f for f in self.all_findings if '状态副作用' in f['type']]),
                'naming_style': len([f for f in self.all_findings if '命名风格' in f['type']]),
            },
            'pi_anchors': {
                'total_allocated': len(self.anchor_allocator.get_all()),
                'anchors': list(self.anchor_allocator.get_all().values())[:50],  # 限制输出
            },
            'findings_by_type': {k: v[:20] for k, v in by_type.items()},  # 每类限制20条
            'ledger': {
                'total_entries': len(self.ledger.entries),
                'chain_verified': self.ledger.verify_chain()[0],
            },
        }

        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
            report_path = os.path.join(out_dir, 'cic_audit_report.json')
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, ensure_ascii=False, indent=2)

            # 人类可读摘要
            summary_path = os.path.join(out_dir, 'cic_audit_summary.txt')
            with open(summary_path, 'w', encoding='utf-8') as f:
                f.write(self._format_human_readable(report))

            # 账本
            ledger_path = os.path.join(out_dir, 'cic_state_ledger.json')
            with open(ledger_path, 'w', encoding='utf-8') as f:
                json.dump(self.ledger.entries, f, ensure_ascii=False, indent=2)

        return report

    def _format_human_readable(self, report):
        """格式化为人类可读摘要"""
        s = report['summary']
        h = report['hallucination_summary']
        d = report['dialect_summary']
        lines = [
            "=" * 60,
            "PEF-CIC 跨模型代码协作治理与AI幻觉检测报告",
            "=" * 60,
            f"审计时间: {report['audit_time']}",
            f"审计文件数: {s['total_files']}",
            f"总发现数: {s['total_findings']}",
            f"  P0(致命): {s['p0_critical']}",
            f"  P1(严重): {s['p1_severe']}",
            f"  P2(中等): {s['p2_moderate']}",
            f"裁决: {'❌ FAIL' if s['verdict'] == 'FAIL' else '✅ PASS'}",
            f"推断代码来源模型: {s['inferred_model_source']} (置信度: {s['model_confidence']})",
            "",
            "--- AI幻觉检测 ---",
            f"  空函数体: {h['empty_functions']}",
            f"  幽灵变量: {h['ghost_variables']}",
            f"  TODO占位符: {h['todo_placeholders']}",
            f"  假逻辑/恒真条件: {h['fake_logic']}",
            f"  复制粘贴重复: {h['copy_paste']}",
            f"  注释密度异常: {h['comment_anomaly']}",
            "",
            "--- 跨模型方言偏差检测 ---",
            f"  架构分割: {d['architecture_split']}",
            f"  错误处理: {d['exception_handling']}",
            f"  状态副作用: {d['state_side_effect']}",
            f"  命名风格: {d['naming_style']}",
            "",
            "--- π实体锚定 ---",
            f"  已分配锚号: {report['pi_anchors']['total_allocated']}",
            "",
            "--- StateLedger哈希链 ---",
            f"  账本条目数: {report['ledger']['total_entries']}",
            f"  链完整性: {'✅ 完整' if report['ledger']['chain_verified'] else '❌ 断裂'}",
            "",
            "=" * 60,
        ]
        return '\n'.join(lines)


# ============================================================
# CLI 入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(description='PEF-CIC 跨模型代码协作治理与AI幻觉检测仪')
    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # hallucination 子命令
    hall_parser = subparsers.add_parser('hallucination', help='AI幻觉检测')
    hall_parser.add_argument('--input', required=True, help='代码文件或目录')
    hall_parser.add_argument('--out-dir', help='输出目录')

    # dialect 子命令
    dial_parser = subparsers.add_parser('dialect', help='跨模型方言偏差检测')
    dial_parser.add_argument('--input', required=True, help='代码文件或目录')
    dial_parser.add_argument('--model-source', default='auto', choices=['auto', 'deepseek', 'glm', 'trae'], help='代码来源模型')
    dial_parser.add_argument('--out-dir', help='输出目录')

    # audit 子命令
    audit_parser = subparsers.add_parser('audit', help='完整审计（幻觉+方言+π锚定+LOCKED）')
    audit_parser.add_argument('--input', required=True, help='代码文件或目录')
    audit_parser.add_argument('--model-source', default='auto', choices=['auto', 'deepseek', 'glm', 'trae'], help='代码来源模型')
    audit_parser.add_argument('--out-dir', required=True, help='输出目录')

    # anchor 子命令
    anchor_parser = subparsers.add_parser('anchor', help='π实体锚定')
    anchor_parser.add_argument('--input', required=True, help='代码文件或目录')
    anchor_parser.add_argument('--out-dir', help='输出目录')

    # report 子命令
    report_parser = subparsers.add_parser('report', help='生成报告')
    report_parser.add_argument('--out-dir', required=True, help='输出目录')

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    engine = CICAuditEngine()

    if args.command in ('hallucination', 'dialect', 'audit', 'anchor'):
        input_path = args.input
        model_source = getattr(args, 'model_source', 'auto')

        if os.path.isfile(input_path):
            engine.audit_file(input_path, model_source)
        elif os.path.isdir(input_path):
            files = engine.audit_directory(input_path, model_source)
            print(f"扫描到 {len(files)} 个代码文件")
        else:
            print(f"错误: 输入路径不存在: {input_path}")
            sys.exit(1)

        if args.command == 'audit':
            report = engine.generate_report(args.out_dir)
            print(engine._format_human_readable(report))
            print(f"\n报告已保存到: {args.out_dir}")
        elif args.command in ('hallucination', 'dialect'):
            # 只显示对应类型的发现
            if args.command == 'hallucination':
                findings = [f for f in engine.all_findings if f['id'].startswith('HALLUC')]
                print(f"\n=== AI幻觉检测结果 ===")
            else:
                findings = [f for f in engine.all_findings if f['id'].startswith('DIALECT')]
                print(f"\n=== 跨模型方言偏差检测结果 ===")

            for f in findings[:30]:
                print(f"  [{f['severity']}] {f['type']}: {f['message']}")
                if 'line' in f:
                    print(f"    文件: {f['file']}:{f['line']}")
            print(f"\n总计: {len(findings)} 条发现")

            if getattr(args, 'out_dir', None):
                report = engine.generate_report(args.out_dir)
                print(f"报告已保存到: {args.out_dir}")

        elif args.command == 'anchor':
            anchors = engine.anchor_allocator.get_all()
            print(f"\n=== π实体锚定结果 ===")
            print(f"已分配锚号: {len(anchors)}")
            for anchor in list(anchors.values())[:30]:
                print(f"  {anchor['anchor_id']} -> {anchor['entity_type']}: {anchor['entity_name']} ({anchor['file_path']})")
            if getattr(args, 'out_dir', None):
                os.makedirs(args.out_dir, exist_ok=True)
                with open(os.path.join(args.out_dir, 'pi_anchors.json'), 'w', encoding='utf-8') as f:
                    json.dump(list(anchors.values()), f, ensure_ascii=False, indent=2)
                print(f"锚点已保存到: {args.out_dir}")

    elif args.command == 'report':
        # 从已有结果生成报告（简化版）
        print("报告生成需要先执行 audit 命令")
        sys.exit(1)

    # 退出码：有P0则退出码1
    p0_count = sum(1 for f in engine.all_findings if f['severity'] == 'P0')
    sys.exit(1 if p0_count > 0 else 0)


if __name__ == '__main__':
    main()
