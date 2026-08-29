#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEF自检清单 — PEF_SelfCheckList
==============================
12项PEF合规性自检清单。
"""


class PEF_SelfCheckList:
    """PEF合规性自检清单（12项）。"""

    def __init__(self):
        self.items = []
        self._results = []

    def check(self, name: str, passed: bool, detail: str = ''):
        """添加自检项。"""
        self._results.append({
            'name': name,
            'passed': passed,
            'detail': detail,
        })

    def report(self) -> str:
        """生成自检报告文本。"""
        if not self._results:
            return '无自检项'
        lines = []
        lines.append('=' * 60)
        lines.append('PEF 自检清单报告')
        lines.append('=' * 60)
        passed_count = sum(1 for r in self._results if r['passed'])
        for r in self._results:
            status = '✓ PASS' if r['passed'] else '✗ FAIL'
            lines.append(f'  [{status}] {r["name"]}')
            if r['detail']:
                lines.append(f'          {r["detail"]}')
        lines.append('-' * 60)
        lines.append(f'总计: {len(self._results)} 项 | 通过: {passed_count} | 失败: {len(self._results) - passed_count}')
        lines.append('=' * 60)
        return '\n'.join(lines)

    def all_passed(self) -> bool:
        return all(r['passed'] for r in self._results)