#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""语义错误异常 — PEF内核专用异常类"""


class SemanticError(Exception):
    """语义错误：当数据无法映射为PEFmod时抛出。"""
    pass