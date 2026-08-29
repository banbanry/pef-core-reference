#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置加载器 — PEF框架配置加载
============================
"""
import json
import os
from typing import Any, Dict

_FRAMEWORK_CONFIG_CACHE = None


def _find_config_dir() -> str:
    """定位 config 目录（相对 PEF_Core 父目录）。"""
    core_dir = os.path.dirname(os.path.abspath(__file__))
    parent = os.path.dirname(core_dir)
    config_dir = os.path.join(parent, 'config')
    if os.path.isdir(config_dir):
        return config_dir
    return parent


def load_framework_config() -> Dict[str, Any]:
    """加载框架全局配置（带缓存，进程内只加载一次）。"""
    global _FRAMEWORK_CONFIG_CACHE
    if _FRAMEWORK_CONFIG_CACHE is not None:
        return _FRAMEWORK_CONFIG_CACHE
    config_path = os.path.join(_find_config_dir(), 'framework_config.json')
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            _FRAMEWORK_CONFIG_CACHE = json.load(f)
    else:
        _FRAMEWORK_CONFIG_CACHE = {}
    return _FRAMEWORK_CONFIG_CACHE


def clear_framework_config_cache():
    """清空框架配置缓存（测试用）。"""
    global _FRAMEWORK_CONFIG_CACHE
    _FRAMEWORK_CONFIG_CACHE = None