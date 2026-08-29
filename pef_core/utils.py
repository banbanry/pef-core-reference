#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEF内核工具函数 — 字符串清洗、输入校验、日志操作
================================================
"""
import re
import os
import json as _json
import threading as _threading
import unicodedata
import numpy as np
import pandas as pd
from datetime import datetime

# 全角→半角转换表
_FW_TRANS = str.maketrans(
    'ＡＢＣＤＥＦＧＨＩＪＫＬＭＮＯＰＱＲＳＴＵＶＷＸＹＺａｂｃｄｅｆｇｈｉｊｋｌｍｎｏｐｑｒｓｔｕｖｗｘｙｚ０１２３４５６７８９（）',
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789()')
_VALID_NA_TOKENS = {'na', 'n/a', 'n.a', 'not applicable'}


def is_valid_na_token(s) -> bool:
    """业务占位符 NA/N/A/N.A./Not Applicable 视为有效数据。"""
    if not isinstance(s, str):
        return False
    return s.strip().lower().rstrip('.') in _VALID_NA_TOKENS


def string_normalize(s) -> str:
    """统一字符串清洗：None/nan/NaT/NA→''，全角→半角，中文括号→英文括号。"""
    if s is None or (isinstance(s, float) and s != s):
        return ''
    # BUG-NaT-001（2026-08-16，用户授权的内核语义修改）：
    # pd.NaT / pd.NA / numpy NaT 此前被 str() 化为 'NaT'/'<NA>' 脏字符串
    # （进口归档"送达日期"列 52 处脏数据根因），统一归 ''。必须用 is 判定——
    # pd.NA 的 == 比较返回 NA 而非 bool，用 == 会抛 TypeError。
    if s is pd.NaT or s is pd.NA:
        return ''
    if isinstance(s, (np.datetime64, np.timedelta64)) and np.isnat(s):
        return ''
    if isinstance(s, str):
        s_stripped = s.strip()
        if s_stripped == '':
            return ''
        if s_stripped.lower() == 'nan' and (not is_valid_na_token(s_stripped)):
            return ''
        s = s_stripped
    else:
        try:
            s = str(s).strip()
        except Exception:
            return ''
    s = s.translate(_FW_TRANS)
    return s.replace('（', '(').replace('）', ')')


def norm_col(c) -> str:
    """列名归一化：全角→半角、换行→空格、多余空白压缩。"""
    c = string_normalize(c).replace('\n', ' ').replace('\r', ' ')
    return re.sub(r'\s+', ' ', c).strip()


def is_blank(v) -> bool:
    """判断值是否为空（None/NaN/空字符串视为空，NA视为有效）。"""
    if v is None:
        return True
    if isinstance(v, float) and np.isnan(v):
        return True
    s = string_normalize(v)
    if s == '':
        return True
    if is_valid_na_token(s):
        return False
    return s.lower() == 'nan'


def cmp_val(col: str, v) -> str:
    """值比较归一化：日期列去除非数字字符，其他列做字符串归一化。
    【残留污染标记】'接单时间'等业务列名待 smoke_test.py 导入授权后迁往业务层。"""
    if col in ('接单时间', '提货日期', '送达日期'):
        return re.sub('[^0-9]', '', str(v))[:8]
    return string_normalize(v)


def clean_input(value, max_length=255, field_type='general'):
    """统一外部输入清洗：长度限制+非法字符过滤+异常数值拦截。"""
    if value is None:
        return ''
    if isinstance(value, float) and np.isnan(value):
        return ''
    # BUG-NaT-001：与 string_normalize 同族的 NaT/NA 泄漏预防（str() 化前拦截）
    if value is pd.NaT or value is pd.NA:
        return ''
    if isinstance(value, (np.datetime64, np.timedelta64)) and np.isnat(value):
        return ''
    s = str(value)
    s = ''.join((ch for ch in s if ch == '\n' or ch == '\t' or
                 unicodedata.category(ch)[0] != 'C'))
    s = s.strip()
    if s.lower() == 'nan' and (not is_valid_na_token(s)):
        return ''
    if field_type == 'numeric':
        m = re.search(r'-?\d+(?:\.\d+)?', s)
        s = m.group(0) if m else ''
        s = re.sub('[^0-9\\.\\-]', '', s)
        try:
            if s and float(s) < 0:
                s = ''
        except ValueError:
            pass
    elif field_type == 'id':
        s = re.sub(r'[^\w\-/.]', '', s)
    elif field_type == 'path':
        s = s.replace('..', '_').replace('\x00', '')
    if len(s) > max_length:
        s = s[:max_length]
    return s.strip()


_LOG_LOCK = _threading.Lock()


def log_operation(level: str, message: str, out_dir: str = None):
    """操作日志写入（线程安全）。"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    sep = '─' * 72
    log_line = f'\n{sep}\n[{timestamp}] [{level}] {message}\n'
    if out_dir:
        try:
            out_dir = os.path.realpath(out_dir)
            user_home = os.path.realpath(os.path.expanduser('~'))
            system_drive = os.environ.get('SystemDrive', 'C:') + '\\'
            is_system_drive = out_dir.upper().startswith(system_drive.upper())
            is_user_home = out_dir.startswith(user_home)
            if is_system_drive and (not is_user_home):
                return
            out_log_dir = os.path.join(out_dir, 'logs')
            os.makedirs(out_log_dir, exist_ok=True)
            today = datetime.now().strftime('%Y-%m-%d')
            out_log_file = os.path.join(out_log_dir, f'操作日志_{today}.txt')
            with _LOG_LOCK:
                with open(out_log_file, 'a', encoding='utf-8') as f:
                    f.write(log_line)
        except (OSError, ValueError):
            pass


class TimedLock:
    """带超时、死锁检测、自动释放的互斥锁。"""
    DEFAULT_TIMEOUT = 600
    DEADLOCK_MULTIPLIER = 2

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, lock_file: str = None):
        self._lock = _threading.Lock()
        self._timeout = timeout
        self._acquired_at = 0.0
        self._holder = None
        self._lock_file = lock_file

    def _stale_lockfile_exists(self) -> bool:
        if not self._lock_file or not os.path.exists(self._lock_file):
            return False
        try:
            age = __import__('time').time() - os.path.getmtime(self._lock_file)
            return age > self._timeout * self.DEADLOCK_MULTIPLIER
        except OSError:
            return False

    def _write_lockfile(self, info: str):
        if not self._lock_file:
            return
        try:
            os.makedirs(os.path.dirname(self._lock_file), exist_ok=True)
            with open(self._lock_file, 'w', encoding='utf-8') as f:
                f.write(_json.dumps(
                    {'ts': __import__('time').time(), 'pid': os.getpid(), 'info': info},
                    ensure_ascii=False))
        except OSError:
            pass

    def _clear_lockfile(self):
        if not self._lock_file or not os.path.exists(self._lock_file):
            return
        try:
            os.remove(self._lock_file)
        except OSError:
            pass

    def acquire(self, blocking=True, info: str = '') -> bool:
        if blocking:
            deadline = __import__('time').time() + self._timeout
            while __import__('time').time() < deadline:
                if self._lock.acquire(blocking=False):
                    self._acquired_at = __import__('time').time()
                    self._holder = info
                    self._write_lockfile(info)
                    return True
                __import__('time').sleep(0.1)
            return False
        if self._lock.acquire(blocking=False):
            self._acquired_at = __import__('time').time()
            self._holder = info
            self._write_lockfile(info)
            return True
        return False

    def release(self):
        try:
            self._lock.release()
        except RuntimeError:
            pass
        self._holder = None
        self._clear_lockfile()

    def __enter__(self):
        self.acquire(info='context')
        return self

    def __exit__(self, *args):
        self.release()