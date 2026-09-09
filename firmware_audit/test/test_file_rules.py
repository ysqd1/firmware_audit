"""file_rules 单测:搜索过滤名单(ADR-0011 收缩后模块的唯一公开面)。

接缝:file_rules 的公开函数(纯逻辑,读 profile)。原 logical_path /
is_system_std / is_system_trust / is_downgrade_dir 随 Step2-4 退役删除。
"""
from __future__ import annotations

from .. import file_rules
from ..file_rules import get_search_exclude_dirs, is_search_excluded


def test_is_search_excluded_hits_sdk():
    """命中搜索过滤名单判定为应过滤。"""
    # SEARCH_EXCLUDE_DIRS 含 usr/lib/usr/local/lib/usr/share/lib/opt 等 SDK 目录,
    # 及 .git/__pycache__/node_modules/.pytest_cache 等工具噪音
    assert is_search_excluded("usr/lib/x86_64/libfoo.so") is True
    assert is_search_excluded("usr/local/lib/python3.9/os.py") is True
    assert is_search_excluded("usr/share/doc") is True
    assert is_search_excluded("opt/ros/noetic/foo.py") is True
    assert is_search_excluded("lib/x86_64/libbar.so") is True
    assert is_search_excluded(".git/config") is True
    assert is_search_excluded("__pycache__/foo.cpython-312.pyc") is True
    assert is_search_excluded("node_modules/lodash/index.js") is True
    assert is_search_excluded(".pytest_cache/v/cache/lastfailed") is True


def test_is_search_excluded_miss():
    """非过滤名单不为 True。"""
    assert is_search_excluded("unitree/bin/idlc") is False
    assert is_search_excluded("etc/init.d/lighttpd") is False


def test_get_search_exclude_dirs_returns_copy():
    """返回名单副本,调用方改动不穿透模块状态。"""
    dirs = get_search_exclude_dirs()
    assert dirs, "默认 profile 应加载到 SEARCH_EXCLUDE_DIRS"
    dirs.append("injected-by-test")
    assert "injected-by-test" not in file_rules.SEARCH_EXCLUDE_DIRS


def test_configure_bad_profile_keeps_last():
    """坏 profile 名保持上次有效名单(失败不崩、不清空)。"""
    before = get_search_exclude_dirs()
    file_rules.configure("no-such-profile")
    assert get_search_exclude_dirs() == before
