"""file_rules 单测:逻辑路径 / 系统标准目录 / 系统信任库 / 搜索过滤 / 降级目录。

接缝:file_rules 的公开函数(纯逻辑,读 profile)。不测各 step 的 import 迁移。
"""
from __future__ import annotations

from ..file_rules import (
    is_downgrade_dir,
    is_search_excluded,
    is_system_std,
    is_system_trust,
    logical_path,
)


def test_logical_path_strips_extracted():
    """剥 binwalk 嵌套前缀: .extracted/<N>/ 段被去掉。"""
    assert logical_path(
        "foo.tar.xz.extracted/0/decompressed.bin.extracted/0/etc/passwd"
    ) == "etc/passwd"
    # hex 偏移目录(3.1.1)也能剥
    assert logical_path("x.tar.xz.extracted/13DE7F0/etc/passwd") == "etc/passwd"


def test_logical_path_strips_fstype_root():
    """剥 <fstype>-root/ 段。"""
    assert logical_path("root.squashfs.extracted/0/squashfs-root/etc/passwd") == "etc/passwd"
    assert logical_path("root.cpio.extracted/0/cpio-root/etc/passwd") == "etc/passwd"


def test_logical_path_flat_unchanged():
    """非解包路径原样返回(已扁平化)。"""
    assert logical_path("etc/passwd") == "etc/passwd"
    assert logical_path("unitree/bin/idlc") == "unitree/bin/idlc"


def test_is_system_std_hits_profile_dirs():
    """命中 profile SYSTEM_STD_DIRS 判定为标准目录。"""
    # nano-ubuntu.yaml 里 SYSTEM_STD_DIRS 含 etc/mono
    assert is_system_std("etc/mono/machine.config") is True
    assert is_system_std("etc/mono") is True


def test_is_system_std_miss():
    """非标准目录不为 True。"""
    assert is_system_std("etc/init.d/lighttpd") is False
    assert is_system_std("unitree/bin/idlc") is False


def test_is_system_trust_hits_trust_dirs():
    """命中 profile SYSTEM_TRUST_DIRS 判定为系统信任库。"""
    # nano-ubuntu.yaml 里 SYSTEM_TRUST_DIRS 含 etc/ssl/certs
    assert is_system_trust("etc/ssl/certs/ca-certificates.crt") is True
    assert is_system_trust("etc/ssl/certs") is True


def test_is_system_trust_miss():
    """非信任库路径不为 True。"""
    assert is_system_trust("unitree/etc/app.crt") is False


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


def test_is_downgrade_dir_hits():
    """命中低危信号降级目录(SYSTEM_DOWNGRADE_DIRS)。"""
    # SYSTEM_DOWNGRADE_DIRS 含 etc/init.d 等(Step4 文本扫描降级用)
    assert is_downgrade_dir("etc/init.d/lighttpd") is True
    assert is_downgrade_dir("etc/apt/sources.list") is True


def test_is_downgrade_dir_miss():
    """非降级目录不为 True。"""
    assert is_downgrade_dir("unitree/bin/idlc") is False
    assert is_downgrade_dir("etc/xdg/user-dirs.conf") is False  # etc/xdg 在 SYSTEM_STD 非降级
