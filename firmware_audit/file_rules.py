"""file_rules —— 路径判断策略的唯一入口。

收敛"哪些路径不值得审 / 该标记 / 该过滤"的判断(2026-08-30,架构体检 C3):
- 系统标准目录(is_system_std):命中即排除,不送审 —— Step2/Step4 用
- 系统信任库(is_system_trust):命中即标记,仍送审但标注"非厂商凭证" —— Step3 用
- 搜索过滤(is_search_excluded):命中即搜索时跳过(过滤噪音,不排除) —— Step5 工具层用
- 逻辑路径(logical_path):剥 binwalk 嵌套前缀,是以上判断的共同前置

名单全部外置到 profiles/<name>.yaml(换机型只改 profile,三处一起生效)。
原先各 step 自持的名单(Step4 _SYSTEM_STD_DIRS 硬编码、Step5 工具层
DEFAULT_EXCLUDE_DIRS/SDK_DIR_PREFIXES)已收敛到此处,消除分叉。
"""
from __future__ import annotations

import re
from pathlib import Path

_PROFILE_DIR = Path(__file__).resolve().parent / "profiles"
_DEFAULT_PROFILE = "nano-ubuntu"

# binwalk 递归解包产生的嵌套前缀形如:
#   nano14-backup-SANITIZED.tar.xz.extracted/0/decompressed.bin.extracted/0/etc/passwd
# 名单(usr/share, etc/passwd, home/unitree ...)是针对"逻辑固件路径"定义的,
# 直接对 rel_path 做 startswith 永不命中。先剥掉所有 <name>.extracted/<N>/ 前缀。
# 偏移子目录:旧 binwalk 是数字(0/1/...),3.1.1 是 hex(13DE7F0、2919000)。
# 只剥数字会卡在 hex 树 → 名单全 miss(实测 part05_B_kernel 61 万条目树)。
# 7z 兜底(引导解包器 binwalk 无 extractor 的容器走 7z 扁平解包)无偏移段:
#   <seq>_x.cpio.extracted/etc/passwd —— 偏移目录可缺省。
_EXTRACTED_PREFIX_RE = re.compile(r"^[^/]+\.extracted/(?:[0-9A-Fa-f]+/)?")

# binwalk 对内嵌文件系统(如 squashfs/cpio/jffs2)解出 <fstype>-root 目录:
#   xxx.squashfs.extracted/0/squashfs-root/etc/passwd
#   xxx.cpio.extracted/0/cpio-root/etc/passwd
# 这些 root 目录名(带可选 -N 后缀)也剥掉,否则名单(etc/passwd)匹配不到。
# 用 <name>-root 通配,覆盖 squashfs-root/cpio-root/jffs2-root/cramfs-root 等。
_ROOT_PREFIX_RE = re.compile(r"^[^/]+-root(?:-\d+)?/")


def _load_profile(name: str) -> dict:
    """读取 profile yaml,返回名单 dict;缺文件/解析失败回退空 dict(失败不崩)。"""
    try:
        import yaml
    except ImportError:
        print("[file_rules] 警告: pyyaml 未安装,名单未加载")
        return {}
    path = _PROFILE_DIR / f"{name}.yaml"
    if not path.is_file():
        print(f"[file_rules] 警告: profile 文件不存在: {path.name}")
        return {}
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        print(f"[file_rules] 警告: profile 解析失败({path.name}): {e}")
        return {}


# 当前生效的 profile(默认 nano-ubuntu)。configure() 会重载并更新模块级名单。
_PROFILE = _load_profile(_DEFAULT_PROFILE)

# 名单(按"逻辑固件路径"定义;SYSTEM_STD_DIRS/SYSTEM_TRUST_DIRS 来自 profile,
# SEARCH_EXCLUDE_DIRS 为 2026-08-30 新增,收纳 Step5 工具层原硬编码的过滤名单)
SYSTEM_STD_DIRS = _PROFILE.get("SYSTEM_STD_DIRS") or []
SYSTEM_TRUST_DIRS = _PROFILE.get("SYSTEM_TRUST_DIRS") or []
SEARCH_EXCLUDE_DIRS = _PROFILE.get("SEARCH_EXCLUDE_DIRS") or []
SYSTEM_DOWNGRADE_DIRS = _PROFILE.get("SYSTEM_DOWNGRADE_DIRS") or []


def configure(profile_name: str) -> None:
    """加载指定 profile 并更新模块级名单。

    profile 不存在/解析失败时保持上次有效名单不变(与 step2_filter.configure 同语义),
    避免误传 profile 名把名单清空。
    """
    new_profile = _load_profile(profile_name)
    if not new_profile:
        return
    global _PROFILE, SYSTEM_STD_DIRS, SYSTEM_TRUST_DIRS, SEARCH_EXCLUDE_DIRS
    global SYSTEM_DOWNGRADE_DIRS
    _PROFILE = new_profile
    SYSTEM_STD_DIRS = _PROFILE.get("SYSTEM_STD_DIRS") or []
    SYSTEM_TRUST_DIRS = _PROFILE.get("SYSTEM_TRUST_DIRS") or []
    SEARCH_EXCLUDE_DIRS = _PROFILE.get("SEARCH_EXCLUDE_DIRS") or []
    SYSTEM_DOWNGRADE_DIRS = _PROFILE.get("SYSTEM_DOWNGRADE_DIRS") or []


def logical_path(rel_path: str) -> str:
    """剥掉 binwalk 嵌套前缀,返回固件内的逻辑路径。

    反复剥 <name>.extracted/<N>/ 与 <fstype>-root/ 前缀直到不再变化。
    例: foo.tar.xz.extracted/0/decompressed.bin.extracted/0/etc/passwd -> etc/passwd
    例: root.squashfs.extracted/0/squashfs-root/etc/passwd -> etc/passwd
    非解包路径(无上述段)原样返回,兼容单测与已扁平化场景。
    """
    rel = rel_path
    while True:
        new = _EXTRACTED_PREFIX_RE.sub("", rel, count=1)
        if new != rel:
            rel = new
            continue
        new = _ROOT_PREFIX_RE.sub("", rel, count=1)
        if new != rel:
            rel = new
            continue
        return rel


def _in_dirs(logical: str, dirs: list[str]) -> bool:
    """逻辑路径是否落在 dirs 中某目录下(等于或以其为前缀)。"""
    return any(logical == d or logical.startswith(d + "/") for d in dirs)


def is_system_std(logical: str) -> bool:
    """逻辑路径是否落在系统标准目录下(命中即排除,不送审)。"""
    return _in_dirs(logical, SYSTEM_STD_DIRS)


def is_system_trust(logical: str) -> bool:
    """逻辑路径是否落在系统信任库目录下(命中即标记,仍送审)。"""
    return _in_dirs(logical, SYSTEM_TRUST_DIRS)


def is_search_excluded(logical: str) -> bool:
    """逻辑路径是否落在搜索过滤名单下(命中即搜索时跳过,不排除)。"""
    return _in_dirs(logical, SEARCH_EXCLUDE_DIRS)


def is_downgrade_dir(logical: str) -> bool:
    """逻辑路径是否落在低危信号降级目录下(Step4 文本扫描用)。

    注意: 这是"降级"不是"排除"——此目录下的文件活着走到 Step4,
    只是低危信号(password_kw/url/ipv4)不匹配,避免系统标配脚本误报。
    """
    return _in_dirs(logical, SYSTEM_DOWNGRADE_DIRS)


def get_search_exclude_dirs() -> list[str]:
    """返回当前搜索过滤名单副本(供工具层遍历生成排除参数,避免绑定旧列表)。"""
    return list(SEARCH_EXCLUDE_DIRS)


__all__ = [
    "logical_path", "is_system_std", "is_system_trust", "is_search_excluded",
    "is_downgrade_dir", "get_search_exclude_dirs",
    "SYSTEM_STD_DIRS", "SYSTEM_TRUST_DIRS", "SEARCH_EXCLUDE_DIRS",
    "SYSTEM_DOWNGRADE_DIRS", "configure",
]
