"""file_rules —— 路径过滤策略的唯一入口(ADR-0011 收缩后)。

Step2/3/4 退役后,本模块只剩 Step5 工具层消费的**搜索过滤**判断:
- 搜索过滤(is_search_excluded):命中即搜索时跳过(过滤噪音,不排除)
  —— list_files / search_code / semgrep_scan / 简报现场概览消费

名单外置到 profiles/<name>.yaml 的 SEARCH_EXCLUDE_DIRS 段(换机型只改 profile)。
原 SYSTEM_STD/SYSTEM_TRUST/SYSTEM_DOWNGRADE 名单与其判断函数随 Step2-4
退役删除(ADR-0011 能力消失清单);binwalk 嵌套前缀剥离(logical_path)
的唯一消费者曾是 Step2-4,一并删除,将来审 MCU blob 需要时从 git 历史捞回。
"""
from __future__ import annotations

from pathlib import Path

_PROFILE_DIR = Path(__file__).resolve().parent / "profiles"
_DEFAULT_PROFILE = "nano-ubuntu"


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

# 搜索过滤名单(profile SEARCH_EXCLUDE_DIRS 段;2026-08-30 收敛,ADR-0011 后
# 成为 profile 的唯一存活段)
SEARCH_EXCLUDE_DIRS = _PROFILE.get("SEARCH_EXCLUDE_DIRS") or []


def configure(profile_name: str) -> None:
    """加载指定 profile 并更新模块级名单。

    profile 不存在/解析失败时保持上次有效名单不变,
    避免误传 profile 名把名单清空。
    """
    new_profile = _load_profile(profile_name)
    if not new_profile:
        return
    global _PROFILE, SEARCH_EXCLUDE_DIRS
    _PROFILE = new_profile
    SEARCH_EXCLUDE_DIRS = _PROFILE.get("SEARCH_EXCLUDE_DIRS") or []


def _in_dirs(path: str, dirs: list[str]) -> bool:
    """path 是否落在 dirs 中某目录下(等于或以其为前缀)。"""
    return any(path == d or path.startswith(d + "/") for d in dirs)


def is_search_excluded(path: str) -> bool:
    """路径是否落在搜索过滤名单下(命中即搜索时跳过,不排除)。"""
    return _in_dirs(path, SEARCH_EXCLUDE_DIRS)


def get_search_exclude_dirs() -> list[str]:
    """返回当前搜索过滤名单副本(供工具层遍历生成排除参数,避免绑定旧列表)。"""
    return list(SEARCH_EXCLUDE_DIRS)


__all__ = [
    "is_search_excluded", "get_search_exclude_dirs",
    "SEARCH_EXCLUDE_DIRS", "configure",
]
