"""step5_agent 依赖分层守护测试(ADR-0009 起源;ADR-0012 公开切换后收敛)。

"engine/providers 互不 import、依赖只准向下"原是 AGENTS.md 里的文档约定,
靠自觉;本文件用 AST 扫描 step5_agent 全部 .py 的 import 边(含函数级延迟
导入),把规则升级为断言,违规即红:

    入口(run_step5 / 包根 __init__)
      → host(ADR-0012 Host 控制层,唯一控制边界)
      → engine / providers(叶子两包:互不 import、不向上)

- 跨单元边只准向下(目标层级序严格大于源);同单元(包内)边不受限;
  入口层是顶层,可引任意单元
- 叶子两包两两互不依赖单独断言,失败信息直白
- 新顶层模块必须先在 TIER 登记层级,否则守护直接红——层级图变更应是
  显式决策(改本文件),不是悄悄发生
- 旧 orchestration/runner/aggregator/data 已随票 14 公开切换删除:
  守护反向断言它们不得复活(不留 shim、不双写)

先例:tool_permissions_and_threshold(权限矩阵机器化)。
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

PKG_ROOT = Path(__file__).resolve().parents[1] / "step5_agent"
_PREFIX = ["firmware_audit", "step5_agent"]

# 单元 → 层级序(越小越上层)。'' 是包根 __init__。
# 层级图来源:ADR-0009 起,ADR-0012 票 14 收敛;改动这里 = 显式架构决策。
TIER: dict[str, int] = {
    "": 0,               # step5_agent/__init__(对外只暴露 step5_run)
    "run_step5": 0,      # CLI 入口
    "host": 1,           # ADR-0012 Host 控制层(唯一控制边界)
    "engine": 2,
    "providers": 2,
}
_LEAVES = ("engine", "providers")

# 票 14 公开切换删除的 legacy 单元:不得以任何形态复活(不含 __pycache__)。
_RETIRED_UNITS = ("orchestration", "runner", "aggregator", "data", "demos")


def _module_parts(py: Path) -> list[str]:
    """文件 → 点分模块组件(含 firmware_audit.step5_agent 前缀;__init__ 折叠为包)。"""
    rel = py.relative_to(PKG_ROOT)
    parts = _PREFIX + list(rel.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return parts


def _unit(parts: list[str]) -> str | None:
    """点分路径 → step5_agent 内单元名(首段;包根为 '');包外返回 None。"""
    if parts[: len(_PREFIX)] != _PREFIX:
        return None
    rest = parts[len(_PREFIX):]
    return rest[0] if rest else ""


def _import_units(py: Path) -> set[str]:
    """该文件 import 的 step5_agent 内部单元集合(去重,含延迟导入)。"""
    mod = _module_parts(py)
    pkg = mod[:-1] if py.name != "__init__.py" else mod
    units: set[str] = set()

    def note(target: list[str]) -> None:
        u = _unit(target)
        if u is not None:
            units.add(u)

    tree = ast.parse(py.read_text(encoding="utf-8-sig"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 0:
                if node.module:  # level=0 且 module=None 不存在于语法层
                    note(node.module.split("."))
            else:
                # level≥1:锚点 = 当前包上退 level-1 级(from . → 本包)
                cut = len(pkg) - (node.level - 1)
                if cut < 0:
                    continue  # 退到 firmware_audit 之外,必非内部边
                anchor = pkg[:cut]
                if node.module:
                    note(anchor + node.module.split("."))
                else:  # from . import x:每个别名都是目标模块
                    for alias in node.names:
                        note(anchor + [alias.name])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                note(alias.name.split("."))
    return units


def test_dependency_layering() -> list[str]:
    """全依赖图分层断言:跨单元边只准向下;入口在顶;未知单元拒绝。"""
    fails: list[str] = []
    files = sorted(p for p in PKG_ROOT.rglob("*.py") if "__pycache__" not in p.parts)
    if not files:
        return ["step5_agent 下没有任何 .py,扫描本身异常"]

    graph: dict[str, set[str]] = {}  # src 单元 → dst 单元集合(合并同单元多文件)
    for py in files:
        src = _unit(_module_parts(py))
        if src not in TIER:
            fails.append(f"{py.relative_to(PKG_ROOT)}: 未知顶层单元 {src!r}——"
                         f"先在本文件 TIER 登记层级再引入")
            continue
        graph.setdefault(src, set()).update(_import_units(py))

    for src, dsts in sorted(graph.items()):
        src_tier = TIER[src]
        for dst in sorted(dsts):
            if dst == src:  # 包内边(含包 __init__ 铺面再导出)不受层级约束
                continue
            dst_tier = TIER[dst]
            if src_tier == 0:
                continue  # 入口层在顶,可引任意单元
            if dst_tier <= src_tier:
                fails.append(f"{src or '<pkg>'}(层{src_tier}) → {dst}(层{dst_tier}): "
                             f"依赖只准向下,禁止同层/反向")

    # 红线一:叶子两包两两互不依赖
    for a in _LEAVES:
        for b in _LEAVES:
            if a != b and b in graph.get(a, set()):
                fails.append(f"{a} 不得 import {b}(叶子两包互不依赖)")

    # 红线二:入口必须经 host 控制层接线(防公开入口绕过 Host 直连叶子循环)
    if "host" not in graph.get("run_step5", set()):
        fails.append("run_step5 应 import host(公开入口 → Host 控制层接线,ADR-0012)")
    return fails


def test_retired_legacy_units_stay_deleted() -> list[str]:
    """票 14 公开切换删除的 legacy 单元不得复活:不留 shim、不双写、不双模式。"""
    fails: list[str] = []
    for unit in _RETIRED_UNITS:
        if (PKG_ROOT / unit).exists():
            fails.append(
                f"step5_agent/{unit} 不应存在——旧控制流已随票 14 公开切换删除,"
                f"不保留兼容 shim 或双模式(ADR-0012)")
    for name in ("runner.py", "aggregator.py", "orchestrator.py"):
        if (PKG_ROOT / name).exists():
            fails.append(f"step5_agent/{name} 不应存在——legacy 单文件不得复活")
    if (PKG_ROOT / "engine" / "react_loop.py").exists():
        fails.append("engine/react_loop.py 不应存在——内藏完整循环的旧 ReAct "
                     "状态机已由 Host 逐步 Agent Session 取代(ADR-0012)")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in (
        ("dependency_layering", test_dependency_layering),
        ("retired_legacy_units_stay_deleted", test_retired_legacy_units_stay_deleted),
    ):
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())
