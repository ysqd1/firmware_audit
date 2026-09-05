"""step5_agent 依赖分层守护测试(ADR-0009:分层规则机器化)。

"engine/data/providers 互不 import、依赖只准向下"原是 AGENTS.md 里的
文档约定,靠自觉;本文件用 AST 扫描 step5_agent 全部 .py 的 import 边
(含函数级延迟导入),把规则升级为断言,违规即红:

    入口(run_step5 / 包根 __init__ / demo_display)
      → orchestration(编排层包)
      → runner / aggregator(单实例执行 / 聚合纯逻辑)
      → engine / data / providers(叶子三包:互不 import、不向上)

- 跨单元边只准向下(目标层级序严格大于源);同单元(包内)边不受限;
  入口层是顶层,可引任意单元
- 票面点名两条红线单独断言,失败信息直白:runner 永不 import
  orchestration;叶子三包两两互不依赖
- 新顶层模块必须先在 TIER 登记层级,否则守护直接红——层级图变更应是
  显式决策(改本文件),不是悄悄发生
- 守护范围是 step5_agent 全依赖图,不限于 orchestration 新包;
  跨子系统引用(firmware_audit.docker/file_rules 等共享工具)不在本图内

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
# 层级图来源:ADR-0009;改动这里 = 显式架构决策。
TIER: dict[str, int] = {
    "": 0,               # step5_agent/__init__(对外只暴露 step5_run)
    "run_step5": 0,      # CLI 入口
    "demo_display": 0,   # 演示脚本(入口同层;T6 迁 demos/)
    "orchestration": 1,  # 编排层包(ADR-0009)
    "runner": 2,         # 单 Agent 执行
    "aggregator": 2,     # findings 聚合纯逻辑
    "engine": 3,
    "data": 3,
    "providers": 3,
}
_LEAVES = ("engine", "data", "providers")


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
                         f"先在本文件 TIER 登记层级再引入(ADR-0009)")
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
                             f"依赖只准向下(ADR-0009 分层),禁止同层/反向")

    # 红线一:runner 永不 import orchestration(单实例执行不知道编排的存在)
    if "orchestration" in graph.get("runner", set()):
        fails.append("runner 不得 import orchestration(编排只准从入口进入,ADR-0009)")

    # 红线二:叶子三包两两互不依赖
    for a in _LEAVES:
        for b in _LEAVES:
            if a != b and b in graph.get(a, set()):
                fails.append(f"{a} 不得 import {b}(叶子三包互不依赖,ADR-0009)")

    # 接线存在性:入口必须经 orchestration 编排(防迁移中悄悄断链)
    if "orchestration" not in graph.get("run_step5", set()):
        fails.append("run_step5 应 import orchestration(入口 → 编排层接线,ADR-0009)")
    return fails


def test_no_legacy_top_level_orchestrator() -> list[str]:
    """旧顶层编排器模块不复活:不留兼容 shim,单一 import 路径(ADR-0009)。"""
    fails: list[str] = []
    if (PKG_ROOT / "orchestrator.py").exists():
        fails.append("firmware_audit/step5_agent/orchestrator.py 不应存在——"
                     "编排器已整体迁入 orchestration/ 包,不设顶层 shim(ADR-0009)")
    if not (PKG_ROOT / "orchestration" / "orchestrator.py").is_file():
        fails.append("orchestration/orchestrator.py 缺失——T1 整体迁移被破坏")
    if not (PKG_ROOT / "orchestration" / "__init__.py").is_file():
        fails.append("orchestration/__init__.py 缺失——包不成立")
    return fails


def test_orchestration_internal_edges() -> list[str]:
    """编排包内边守护(T4):state/dispatch_log/handoff/actions 不得 import
    编排主体 orchestrator——orchestrator 装配动作类、被动作回调,环由 state
    切断,import 必须单向 orchestrator → actions → handoff → state(ADR-0009)。"""
    fails: list[str] = []
    for name in ("state", "dispatch_log", "handoff", "actions"):
        py = PKG_ROOT / "orchestration" / f"{name}.py"
        if not py.is_file():
            continue  # 未到票的模块尚不存在,不空守护
        tree = ast.parse(py.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            targets = []
            if isinstance(node, ast.ImportFrom) and node.module:
                targets = [node.module]
            elif isinstance(node, ast.Import):
                targets = [a.name for a in node.names]
            for t in targets:
                if t.split(".")[-1] == "orchestrator":
                    fails.append(f"orchestration/{name}.py 不得 import orchestrator"
                                 "(包内依赖无环:环由 state 切断,反向边即环复活,ADR-0009 T4)")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in (
        ("dependency_layering", test_dependency_layering),
        ("no_legacy_top_level_orchestrator", test_no_legacy_top_level_orchestrator),
        ("orchestration_internal_edges", test_orchestration_internal_edges),
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
