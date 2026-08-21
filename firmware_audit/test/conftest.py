"""Step5 测试共享 fixture:让双模式测试(test_main 独立跑 + pytest 收集)在 pytest 下可用。

三个 step5 测试文件(test_step5_tools / test_step5_cli_tools / test_step5_smoke)
的测试函数声明 tools/llm/process_dir 形参:独立运行时由 test_main() 手动构造,
pytest 运行时由本文件注入。工件/Docker 缺失时 SKIP,与独立模式的 SKIP 语义一致。
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# 真实工件目录候选(与 test_step5_tools.py 保持一致)
_CANDIDATE_ROOTS = [
    Path(__file__).resolve().parents[2] / "target" / "1" / "process",
    Path(r"E:\固件\create\important\target\1\process"),
]
_PROBE = Path("analysis") / "unitree" / "bin" / "idlc.c"  # 探针文件:确认工件完整可测


def _find_process_dir() -> Path | None:
    for root in _CANDIDATE_ROOTS:
        if (root / _PROBE).exists():
            return root
    return None


@pytest.fixture(scope="session")
def process_dir() -> Path:
    """target/1/process 工件根;缺失则 SKIP(不影响 CI 环境)。"""
    d = _find_process_dir()
    if d is None:
        pytest.skip("target/1 工件不存在,读盘工具测试跳过")
    return d


@pytest.fixture(scope="session")
def tools(process_dir: Path) -> dict:
    """Agent 工具注册表(宿主读盘 + CLI + API 全集,构造不触发 Docker)。"""
    from firmware_audit.step5_agent.providers.tools import make_tools
    from firmware_audit.step5_agent.providers.tools.base import ToolContext

    return make_tools(ToolContext(process_dir=process_dir))


def pytest_pyfunc_call(pyfuncitem):
    """双模式测试兼容钩子。

    本目录测试函数沿用"收集 fails 列表并 return"的约定(便于 test_main 统一
    汇总打印)。默认 pytest 忽略非 None 返回值 → 断言失败也显示 PASSED(假绿)。
    此处接管调用:非空 fails 列表 / 非零退出码按测试失败处理,
    空 list / 0 / None 按通过处理(顺带消除 PytestReturnNotNoneWarning)。
    """
    testfunction = pyfuncitem.obj
    funcargs = pyfuncitem.funcargs
    testargs = {arg: funcargs[arg] for arg in pyfuncitem._fixtureinfo.argnames}
    result = testfunction(**testargs)

    if isinstance(result, list) and result:
        pytest.fail(
            f"{len(result)} 个断言失败:\n" + "\n".join(f"  - {m}" for m in result),
            pytrace=False,
        )
    if isinstance(result, int) and result != 0:
        pytest.fail(f"test_main 退出码非零: {result}", pytrace=False)
    return True
