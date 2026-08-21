"""Step5 CLI 工具单测:checksec / xref_query / cve_bin_tool_scan(真实沙箱容器)。

依赖 Docker + firm_audit/sandbox:latest + target/1 工件,任一缺失全部 SKIP。
cve_bin_tool_scan 首跑需下载 CVE 库(NVD 无 key 限速,可能极慢),默认 SKIP,
设环境变量 STEP5_TEST_CVE_BT=1 强制启用。
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.docker.docker_utils import docker_available
from firmware_audit.step5_agent.providers.tools import make_tools
from firmware_audit.step5_agent.providers.tools.base import ToolContext

SAMPLE_ELF = "unitree/bin/idlc"
_CANDIDATE = [Path(__file__).resolve().parents[2] / "target" / "1" / "process"]


@pytest.fixture(scope="module")
def tools(process_dir: Path) -> dict:
    """覆盖 conftest.tools:CLI 工具实测需 Docker 沙箱,不可用则 SKIP(同 _ready)。"""
    from firmware_audit.step5_agent.providers.tools.cli_base import SANDBOX_IMAGE

    if not docker_available(SANDBOX_IMAGE):
        pytest.skip(f"Docker 或镜像 {SANDBOX_IMAGE} 不可用")
    return make_tools(ToolContext(process_dir=process_dir))


def _ready() -> bool:
    from firmware_audit.step5_agent.providers.tools.cli_base import SANDBOX_IMAGE as img
    if not _CANDIDATE[0].exists():
        print("[SKIP] target/1 工件不存在")
        return False
    if not docker_available(img):
        print(f"[SKIP] Docker 或镜像 {img} 不可用")
        return False
    return True


def test_checksec(tools) -> list[str]:
    fails: list[str] = []
    r = tools["checksec"].execute(file_ref=SAMPLE_ELF)
    if not r.ok:
        fails.append(f"checksec 失败: {r.error}")
    else:
        d = r.data or {}
        if d.get("relro") != "partial":
            fails.append(f"relro 应为 partial(实测镜像), got {d.get('relro')}")
        if "canary" not in d or "nx" not in d or "pie" not in d:
            fails.append(f"属性缺字段: {sorted(d)}")
    # 越界路径拒绝
    if tools["checksec"].execute(file_ref="../../etc/passwd").ok:
        fails.append("越界路径应被拒绝")
    return fails


def test_xref_query(tools) -> list[str]:
    fails: list[str] = []
    # idlc 实测导入 popen(analysis/imports.json 确认),调用者是 idlc_load_generator
    r = tools["xref_query"].execute(file_ref=SAMPLE_ELF, symbol="popen")
    if not r.ok:
        fails.append(f"xref popen 失败: {r.error}")
    elif not r.data:
        fails.append("popen 应有交叉引用")
    elif not any("idlc_load_generator" in (d.get("fcn_name") or "") for d in r.data):
        fails.append(f"popen 调用者应含 idlc_load_generator, got {r.data}")

    # 符号不存在 → 不 ok=True 的空表或明确报错都算通过(不崩即可)
    r2 = tools["xref_query"].execute(file_ref=SAMPLE_ELF, symbol="definitely_not_a_symbol")
    if r2.ok and r2.data:
        fails.append("不存在符号不应有结果")
    return fails


def test_cve_bin_tool_scan(tools) -> list[str]:
    fails: list[str] = []
    r = tools["cve_bin_tool_scan"].execute(file_ref=SAMPLE_ELF)
    # 首跑下载 CVE 库受 NVD 限速影响,失败降级可接受,但 ok 时不允许无 data 字段结构
    if r.ok:
        if not isinstance(r.data, list):
            fails.append(f"cve-bin-tool data 应为 list, got {type(r.data)}")
    else:
        print(f"  [INFO] cve_bin_tool_scan 降级(CVE 库未就绪): {(r.error or '')[:120]}")
    return fails


def test_semgrep_scan(tools) -> list[str]:
    fails: list[str] = []
    # 本地规则扫真实脚本目录:ok 且 data 为 list(0 命中也是正常结果)
    r = tools["semgrep_scan"].execute(path="unitree/module/bashrunner")
    if not r.ok:
        fails.append(f"semgrep_scan 失败: {r.error}")
    elif not isinstance(r.data, list):
        fails.append(f"semgrep data 应为 list, got {type(r.data)}")
    # 越界路径拒绝
    if tools["semgrep_scan"].execute(path="../../etc").ok:
        fails.append("semgrep 越界路径应被拒绝")
    return fails


def test_gitleaks_scan(tools) -> list[str]:
    fails: list[str] = []
    r = tools["gitleaks_scan"].execute(path="unitree/module/bashrunner")
    if not r.ok:
        fails.append(f"gitleaks_scan 失败: {r.error}")
    elif not isinstance(r.data, list):
        fails.append(f"gitleaks data 应为 list, got {type(r.data)}")
    # 不存在路径 → gitleaks 非零退出,应报错不崩
    r2 = tools["gitleaks_scan"].execute(path="no/such/dir")
    if r2.ok:
        fails.append("gitleaks_scan 不存在路径不应 ok")
    return fails


def test_sandbox_verify(tools) -> list[str]:
    fails: list[str] = []
    # 命令注入 Fuzzing Harness 原型:mock os.system 检测调用
    code = ("import os\n"
            "hits=[]\n"
            "os.system=lambda c:(hits.append(c),0)[1]\n"
            "def vuln(u): os.system(f'echo {u}')\n"
            "vuln('; id')\n"
            "print('DETECTED', bool(hits))\n")
    r = tools["sandbox_verify"].execute(code=code, language="python", timeout=60)
    if not r.ok:
        fails.append(f"sandbox_verify 失败: {r.error}")
    elif "DETECTED True" not in r.text:
        fails.append(f"harness 输出异常: {r.text[:200]}")
    # 非白名单语言拒绝
    if tools["sandbox_verify"].execute(code="x", language="bash").ok:
        fails.append("非白名单语言应被拒绝")
    return fails


def test_binwalk_rescan(tools) -> list[str]:
    fails: list[str] = []
    # 签名复扫:统一沙箱装了 binwalk 直跑;旧镜像自动回退专用 binwalk 镜像
    r = tools["binwalk_rescan"].execute(file_ref=SAMPLE_ELF)
    if not r.ok:
        fails.append(f"binwalk_rescan 失败: {r.error}")
    elif "签名复扫" not in r.text:
        fails.append(f"binwalk 输出异常: {r.text[:200]}")
    # 越界路径拒绝
    if tools["binwalk_rescan"].execute(file_ref="../../etc/passwd").ok:
        fails.append("binwalk 越界路径应被拒绝")
    return fails


def test_web_search(tools) -> list[str]:
    fails: list[str] = []
    # 离线参数校验(网络实查由 STEP5_TEST_WEB=1 门控,防 CI 抖动)
    if tools["web_search"].execute(query="").ok:
        fails.append("空 query 应 ok=False")
    import os
    if os.environ.get("STEP5_TEST_WEB") == "1":
        r = tools["web_search"].execute(query="binwalk firmware extraction")
        if not r.ok:
            print(f"  [INFO] web_search 网络降级: {(r.error or '')[:120]}")
        elif not isinstance(r.data, list):
            fails.append("web_search data 应为 list")
    return fails


def test_main() -> int:
    if not _ready():
        return 0
    tools = make_tools(ToolContext(process_dir=_CANDIDATE[0]))

    cases = [
        ("checksec", lambda: test_checksec(tools)),
        ("xref_query", lambda: test_xref_query(tools)),
        ("semgrep_scan", lambda: test_semgrep_scan(tools)),
        ("gitleaks_scan", lambda: test_gitleaks_scan(tools)),
        ("sandbox_verify", lambda: test_sandbox_verify(tools)),
        ("binwalk_rescan", lambda: test_binwalk_rescan(tools)),
        ("web_search", lambda: test_web_search(tools)),
    ]
    if os.environ.get("STEP5_TEST_CVE_BT") == "1":
        cases.append(("cve_bin_tool_scan", lambda: test_cve_bin_tool_scan(tools)))
    else:
        print("[SKIP] cve_bin_tool_scan(设 STEP5_TEST_CVE_BT=1 启用,首跑需下载 CVE 库)")

    failures = 0
    for name, fn in cases:
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
