"""Step5 CLI 工具单测:checksec / r2_xref_query / cve_bin_tool_scan(真实沙箱容器)。

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


def test_r2_xref_query(tools) -> list[str]:
    fails: list[str] = []
    # idlc 实测导入 popen(analysis/imports.json 确认),调用者是 idlc_load_generator
    r = tools["r2_xref_query"].execute(file_ref=SAMPLE_ELF, symbol="popen")
    if not r.ok:
        fails.append(f"xref popen 失败: {r.error}")
    elif not r.data:
        fails.append("popen 应有交叉引用")
    elif not any("idlc_load_generator" in (d.get("fcn_name") or "") for d in r.data):
        fails.append(f"popen 调用者应含 idlc_load_generator, got {r.data}")

    # 符号不存在 → 不 ok=True 的空表或明确报错都算通过(不崩即可)
    r2 = tools["r2_xref_query"].execute(file_ref=SAMPLE_ELF, symbol="definitely_not_a_symbol")
    if r2.ok and r2.data:
        fails.append("不存在符号不应有结果")
    return fails


def test_r2_list_functions(tools) -> list[str]:
    """票01 Docker 门控真跑:aflj 函数清单(真实沙箱 + target/1 ELF)。"""
    fails: list[str] = []
    r = tools["r2_list_functions"].execute(file_ref=SAMPLE_ELF)
    if not r.ok:
        fails.append(f"r2_list_functions 失败: {r.error}")
    elif not isinstance(r.data, list) or not r.data:
        fails.append("idlc 应有函数条目")
    elif not any(isinstance(d, dict) and d.get("name") for d in r.data):
        fails.append(f"函数条目应含 name 字段: {r.data[:2]}")
    # 非 ELF → 引导性拒绝(不付容器;真实存在的脚本文件)
    r2 = tools["r2_list_functions"].execute(file_ref="unitree/module/bashrunner/run_test.sh")
    if r2.ok:
        fails.append("非 ELF 应被引导性拒绝")
    elif "不是 ELF" not in (r2.error or ""):
        fails.append(f"非 ELF 错误文案应引导: {r2.error}")
    # 越界路径拒绝
    if tools["r2_list_functions"].execute(file_ref="../../etc/passwd").ok:
        fails.append("越界路径应被拒绝")
    return fails


def test_r2_disassemble_function(tools) -> list[str]:
    """票01 Docker 门控真跑:pdf 单函数反汇编 + 未命中附函数名提示。"""
    fails: list[str] = []
    # main 符号存在(与 find_decompiled_function 的 main 对应)
    r = tools["r2_disassemble_function"].execute(file_ref=SAMPLE_ELF, func_or_addr="sym.main")
    if not r.ok:
        fails.append(f"r2_disassemble sym.main 失败: {r.error}")
    elif "sym.main" not in r.text:
        fails.append(f"反汇编输出应含目标标注: {r.text[:120]}")
    # 不存在的目标 → 错误附函数/符号名提示
    r2 = tools["r2_disassemble_function"].execute(
        file_ref=SAMPLE_ELF, func_or_addr="sym.definitely_not_here")
    if r2.ok:
        fails.append("不存在目标应 ok=False")
    elif "sym." not in (r2.error or ""):
        fails.append(f"未命中错误应附符号名提示: {r2.error[:200]}")
    return fails


def test_strings_imports_r2_fallback(tools, process_dir) -> list[str]:
    """票02 Docker 门控真跑:无边车工作区(tmp 拷真实 ELF)自动 r2 兜底。"""
    import shutil
    import tempfile

    from firmware_audit.step5_agent.providers.tools.base import ToolContext

    fails: list[str] = []
    src = process_dir / "extracted" / SAMPLE_ELF
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        dst = root / "extracted" / "sample.elf"
        dst.parent.mkdir(parents=True)
        shutil.copy2(src, dst)
        ctx = ToolContext(process_dir=root)
        fresh = dict(make_tools(ctx))
        # strings 兜底:izz 对真实 ELF 出字符串;url 模式可能零命中但必须 ok
        rs = fresh["strings_query"].execute(file_ref="sample.elf", pattern="url")
        if not rs.ok:
            fails.append(f"strings 兜底失败: {rs.error}")
        elif "r2 izz" not in rs.text:
            fails.append(f"strings 兜底来源标注异常: {rs.text[:120]}")
        # imports 兜底:真实 ELF 导入表;危险表可能零命中但必须 ok
        ri = fresh["imports_query"].execute(file_ref="sample.elf")
        if not ri.ok:
            fails.append(f"imports 兜底失败: {ri.error}")
        elif "r2 iij" not in ri.text:
            fails.append(f"imports 兜底来源标注异常: {ri.text[:120]}")
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
    elif r.data and not all(str(m.get("path", "")).startswith("extracted/")
                            for m in r.data if isinstance(m, dict)):
        fails.append(f"semgrep 命中路径应带 extracted/ 前缀(ADR-0008): {r.data[:2]}")
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
    elif r.data and not all(str(m.get("file", "")).startswith("extracted/")
                            for m in r.data if isinstance(m, dict)):
        fails.append(f"gitleaks 命中路径应带 extracted/ 前缀(ADR-0008): {r.data[:2]}")
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
    # 签名复扫:binwalk 专用镜像直跑(沙箱装不下,见 binwalk_rescan 模块注释)
    r = tools["binwalk_rescan"].execute(file_ref=SAMPLE_ELF)
    if not r.ok:
        fails.append(f"binwalk_rescan 失败: {r.error}")
    elif "签名复扫" not in r.text:
        fails.append(f"binwalk 输出异常: {r.text[:200]}")
    # 票02 真跑回归:不存在文件 → 宿主预检引导性拒绝(幽灵扫描修复)
    r2 = tools["binwalk_rescan"].execute(file_ref="no/such/ghost.bin")
    if r2.ok:
        fails.append("不存在文件应 ok=False(幽灵扫描)")
    elif "文件不在解包树" not in (r2.error or "") or "list_files" not in (r2.error or ""):
        fails.append(f"缺失文件错误应引导 list_files: {r2.error}")
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


def test_extracted_tool_path() -> list[str]:
    """extracted_tool_path(ADR-0008,纯函数):容器报告路径 → extracted/ 前缀
    工具路径;覆盖相对/带挂载前缀/子目录扫描根/防重复前缀四种形态。"""
    from firmware_audit.step5_agent.providers.tools.cli_base import extracted_tool_path

    fails: list[str] = []
    cases = [
        # (scan_root, reported, 期望)
        (".", "unitree/bin/idlc", "extracted/unitree/bin/idlc"),
        ("", "unitree/bin/idlc", "extracted/unitree/bin/idlc"),
        ("unitree/module", "pet_go/x.py", "extracted/unitree/module/pet_go/x.py"),
        # semgrep 绝对形态:剥挂载前缀后已含扫描根,不得重复
        ("unitree/module", "/work/extracted/unitree/module/pet_go/x.py",
         "extracted/unitree/module/pet_go/x.py"),
        # 全挂载根形态
        (".", "/work/extracted/a.py", "extracted/a.py"),
    ]
    for root, reported, want in cases:
        got = extracted_tool_path(root, reported)
        if got != want:
            fails.append(f"extracted_tool_path({root!r}, {reported!r}) = {got!r}, 期望 {want!r}")
    return fails


def test_semgrep_dual_scan() -> list[str]:
    """semgrep 双扫(path="."):extracted 全规则 + analysis 仅 *.c(2026-09-04)。
    小夹具临时目录(秒级):.py 命中走 extracted/ 前缀,.c 命中走 analysis/
    前缀且是 C 规则;JSON 边车不被扫。"""
    import json as _json
    import tempfile
    from firmware_audit.docker.docker_utils import docker_available
    from firmware_audit.step5_agent.providers.tools.cli_base import SANDBOX_IMAGE
    from firmware_audit.step5_agent.providers.tools.semgrep_scan import SemgrepScanTool
    from firmware_audit.step5_agent.providers.tools.base import ToolContext

    fails: list[str] = []
    if not docker_available(SANDBOX_IMAGE):
        pytest.skip(f"Docker 或镜像 {SANDBOX_IMAGE} 不可用")
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "extracted" / "mod").mkdir(parents=True)
        (root / "extracted" / "mod" / "a.py").write_text(
            "import os\nos.system(cmd)\n", encoding="utf-8")
        (root / "analysis" / "mod").mkdir(parents=True)
        (root / "analysis" / "mod" / "svc.c").write_text(
            '#include <string.h>\nvoid f(char* a, char* b){ strcpy(a, b); }\n'
            'void g(const char* c){ system(c); }\n',
            encoding="utf-8")
        (root / "analysis" / "mod" / "noise.json").write_text(
            _json.dumps({"looks": "like strcpy(a, b) but is json"}), encoding="utf-8")
        t = SemgrepScanTool(ToolContext(process_dir=root))
        r = t.execute(path=".")
        if not r.ok:
            fails.append(f"双扫应成功: {r.error}")
            return fails
        paths = {m.get("path") for m in (r.data or [])}
        cids = {m.get("check_id") for m in (r.data or [])}
        if not any(p and p.startswith("extracted/") for p in paths):
            fails.append(f"应含 extracted/ 前缀命中: {paths}")
        if not any(p and p.startswith("analysis/") for p in paths):
            fails.append(f"应含 analysis/ 前缀命中: {paths}")
        if "rules.c-strcpy" not in cids:
            fails.append(f"C 规则应命中 strcpy: {cids}")
        if "rules.c-system-popen" not in cids:
            fails.append(f"pattern-either 修复后 c-system-popen 应命中: {cids}")
        if any(p and "noise.json" in p for p in paths):
            fails.append(f"JSON 边车不得被扫: {paths}")
        if any(p and "extracted/extracted" in p or "analysis/analysis" in p
               for p in paths):
            fails.append(f"路径不得双重前缀: {paths}")
    return fails


def test_ghidra_decompile_smoke(tools, process_dir) -> list[str]:
    """票03 Docker 门控真 Ghidra 冒烟(验收锚点):小 ELF 三件套完整 + 二次调用缓存命中。

    tmp 工作区(不污染 target/1);真容器分钟级,仅在 ghidra 镜像可用时跑。
    """
    import shutil
    import tempfile

    from firmware_audit.docker.docker_utils import docker_available
    from firmware_audit.step5_agent.providers.tools.base import ToolContext
    from firmware_audit.step5_agent.providers.tools.ghidra_decompile import GHIDRA_IMAGE

    if not docker_available(GHIDRA_IMAGE):
        pytest.skip(f"Docker 或镜像 {GHIDRA_IMAGE} 不可用")

    fails: list[str] = []
    src = process_dir / "extracted" / "unitree/opt/lib/vlc/plugins/control/libdummy_plugin.so"
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "extracted").mkdir(parents=True)
        # 拷贝名不带扩展名(边车名 = <rel>.c,避免 ".so.c" 这类后缀误判)
        shutil.copy2(src, root / "extracted" / "sample")
        ctx = ToolContext(process_dir=root)
        fresh = make_tools(ctx)["ghidra_decompile"]
        r = fresh.execute(file_ref="sample")
        if not r.ok:
            fails.append(f"真 Ghidra 反编译失败: {r.error}")
            return fails
        ana = root / "analysis"
        for suf in (".c", ".imports.json", ".strings.json"):
            if not (ana / f"sample{suf}").is_file():
                fails.append(f"三件套缺 sample{suf}")
        if "个函数" not in r.text:
            fails.append(f"Observation 应含函数数: {r.text[:160]}")
        # 二次调用:缓存命中,零容器语义(Observation 文案判别)
        r2 = fresh.execute(file_ref="sample")
        if not r2.ok or "缓存命中" not in r2.text:
            fails.append(f"二次调用应缓存命中: {r2.error or r2.text[:160]}")
    return fails


def test_main() -> int:
    if not _ready():
        return 0
    tools = make_tools(ToolContext(process_dir=_CANDIDATE[0]))

    cases = [
        ("checksec", lambda: test_checksec(tools)),
        ("r2_xref_query", lambda: test_r2_xref_query(tools)),
        ("r2_list_functions", lambda: test_r2_list_functions(tools)),
        ("r2_disassemble_function", lambda: test_r2_disassemble_function(tools)),
        ("strings_imports_r2_fallback", lambda: test_strings_imports_r2_fallback(tools, _CANDIDATE[0])),
        ("ghidra_decompile_smoke", lambda: test_ghidra_decompile_smoke(tools, _CANDIDATE[0])),
        ("semgrep_scan", lambda: test_semgrep_scan(tools)),
        ("gitleaks_scan", lambda: test_gitleaks_scan(tools)),
        ("sandbox_verify", lambda: test_sandbox_verify(tools)),
        ("binwalk_rescan", lambda: test_binwalk_rescan(tools)),
        ("web_search", lambda: test_web_search(tools)),
        ("extracted_tool_path", lambda: test_extracted_tool_path()),
        ("semgrep_dual_scan", lambda: test_semgrep_dual_scan()),
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
