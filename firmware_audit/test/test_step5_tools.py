"""Step5 读盘工具单测:find_decompiled_function / imports_query / strings_query / read_file。

用真实 target/1 工件验证(读盘工具的输入契约就是 Step4 产出格式);
工件目录不存在时全部 SKIP(不影响 CI 环境)。
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import make_tools
from firmware_audit.step5_agent.providers.tools.base import ToolContext
from firmware_audit.step5_agent.providers.tools.find_decompiled_function import extract_function

# 真实工件目录(target/1/process)
_CANDIDATE_ROOTS = [
    Path(__file__).resolve().parents[2] / "target" / "1" / "process",
    Path(r"E:\固件\create\important\target\1\process"),
]
SAMPLE_ELF = "unitree/bin/idlc"  # 实测存在的反编译产物


def _find_process_dir() -> Path | None:
    for root in _CANDIDATE_ROOTS:
        if (root / "analysis" / "unitree" / "bin" / "idlc.c").exists():
            return root
    return None


def test_resolve_and_decompile(tools) -> list[str]:
    fails: list[str] = []
    # 正常切函数
    r = tools["find_decompiled_function"].execute(file_ref=SAMPLE_ELF, func_name="main")
    if not r.ok:
        fails.append(f"decompile main 失败: {r.error}")
    elif "// ===== Function: main @" not in r.text or "int main(" not in r.text:
        fails.append("decompile main 内容异常(缺函数头或签名)")
    elif "// ===== Function:" in r.text.split("// ===== Function: main @", 1)[1].replace("00104ea0 =====", "", 1):
        fails.append("decompile 切片未在下一个函数头截断,串进了后续函数")

    # 函数不存在 → 错误应附函数名列表面 + 命名规则提示
    r2 = tools["find_decompiled_function"].execute(file_ref=SAMPLE_ELF, func_name="no_such_fn")
    if r2.ok or "_init" not in (r2.error or ""):
        fails.append(f"不存在函数的错误提示应附函数名列表, got: {r2.error}")
    elif "functions.json" not in (r2.error or ""):
        fails.append("错误提示应指引 functions.json 反查(2026-08-19 E1 落地)")

    # 误带 .c 后缀的宽容解析
    r3 = tools["find_decompiled_function"].execute(file_ref=SAMPLE_ELF + ".c", func_name="main")
    if not r3.ok:
        fails.append(f"带 .c 后缀解析失败: {r3.error}")

    # 产物缺失 → 明确报错不崩
    r4 = tools["find_decompiled_function"].execute(file_ref="no/such/file", func_name="main")
    if r4.ok:
        fails.append("缺失产物应返回 ok=False")
    return fails


def test_extract_function_edge_cases() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        f = Path(td) / "t.c"
        f.write_text(
            "// ===== Function: a @ 1000 =====\nint a(void){}\n"
            "// ===== Function: b @ 2000 =====\nint b(void){}\n",
            encoding="utf-8",
        )
        if (extract_function(f, "b") or "").strip() != "// ===== Function: b @ 2000 =====\nint b(void){}".strip():
            fails.append("中间函数切片错误")
        # 尾部函数(无下一个头)应收敛到 EOF
        tail = extract_function(f, "x_none")
        if tail is not None:
            fails.append("不存在函数应返回 None")
    return fails


def test_imports_query(tools) -> list[str]:
    fails: list[str] = []
    r = tools["imports_query"].execute(file_ref=SAMPLE_ELF, name="memcpy")
    if not r.ok:
        fails.append(f"imports name 查询失败: {r.error}")
    elif not r.data:
        fails.append("idlc 应导入 memcpy")

    # 危险导入全表
    r2 = tools["imports_query"].execute(file_ref=SAMPLE_ELF)
    if not r2.ok:
        fails.append(f"imports 全表失败: {r2.error}")
    elif not isinstance(r2.data, list):
        fails.append("危险导入应为 list")
    return fails


def test_strings_query(tools) -> list[str]:
    fails: list[str] = []
    # 自定义正则:查 cyclonedds(实测存在于 idlc 字符串)
    r = tools["strings_query"].execute(file_ref=SAMPLE_ELF, pattern="re:libcyclonedds")
    if not r.ok:
        fails.append(f"strings 查询失败: {r.error}")
    elif not r.data:
        fails.append("re:libcyclonedds 应命中(idlc 链接 cycloneddsidl)")

    # 未知模式报错
    r2 = tools["strings_query"].execute(file_ref=SAMPLE_ELF, pattern="bogus")
    if r2.ok:
        fails.append("未知模式应 ok=False")

    # url 模式正常跑(可能零命中但不报错)
    r3 = tools["strings_query"].execute(file_ref=SAMPLE_ELF, pattern="url")
    if not r3.ok:
        fails.append(f"url 模式不应报错: {r3.error}")
    return fails


def test_read_file(tools, process_dir) -> list[str]:
    fails: list[str] = []
    # 越界拒绝
    r = tools["read_file"].execute(path="../../etc/passwd")
    if r.ok:
        fails.append("越界路径应被拒绝")

    r2 = tools["read_file"].execute(path="fileinfo.json", limit=5)
    if not r2.ok:
        fails.append(f"读 fileinfo.json 失败: {r2.error}")
    elif len(r2.text.splitlines()) > 7:  # header + 5 行 + 截断提示
        fails.append("limit 生效失败")

    # offset 越界
    r3 = tools["read_file"].execute(path="fileinfo.json", offset=10**9)
    if r3.ok:
        fails.append("offset 超界应报错")
    return fails


def test_make_tools_exclude() -> list[str]:
    """注册表可选排除(离线):exclude 参数与 STEP5_EXCLUDE_TOOLS 环境变量。"""
    import os
    fails: list[str] = []
    from firmware_audit.step5_agent.providers.tools import make_tools as _mk
    ctx = ToolContext(process_dir=Path(tempfile.gettempdir()))

    full = _mk(ctx)
    for name in ("semgrep_scan", "gitleaks_scan", "sandbox_verify",
                 "binwalk_rescan", "web_search", "cve_bin_tool_scan"):
        if name not in full:
            fails.append(f"默认注册表缺 {name}")

    part = _mk(ctx, exclude={"cve_bin_tool_scan"})
    if "cve_bin_tool_scan" in part:
        fails.append("exclude={'cve_bin_tool_scan'} 后 cve_bin_tool_scan 仍存在")
    if len(part) != len(full) - 1:
        fails.append(f"排除后数量异常: {len(part)} vs {len(full) - 1}")

    # 环境变量默认排除(显式 exclude=None 时生效)
    old = os.environ.get("STEP5_EXCLUDE_TOOLS")
    try:
        os.environ["STEP5_EXCLUDE_TOOLS"] = "cve_bin_tool_scan,web_search"
        env_part = _mk(ctx)  # 未显式传 exclude → 读 env
        if "cve_bin_tool_scan" in env_part or "web_search" in env_part:
            fails.append("STEP5_EXCLUDE_TOOLS 未生效")
        if "checksec" not in env_part:
            fails.append("env 排除不应影响其他工具")
    finally:
        if old is None:
            os.environ.pop("STEP5_EXCLUDE_TOOLS", None)
        else:
            os.environ["STEP5_EXCLUDE_TOOLS"] = old
    return fails


def test_main() -> int:
    process_dir = _find_process_dir()
    if process_dir is None:
        print("[SKIP] target/1 工件不存在,读盘工具测试跳过")
        return 0

    ctx = ToolContext(process_dir=process_dir)
    tools = make_tools(ctx)

    failures = 0
    for name, fn in [
        ("resolve_and_decompile", lambda: test_resolve_and_decompile(tools)),
        ("extract_function_edge_cases", test_extract_function_edge_cases),
        ("imports_query", lambda: test_imports_query(tools)),
        ("strings_query", lambda: test_strings_query(tools)),
        ("read_file", lambda: test_read_file(tools, process_dir)),
        ("make_tools_exclude", test_make_tools_exclude),
    ]:
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
