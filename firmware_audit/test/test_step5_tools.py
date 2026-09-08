"""Step5 读盘工具单测:find_decompiled_function / imports_query / strings_query / read_file。

用真实 target/1 工件验证(读盘工具的输入契约就是 Step4 产出格式);
工件目录不存在时全部 SKIP(不影响 CI 环境)。
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import make_tools
from firmware_audit.step5_agent.providers.tools.base import ToolContext
from firmware_audit.step5_agent.providers.tools import cve_bin_tool_scan as cbt
from firmware_audit.step5_agent.providers.tools.find_decompiled_function import extract_function
from firmware_audit.step5_agent.providers.tools.imports_query import format_hits

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


def test_format_hits_trigger() -> list[str]:
    """format_hits 触发层指引(2026-08-23,三层策略第 2 层):

    call_sites 为空 → 附加"用 xref_query 补查,勿判未调用"指引;
    全部有调用点 → 无指引。构造数据,不依赖真实工件。
    """
    fails: list[str] = []
    hint = "请用 xref_query"

    # 1. call_sites 全空 → 必须带指引
    all_empty = [
        {"name": "system", "level": "high", "ref_count": 1, "call_sites": []},
        {"name": "strcpy", "level": "high", "ref_count": 1, "call_sites": None},
    ]
    out1 = format_hits(all_empty)
    if hint not in out1:
        fails.append(f"call_sites 全空时应附 xref 指引:\n{out1}")

    # 2. 全部有调用点 → 不带指引
    all_filled = [
        {"name": "system", "level": "high", "ref_count": 1,
         "call_sites": ["0x8996", "0x28864"]},
    ]
    out2 = format_hits(all_filled)
    if hint in out2:
        fails.append(f"call_sites 齐全时不应附 xref 指引:\n{out2}")

    # 3. 混合(部分空部分有)→ 带指引
    mixed = [
        {"name": "system", "level": "high", "ref_count": 1, "call_sites": ["0x8996"]},
        {"name": "dlopen", "level": "medium", "ref_count": 1, "call_sites": []},
    ]
    out3 = format_hits(mixed)
    if hint not in out3:
        fails.append(f"混合场景应附 xref 指引:\n{out3}")

    # 4. hits 为空 → 不崩、无指引
    out4 = format_hits([])
    if hint in out4 or out4 != "":
        fails.append(f"空 hits 应输出空串且无指引:\n{out4!r}")
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

    # None 缺参快速失败(不静默转空串列根,C4 契约回归 guard;
    # ADR-0004 起改为契约层优雅类型错误,不再暴露 Python 异常文案)
    r4 = tools["read_file"].execute(path=None)
    if r4.ok or "类型错误" not in (r4.error or ""):
        fails.append(f"None 缺参应优雅失败, got ok={r4.ok} err={r4.error}")

    # 未知参数优雅拦截(ADR-0004):recursive 传给 read_file → 列出合法参数而非 TypeError
    r5 = tools["read_file"].execute(path="fileinfo.json", recursive=True)
    if r5.ok or "未知参数 recursive" not in (r5.error or "") or "path/offset/limit" not in (r5.error or ""):
        fails.append(f"recursive 应被优雅拦截, got ok={r5.ok} err={r5.error}")
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


def test_list_files() -> list[str]:
    """list_files(参考 deepaudit ListFiles):目录/递归/排除/截断/越界(纯离线)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # 造树:bin(脚本)、usr/lib(应被排除)、module(脚本)
        (root / "bin").mkdir()
        (root / "bin" / "svc").write_text("#!/bin/sh", encoding="utf-8")
        (root / "usr" / "lib" / "x86_64").mkdir(parents=True)
        (root / "usr" / "lib" / "x86_64" / "libc.so").write_text("x", encoding="utf-8")
        (root / "module").mkdir()
        (root / "module" / "net.py").write_text("print(1)", encoding="utf-8")
        ctx = ToolContext(process_dir=root)
        t = ctx and make_tools(ctx)["list_files"]

        # 顶层枚举:目录项带 /
        r = t.execute(directory=".")
        if not r.ok or "bin/" not in r.text or "usr/" not in r.text:
            fails.append(f"顶层枚举应含目录项: {r.text[:120]}")

        # 递归:usr/lib 被排除,module 下钻可见
        r2 = t.execute(directory=".", recursive=True)
        if "libc.so" in r2.text:
            fails.append("recursive 应排除 usr/lib(SDK/系统库)")
        if "module/net.py" not in r2.text or "bin/svc" not in r2.text:
            fails.append(f"recursive 应列出非排除目录文件: {r2.text[:150]}")

        # pattern 过滤
        r3 = t.execute(directory="module", pattern="*.py")
        if not r3.ok or "net.py" not in r3.text:
            fails.append(f"pattern 过滤失败: {r3.text[:80]}")

        # max_files 截断提示
        r4 = t.execute(directory=".", recursive=True, max_files=2)
        if r4.ok and "截断" not in r4.text:
            fails.append(f"超上限应提示截断: {r4.text[-120:]}")

        # 越界/不存在(失败不崩)
        r5 = t.execute(directory="../outside")
        if r5.ok or "越界" not in (r5.error or ""):
            fails.append(f"越界应拒绝: {r5.error}")
        r6 = t.execute(directory="no/such/dir")
        if r6.ok or "不存在" not in (r6.error or ""):
            fails.append(f"不存在目录应报错: {r6.error}")
        # path 别名(deepaudit 兼容)
        r7 = t.execute(path="module")
        if not r7.ok or "net.py" not in r7.text:
            fails.append(f"path 别名应等价 directory: {r7.error or r7.text[:60]}")
    return fails


def test_search_code() -> list[str]:
    """search_code 混合检索(纯离线):边车索引 + extracted 文本 grep 双路。

    - 边车: strings.json/imports.json/text.json 命中带 地址/调用点 锚点
    - 文本: extracted/ 下的 .py/.sh 按行命中;SDK 目录排除;二进制跳过
    - 错误: 空 keyword / 越界 directory / 非法正则 → ok=False
    - 守卫: 根目录(".")、agent/、.cve_cache 范围拒绝(2026-09-03 卡死修复)
    """
    import json as _json
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        # --- process/analysis 边车(两路都应命中) ---
        ana = root / "analysis" / "unitree" / "bin"
        ana.mkdir(parents=True)
        (ana / "idlc.strings.json").write_text(_json.dumps({
            "program": "idlc", "version": 2,
            "strings": [{"address": "0010d6a1", "value": "password=unitree2018",
                         "refs": ["main"]}],
        }), encoding="utf-8")
        (ana / "idlc.imports.json").write_text(_json.dumps([
            {"name": "system", "address": "EXTERNAL:0001", "ref_count": 2,
             "call_sites": ["main+0x10"]},
        ]), encoding="utf-8")
        (ana / "srv.text.json").write_text(_json.dumps({
            "path": "etc/srv", "type": "text", "count": 1,
            "findings": [{"type": "url", "match": "http://x", "line": 42}],
        }), encoding="utf-8")
        # --- process/extracted 文本源 ---
        ext = root / "extracted" / "module"
        ext.mkdir(parents=True)
        (ext / "net_switcher.py").write_text(
            "#!/usr/bin/python\nimport os\ncmd = os.system('echo '%s' % q)\n"
            "password = 'hardcoded-pass'\n", encoding="utf-8")
        (ext / "srv.conf").write_text("port=8080\npassword=conf-secret\n",
                                      encoding="utf-8")
        (root / "extracted" / "usr" / "lib" / "x").mkdir(parents=True)
        (root / "extracted" / "usr" / "lib" / "x" / "a.py").write_text(
            "password = 'sdk-skip-me'\n", encoding="utf-8")
        # 二进制文件(应被嗅探跳过)
        (ext / "blob.bin").write_bytes(b"\x00\x01password\x00")
        # --- 2026-09-03 卡死修复的范围守卫 fixture ---
        # .cve_cache: cve-bin-tool 预热缓存卷(生产实测 10.7万 json/yml,
        # 全在 _TEXT_EXTS 白名单,进 grep 范围会磨数十分钟)
        cve = root / ".cve_cache" / "cve-bin-tool" / "redhat"
        cve.mkdir(parents=True)
        (cve / "CVE-1999-0001.json").write_text('{"a": "password=cache-hit"}',
                                                encoding="utf-8")
        # agent/: 运行工件(transcript/obs/终端转储)
        ag = root / "agent" / "0_recon" / "obs"
        ag.mkdir(parents=True)
        (ag / "step001_read_file.txt").write_text("password = 'agent-log-hit'\n",
                                                  encoding="utf-8")
        # analysis 下的非边车文本(.c):并集语义的判别器——边车路永远扫
        # analysis,只有文本 grep 也能命中它才证明并集真的进了 analysis 树
        (ana / "decompiled.c").write_text("void f(){ system(union_grep_marker); }\n",
                                          encoding="utf-8")

        t = make_tools(ToolContext(process_dir=root))["search_code"]

        # 边车 + 文本双路命中
        r = t.execute(keyword="password")
        if not r.ok or "idlc.strings.json" not in r.text:
            fails.append(f"边车路应命中 strings.json: {r.text[:200]}")
        if "0010d6a1" not in r.text:
            fails.append(f"strings 命中应带地址锚点: {r.text[:200]}")
        if "net_switcher.py" not in r.text or "srv.conf" not in r.text:
            fails.append(f"文本路应命中 extracted 脚本/配置: {r.text[:200]}")
        if "sdk-skip-me" in r.text:
            fails.append("SDK 目录(usr/lib)应被排除")
        if "blob.bin" in r.text:
            fails.append("二进制文件应被嗅探跳过")

        # imports 命中(带调用点)
        r2 = t.execute(keyword="system")
        if "idlc.imports.json" not in r2.text or "call_sites" not in r2.text:
            fails.append(f"imports 边车命中应有调用点: {r2.text[:200]}")

        # text.json 边车(URL 关键词)
        r3 = t.execute(keyword="http://x")
        if "srv.text.json" not in r3.text or ":42" not in r3.text:
            fails.append(f"text.json 边车命中应有行锚点: {r3.text[:200]}")

        # 正则
        r4 = t.execute(keyword=r"passw\w+", is_regex=True)
        if not r4.ok or not r4.text.startswith("## search_code"):
            fails.append(f"正则模式应工作: {r4.text[:120]}")

        # file_pattern 只过滤文本路(边车路不受影响)
        r5 = t.execute(keyword="password", file_pattern="*.py")
        if "net_switcher.py" not in r5.text or "srv.conf" in r5.text:
            fails.append(f"file_pattern 应过滤文本路(.py 留 .conf 去): {r5.text[:160]}")
        if "idlc.strings.json" not in r5.text:
            fails.append("file_pattern 不应影响边车索引路")

        # 错误路径
        if t.execute(keyword="").ok:
            fails.append("空 keyword 应 ok=False")
        if t.execute(keyword="zzz_no_hit_outer", directory="../../etc").ok:
            fails.append("越界 directory 应 ok=False")
        if t.execute(keyword="[", is_regex=True).ok:
            fails.append("非法正则应 ok=False")

        # 无命中返回 ok=True 且带搜索统计
        r6 = t.execute(keyword="zzz_none")
        if not r6.ok or "未找到匹配" not in r6.text:
            fails.append(f"无命中应 ok=True: {r6.text[:120]}")
        if "边车" not in r6.text or "文本" not in r6.text:
            fails.append(f"无命中应报搜索统计: {r6.text[:120]}")

        # --- 范围语义(2026-09-04 重定义:根/默认 = extracted+analysis 并集) ---
        # 并集不得命中 .cve_cache/agent 内容(防范围扩张回归 + 证据污染)
        rg = t.execute(keyword="password")
        if "cache-hit" in rg.text or "agent-log-hit" in rg.text:
            fails.append(f"并集范围不得命中 .cve_cache/agent: {rg.text[:160]}")
        # 根/默认/一切解析到根的形态:全部合法且等价(并集),文本 grep 两棵子树都进
        for alias in (None, ".", "./", "extracted/.."):
            ru = t.execute(keyword="union_grep_marker",
                           **({} if alias is None else {"directory": alias}))
            if not ru.ok:
                fails.append(f"根/默认应合法 directory={alias!r}: {ru.error}")
            elif "decompiled.c" not in ru.text:
                fails.append(f"并集文本 grep 应含 analysis 子树 directory={alias!r}: {ru.text[:120]}")
        ru2 = t.execute(keyword="password")
        if "net_switcher.py" not in ru2.text:
            fails.append(f"并集应含 extracted 文本命中: {ru2.text[:120]}")
        # 树名 = 该树根(收窄,非并集别名):analysis 树名能查到 analysis 文本,
        # extracted 树名查不到(2026-09-04 修复:树名不得拼成 extracted/extracted)
        ra1 = t.execute(keyword="union_grep_marker", directory="analysis")
        if not ra1.ok or "decompiled.c" not in ra1.text:
            fails.append(f"analysis 树名应命中其下文本: {ra1.text[:120]}")
        ra2 = t.execute(keyword="union_grep_marker", directory="extracted")
        if not ra2.ok or "未找到匹配" not in ra2.text:
            fails.append(f"extracted 树名收窄不得命中 analysis 文本: {ra2.text[:120]}")
        # 守卫范围一律 ok=False:错误带指引且回显 directory 值(断言契约
        # 而非完整文案,同 2026-09-03 encoding 踩坑教训)。
        # 含 .. 穿越形态(2026-09-04 code-review 实证漏洞:字符串前缀匹配
        # 放行 "extracted/../.cve_cache",必须按解析后物理位置判 containment)
        for bad in (".cve_cache", ".cve_cache/cve-bin-tool",
                    "agent", "agent/0_recon",
                    "extracted/../.cve_cache", "analysis/../agent",
                    "extracted/../../.cve_cache"):
            rb = t.execute(keyword="password", directory=bad)
            if rb.ok:
                fails.append(f"守卫范围应拒绝 directory={bad!r}: {rb.text[:120]}")
            elif str(bad) not in (rb.error or ""):
                fails.append(f"守卫错误应回显 directory={bad!r}: {rb.error}")
        # 绕过回归:边车命中已满 max_results 时守卫仍须拦截(code-review 补)
        rb2 = t.execute(keyword="password", directory="agent", max_results=1)
        if rb2.ok:
            fails.append(f"边车满 n 时守卫目录仍应拒绝: {rb2.text[:120]}")
        # 显式收窄约束两路:extracted 子树查询不带 analysis 文本与边车命中
        # (2026-09-04 code-review:旧版边车路无视收窄)
        r7 = t.execute(keyword="password", directory="extracted/module")
        if not r7.ok:
            fails.append(f"extracted 收窄应合法: {r7.error}")
        else:
            if "union_grep_marker" in r7.text:
                fails.append(f"extracted 收窄不得命中 analysis 文本: {r7.text[:120]}")
            if "idlc.strings.json" in r7.text or "srv.text.json" in r7.text:
                fails.append(f"extracted 收窄不得命中 analysis 边车: {r7.text[:120]}")
            if "net_switcher.py" not in r7.text:
                fails.append(f"extracted 收窄应命中本树文本: {r7.text[:120]}")
        # analysis 子树收窄:边车照常(在范围内)
        r8 = t.execute(keyword="password", directory="analysis")
        if not r8.ok or "idlc.strings.json" not in r8.text:
            fails.append(f"analysis 收窄应命中边车: {r8.error or r8.text[:120]}")
    return fails


def test_resolve_analysis_file_tolerant() -> list[str]:
    """resolve_analysis_file 宽容解析(ADR-0008):file_ref 带 extracted/ 前缀
    也能命中 analysis/ 下 sidecar(剥前缀),防止 file 统一成工具路径后
    Agent 把 extracted/ 带进 file_ref 白吃一轮"产物缺失"。"""
    from firmware_audit.step5_agent.providers.tools.base import (
        ToolContext, resolve_analysis_file)

    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        side = root / "analysis" / "unitree" / "bin"
        side.mkdir(parents=True)
        (side / "idlc.c").write_text("int main(){}\n", encoding="utf-8")
        ctx = ToolContext(process_dir=root)
        r1 = resolve_analysis_file(ctx, "unitree/bin/idlc", ".c")
        r2 = resolve_analysis_file(ctx, "extracted/unitree/bin/idlc", ".c")
        if r1 is None:
            fails.append("基线:逻辑路径 file_ref 应命中")
        elif r2 != r1:
            fails.append(f"extracted/ 前缀应宽容解析等价: {r2} != {r1}")
        # 后缀误带 + 前缀组合
        r3 = resolve_analysis_file(ctx, "extracted/unitree/bin/idlc.c", ".c")
        if r3 != r1:
            fails.append(f"前缀+误带后缀组合应解析: {r3}")
        # 越界仍拒绝(宽容不放松安全约束)
        if resolve_analysis_file(ctx, "../../etc/passwd", ".c") is not None:
            fails.append("越界 file_ref 仍应拒绝")
    return fails


def test_cve_cache_dir_env(tmp_path: Path) -> list[str]:
    """CVE 缓存挂载目录(工单 03):缺省 = process/.cve_cache(与现状逐字节
    一致,容器侧仍挂 /home/sandbox/.cache);FIRMWARE_AUDIT_CVE_CACHE_DIR
    覆盖挂载源(共享库预热一次跨 target 复用)。纯单测,不依赖 Docker/工件。"""
    fails: list[str] = []
    ctx = ToolContext(process_dir=tmp_path)
    (tmp_path / "extracted").mkdir()
    (tmp_path / "extracted" / "app").write_bytes(b"\x7fELF")

    captured: dict = {}

    def fake_run_in_sandbox(args, entrypoint, ctx, timeout=0,
                            extra_mounts=None, **kw):
        captured["mounts"] = extra_mounts
        return 0, "[]", ""

    env_name = cbt.CVE_CACHE_ENV
    old = os.environ.get(env_name)
    old_fn = cbt.run_in_sandbox
    cbt.run_in_sandbox = fake_run_in_sandbox
    try:
        # 缺省:挂载源 = process/.cve_cache(自动创建),容器目标不变
        os.environ.pop(env_name, None)
        r = cbt.CveBinToolScanTool(ctx).execute(file_ref="app")
        if not r.ok:
            fails.append(f"假沙箱下扫描应 ok: {r.error}")
        mounts = captured.get("mounts") or []
        if len(mounts) != 1 or mounts[0] != (tmp_path / ".cve_cache",
                                              cbt.CVE_CACHE_MOUNT):
            fails.append(f"缺省挂载源应为 process/.cve_cache,got {mounts}")
        if not (tmp_path / ".cve_cache").is_dir():
            fails.append("缺省缓存目录应自动创建")

        # env 覆盖:挂载源 = 指定目录(共享库),per-target 目录不再创建
        proc2 = tmp_path / "p2"
        proc2.mkdir()
        ctx2 = ToolContext(process_dir=proc2)
        shared = tmp_path / "shared_cve_cache"
        os.environ[env_name] = str(shared)
        cbt.CveBinToolScanTool(ctx2).execute(file_ref="app")
        mounts = captured.get("mounts") or []
        if len(mounts) != 1 or mounts[0] != (shared, cbt.CVE_CACHE_MOUNT):
            fails.append(f"env 覆盖后挂载源应为 {shared},got {mounts}")
        if not shared.is_dir():
            fails.append("env 指定目录应自动创建")
        if (proc2 / ".cve_cache").exists():
            fails.append("env 覆盖时不应再创建 per-target 缓存目录")

        # 解析函数直测:空白 env 视同缺省
        os.environ[env_name] = "   "
        if cbt.resolve_cve_cache_dir(proc2) != proc2 / ".cve_cache":
            fails.append("空白 env 应回落 per-target 缺省")
    finally:
        cbt.run_in_sandbox = old_fn
        if old is None:
            os.environ.pop(env_name, None)
        else:
            os.environ[env_name] = old
    return fails


def test_main() -> int:
    # 纯单测组:不依赖 target/1 工件,SKIP 门槛之外先跑
    standalone_failures = 0
    for name, fn in [
        ("cve_cache_dir_env", lambda: test_cve_cache_dir_env(
            Path(tempfile.mkdtemp(prefix="test_cve_cache_")))),
    ]:
        fl = fn()
        if fl:
            standalone_failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")

    process_dir = _find_process_dir()
    if process_dir is None:
        print("[SKIP] target/1 工件不存在,读盘工具测试跳过")
        return 1 if standalone_failures else 0

    ctx = ToolContext(process_dir=process_dir)
    tools = make_tools(ctx)

    failures = 0
    for name, fn in [
        ("resolve_and_decompile", lambda: test_resolve_and_decompile(tools)),
        ("extract_function_edge_cases", test_extract_function_edge_cases),
        ("imports_query", lambda: test_imports_query(tools)),
        ("format_hits_trigger", test_format_hits_trigger),
        ("strings_query", lambda: test_strings_query(tools)),
        ("read_file", lambda: test_read_file(tools, process_dir)),
        ("make_tools_exclude", test_make_tools_exclude),
        ("list_files", test_list_files),
        ("search_code", test_search_code),
        ("resolve_analysis_file_tolerant", test_resolve_analysis_file_tolerant),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")

    print(f"\n结果: {'全部通过' if failures + standalone_failures == 0 else f'{failures + standalone_failures} 个断言失败'}")
    return 1 if failures + standalone_failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())
