"""Step5 工具解析专项测试:输入容错 + 输出提取(mock,不依赖 Docker/工件)。

三层覆盖:
  A. 纯函数输出提取:CLI 原始 stdout → 结构化 ToolResult.data 的解析逻辑
  B. 工具级解析:mock run_in_sandbox,验证各形态输出正确结构化
  C. 输入解析:畸形 Action Input(None/缺参/未知参/路径穿越)不崩且错误回喂
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools.base import (
    ToolContext, truncate_text,
)
from firmware_audit.step5_agent.providers.tools.cli_base import container_path
from firmware_audit.step5_agent.providers.tools.cve_bin_tool_scan import (
    _extract_json, _flatten,
)
from firmware_audit.step5_agent.providers.tools.r2_base import parse_r2_json as _parse_r2_json
from firmware_audit.step5_agent.providers.tools.web_search import _parse_ddg
from firmware_audit.step5_agent.providers.tools.cve_lookup import _format

_TOOLS_PKG = "firmware_audit.step5_agent.providers.tools"


def _make_ctx(root: Path) -> ToolContext:
    """最小工件树:extracted/ 下一个真实文件供路径解析。"""
    (root / "extracted" / "bin").mkdir(parents=True, exist_ok=True)
    f = root / "extracted" / "bin" / "app"
    if not f.exists():
        f.write_bytes(b"\x7fELF")
    return ToolContext(process_dir=root)


@pytest.fixture()
def ctx(tmp_path: Path) -> ToolContext:
    return _make_ctx(tmp_path)


# ---------- A. 纯函数输出提取 ----------

def test_extract_json_forms() -> list[str]:
    fails: list[str] = []
    # 纯 JSON
    if _extract_json('[{"a": 1}]') != [{"a": 1}]:
        fails.append("纯 JSON 数组解析失败")
    # 日志混 JSON(cve-bin-tool 实际形态:INFO 行 + 结果块)
    mixed = ("[INFO] scanning...\n"
             '[{"product": "curl", "version": "7.5", "cve_number": "CVE-1"}]\n'
             "[INFO] done")
    if _extract_json(mixed) != [{"product": "curl", "version": "7.5",
                                 "cve_number": "CVE-1"}]:
        fails.append("日志混 JSON 提取失败")
    # 多块取最长(短 JSON 是日志片段,长 JSON 是真结果)
    two = '[{"x": 1}]\nlog line\n[{"product": "zlib", "hits": 2}, {"p": "ssl"}]'
    got = _extract_json(two)
    if not (isinstance(got, list) and len(got) == 2):
        fails.append(f"多 JSON 块应取最长, got: {got}")
    # 无 JSON
    if _extract_json("plain text only") is not None:
        fails.append("无 JSON 应回 None")
    # dict 形态
    if _extract_json('{"results": [1]}') != {"results": [1]}:
        fails.append("dict JSON 解析失败")
    return fails


def test_flatten_forms() -> list[str]:
    fails: list[str] = []
    items = [{"product": "a"}, {"product": "b"}]
    if _flatten(items) != items:
        fails.append("list 形态压平失败")
    if _flatten({"results": items}) != items:
        fails.append("{results:} 形态失败")
    if _flatten({"hits": items}) != items:
        fails.append("{hits:} 形态失败")
    if _flatten({"other": items}) != []:
        fails.append("未知 key 应返回空")
    if _flatten(None) != []:
        fails.append("None 应返回空")
    if _flatten([1, "x", {"ok": 1}]) != [{"ok": 1}]:
        fails.append("非 dict 元素应被过滤")
    return fails


def test_parse_r2_json() -> list[str]:
    fails: list[str] = []
    hit = '[{"from": "0x1000", "fcn_name": "main", "type": "CALL"}]'
    # 纯 JSON(r2 -q 输出)
    if _parse_r2_json(hit + "\n") != [{"from": "0x1000", "fcn_name": "main",
                                       "type": "CALL"}]:
        fails.append("纯 JSON 解析失败")
    # 前置日志行,尾部才是结果(r2 实际形态)
    if _parse_r2_json("INFO anal\nWARN x\n" + hit) is None:
        fails.append("日志前缀应被跳过")
    # 非数组 JSON 行应跳过,继续向前找
    if _parse_r2_json('{"not": "array"}\n' + hit) is None:
        fails.append("dict JSON 行应跳过并回退")
    # 空数组 = 无交叉引用(合法结果,由 _run 转为 ok=True 空表)
    if _parse_r2_json("[]") != []:
        fails.append("空数组应返回 [](非 None)")
    # 空输出
    if _parse_r2_json("") is not None:
        fails.append("空输出应返回 None")
    # 跨行缩进数组(2026-08-22 实发):分析 WARN 后 r2 axtj 输出多行数组,逐行找单行 `[` 会漏
    pretty = ('WARN: Unsupported reloc type 1030 for aarch64\n'
              '[\n  {\n    "from": "0x006409bc", "fcn_name": "main", "type": "CALL"\n  }\n]\n')
    if _parse_r2_json(pretty) != [{"from": "0x006409bc", "fcn_name": "main", "type": "CALL"}]:
        fails.append("跨行缩进数组应能解析")
    # 字符串内含 [ ] 不干扰配平
    tricky = '[\n  {"path": "a[b].c", "n": 1}\n]\n'
    if _parse_r2_json(tricky) != [{"path": "a[b].c", "n": 1}]:
        fails.append("字符串内方括号不应干扰配平")
    return fails


def test_xref_data_symbol_hint(ctx) -> list[str]:
    """r2_xref_query 对 r2 data 符号 Invalid argument 应给可操作指引(2026-08-22 实发)。"""
    import firmware_audit.step5_agent.providers.tools.r2_base as r2_base
    import firmware_audit.step5_agent.providers.tools.r2_xref_query as xq
    fails: list[str] = []
    captured: dict = {}

    def fake_run_in_sandbox(args, entrypoint, ctx, timeout=180, extra_mounts=None):
        captured["args"] = list(args)
        # 复现实测: r2 对 data 符号报 Invalid argument,stdout 无 JSON
        return 0, "INFO: Analyze all...\nERROR: Invalid argument\n", "WARN: Relocs..."

    # r2 族共享名在 r2_base 命名空间(经 run_r2 调用),补丁挂那里
    orig = r2_base.run_in_sandbox
    r2_base.run_in_sandbox = fake_run_in_sandbox
    try:
        r = xq.R2XrefQueryTool(ctx).execute(file_ref="bin/app", symbol="sym.video_device_path")
        if r.ok:
            fails.append("data 符号查询应失败")
        elif "数据符号" not in (r.error or ""):
            fails.append(f"错误应含 data 符号指引: {r.error}")
        elif "strings_query" not in (r.error or ""):
            fails.append(f"错误应指引替代工具: {r.error}")
        # 新参数 -e bin.relocs.apply=true 应出现在命令里
        if "bin.relocs.apply=true" not in " ".join(captured.get("args", [])):
            fails.append(f"r2 命令应含 relocs.apply 参数: {captured.get('args')}")
    finally:
        r2_base.run_in_sandbox = orig
    return fails


def test_parse_ddg() -> list[str]:
    fails: list[str] = []
    html = (
        '<html><body>'
        '<div class="result results_links">'
        '<a rel="nofollow" class="result__a" '
        'href="//duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fa&amp;rut=abc">'
        'Example <b>Title</b></a>'
        '<a class="result__snippet" href="#">Some <i>snippet</i> text</a>'
        '</div>'
        '<div class="result results_links">'
        '<a rel="nofollow" class="result__a" href="https://direct.org/b">'
        'Direct Link</a>'
        '</div>'
        '</body></html>'
    )
    rs = _parse_ddg(html)
    if len(rs) != 2:
        fails.append(f"应解析 2 条结果, got {len(rs)}")
    else:
        if rs[0]["url"] != "https://example.com/a":
            fails.append(f"uddg 重定向解包失败: {rs[0]['url']}")
        if rs[0]["title"] != "Example Title":
            fails.append(f"title 应去标签: {rs[0]['title']!r}")
        if rs[0]["snippet"] != "Some snippet text":
            fails.append(f"snippet 应去标签: {rs[0]['snippet']!r}")
        if rs[1]["url"] != "https://direct.org/b":
            fails.append("直连 URL 应保留")
    # 无结果页
    if _parse_ddg("<html>no results</html>") != []:
        fails.append("无结果应返回空表")
    return fails


def test_cve_format() -> list[str]:
    fails: list[str] = []
    # 无记录
    if "无记录" not in _format({"totalResults": 0, "vulnerabilities": []}):
        fails.append("totalResults=0 应提示无记录")
    # 有记录带 CVSS
    raw = {
        "totalResults": 1,
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-1234",
                "descriptions": [{"lang": "en", "value": "Buffer overflow in x"}],
                "metrics": {"cvssMetricV31": [{
                    "cvssData": {"baseScore": 9.8}}]},
            }}],
    }
    text = _format(raw)
    for expect in ("CVE-2024-1234", "9.8", "Buffer overflow"):
        if expect not in text:
            fails.append(f"格式化缺 {expect}: {text}")
    return fails


def test_truncate_text() -> list[str]:
    fails: list[str] = []
    short = "x" * 100
    if truncate_text(short) != short:
        fails.append("≤16k 不应截断")
    exact = "y" * 16000
    if truncate_text(exact) != exact:
        fails.append("恰好 16000 字符不应截断")
    long = "A" * 12000 + "M" * 3000 + "Z" * 4000  # 共 19000
    out = truncate_text(long)
    if len(out) > 16000 + 200:
        fails.append(f"截断后长度异常: {len(out)}")
    if "已截断" not in out or "19000" not in out:
        fails.append("截断提示缺总量说明")
    if not out.startswith("A" * 12000):
        fails.append("头部 75% 保留失败")
    if not out.endswith("Z" * 3200):
        fails.append("尾部 20% 保留失败")
    return fails


# ---------- B. 工具级解析(mock 沙箱,双模式可用) ----------

def _mk_tool(module: str, cls_name: str, ctx, ret):
    """构造工具实例并 mock 其 run_in_sandbox → ret=(rc,out,err)。

    补丁点按模块解析:工具模块自身 import 了 run_in_sandbox(checksec/semgrep
    等直接调用)就挂模块属性;r2 族工具经 r2_base.run_r2 调用,共享名在
    r2_base 命名空间,补丁必须挂那里(挂错处 mock 不生效会真调 Docker)。
    mock 在 execute() 时生效;with 块退出恢复。
    """
    mod = importlib.import_module(f"{_TOOLS_PKG}.{module}")
    target = mod if hasattr(mod, "run_in_sandbox") else importlib.import_module(
        f"{_TOOLS_PKG}.r2_base")
    orig = target.run_in_sandbox
    target.run_in_sandbox = lambda *a, **kw: ret

    class _Restore:
        def __init__(self, tool):
            self.tool = tool

        def __enter__(self):
            return self.tool

        def __exit__(self, *exc):
            target.run_in_sandbox = orig
            return False

    return _Restore(getattr(mod, cls_name)(ctx))


def test_checksec_both_shapes(ctx) -> list[str]:
    fails: list[str] = []
    # dict 形态 {"/容器路径": {...}}
    j = json.dumps({"/work/extracted/bin/app": {
        "relro": "partial", "canary": "no", "nx": "yes", "pie": "no"}})
    with _mk_tool("checksec", "ChecksecTool", ctx, (0, j, "")) as t:
        r = t.execute(file_ref="bin/app")
        if not r.ok or r.data.get("relro") != "partial":
            fails.append(f"dict 形态解析失败: {r.error or r.data}")
        if "relro=partial" not in r.text:
            fails.append(f"text 摘要缺属性串: {r.text}")

    # list 形态(旧版 checksec)
    j2 = json.dumps([{"relro": "full", "canary": "yes", "nx": "yes", "pie": "yes"}])
    with _mk_tool("checksec", "ChecksecTool", ctx, (0, j2, "")) as t2:
        r2 = t2.execute(file_ref="bin/app")
        if not r2.ok or r2.data.get("pie") != "yes":
            fails.append(f"list 形态解析失败: {r2.error or r2.data}")

    # 非 JSON / rc≠0
    with _mk_tool("checksec", "ChecksecTool", ctx, (0, "not json", "")) as t3:
        if t3.execute(file_ref="bin/app").ok:
            fails.append("非 JSON 输出应报错")
    with _mk_tool("checksec", "ChecksecTool", ctx, (2, "", "boom")) as t4:
        if t4.execute(file_ref="bin/app").ok:
            fails.append("rc≠0 应报错")
    return fails


def test_gitleaks_scan_output_split(ctx) -> list[str]:
    fails: list[str] = []
    # 无命中:null 报告
    with _mk_tool("gitleaks_scan", "GitleaksScanTool", ctx,
                  (0, "__RC__0\nnull", "")) as t:
        r = t.execute(path=".")
        if not r.ok or r.data != []:
            fails.append(f"null 报告应为无命中: {r.error or r.data}")

    # 有命中:findings 数组,验证脱敏与结构化
    report = json.dumps([{"RuleID": "private-key", "File": "etc/k.pem",
                          "StartLine": 3, "Secret": "ABCDEFGHIJKLMNOP"}])
    with _mk_tool("gitleaks_scan", "GitleaksScanTool", ctx,
                  (0, f"__RC__0\n{report}", "")) as t2:
        r2 = t2.execute(path=".")
        if not r2.ok or not r2.data:
            fails.append(f"findings 应结构化: {r2.error}")
        else:
            if r2.data[0]["secret"] != "ABCDEFGHIJKLMNOP":
                fails.append("data.secret 应保留原文(供复核)")
            if "ABCD********" not in r2.text:
                fails.append(f"text 应脱敏展示: {r2.text}")
            if "private-key" not in r2.text or "etc/k.pem:3" not in r2.text:
                fails.append(f"text 缺定位信息: {r2.text}")

    # gitleaks 自身失败(__RC__1)
    with _mk_tool("gitleaks_scan", "GitleaksScanTool", ctx,
                  (0, "__RC__1\n", "no such dir")) as t3:
        if t3.execute(path=".").ok:
            fails.append("__RC__1 应报错")

    # docker 层失败(rc≠0)
    with _mk_tool("gitleaks_scan", "GitleaksScanTool", ctx,
                  (1, "", "docker fail")) as t4:
        if t4.execute(path=".").ok:
            fails.append("docker 失败应报错")

    # 无标记回退(兼容直接 JSON 输出)
    with _mk_tool("gitleaks_scan", "GitleaksScanTool", ctx, (0, "[]", "")) as t5:
        if not t5.execute(path=".").ok:
            fails.append("无标记的空数组输出应兼容")
    return fails


def test_semgrep_exit_whitelist(ctx) -> list[str]:
    fails: list[str] = []
    # rc=0 无命中
    with _mk_tool("semgrep_scan", "SemgrepScanTool", ctx,
                  (0, json.dumps({"results": []}), "")) as t:
        r = t.execute(path=".")
        if not r.ok or r.data != []:
            fails.append(f"rc=0 无命中: {r.error or r.data}")

    # rc=1 有命中(退出码白名单),重复结果按 (cid,path,line) 去重。
    # 双扫后 run_in_sandbox 被调两次,假件按路区分:extracted 路给命中,
    # analysis C 路(--include)给空——命中只来自一路,去重语义不变。
    import firmware_audit.step5_agent.providers.tools.semgrep_scan as ss2
    results = [
        {"check_id": "cmd-inject", "path": "a.py", "start": {"line": 1},
         "extra": {"severity": "ERROR", "message": "os.system user input"}},
        {"check_id": "cmd-inject", "path": "a.py", "start": {"line": 1},
         "extra": {"severity": "ERROR", "message": "dup"}},
    ]

    def leg_aware_run(args, entrypoint, ctx, timeout=300, extra_mounts=None):
        if "--include" in args:
            return 0, json.dumps({"results": []}), ""
        return 1, json.dumps({"results": results}), ""

    orig2 = ss2.run_in_sandbox
    ss2.run_in_sandbox = leg_aware_run
    try:
        t2 = ss2.SemgrepScanTool(ctx)
        r2 = t2.execute(path=".")
        if not r2.ok:
            fails.append(f"rc=1 有命中应 ok(白名单): {r2.error}")
        elif r2.text.count("cmd-inject") != 1:
            fails.append(f"text 应去重: {r2.text}")
    finally:
        ss2.run_in_sandbox = orig2

    # rc=2 错误
    with _mk_tool("semgrep_scan", "SemgrepScanTool", ctx,
                  (2, "", "config error")) as t3:
        if t3.execute(path=".").ok:
            fails.append("rc=2 应报错")

    # 输出非 JSON
    with _mk_tool("semgrep_scan", "SemgrepScanTool", ctx,
                  (0, "yaml noise", "")) as t4:
        if t4.execute(path=".").ok:
            fails.append("非 JSON 应报错")
    return fails


def test_xref_symbol_prefix(ctx) -> list[str]:
    fails: list[str] = []
    out = ('anal warn\n'
           '[{"from": "0x104ea0", "fcn_name": "idlc_load_generator", "type": "CALL"}]')
    with _mk_tool("r2_xref_query", "R2XrefQueryTool", ctx, (1, out, "")) as t:
        # 裸符号应自动补 sym.imp. 前缀;rc=1 不可靠不影响判定
        r = t.execute(file_ref="bin/app", symbol="system")
        if not r.ok:
            fails.append(f"xref 应以 stdout 解析为准: {r.error}")
        elif not r.data or r.data[0]["fcn_name"] != "idlc_load_generator":
            fails.append(f"xref data 异常: {r.data}")
    # 无引用 → ok=True 空表
    with _mk_tool("r2_xref_query", "R2XrefQueryTool", ctx, (1, "[]", "")) as t2:
        r2 = t2.execute(file_ref="bin/app", symbol="nothing")
        if not r2.ok or r2.data != []:
            fails.append("空数组应为 ok=True 空表")
    return fails


def test_xref_fcn_symbol_becomes_addr(ctx) -> list[str]:
    """票04:symbol=fcn.<hex> 应在下发前转地址形态,且不得再补 sym.imp. 前缀
    (fcn. 名是某次会话内产物,跨会话不保证可解析;裸地址恒成功)。"""
    import firmware_audit.step5_agent.providers.tools.r2_base as r2_base
    import firmware_audit.step5_agent.providers.tools.r2_xref_query as xq
    from firmware_audit.test.replay_spy import ReplaySpy, patched
    fails: list[str] = []
    out = ('anal warn\n'
           '[{"from": "0x104ea0", "fcn_name": "main", "type": "CALL"}]')
    spy = ReplaySpy((1, out, ""))
    restore = patched(r2_base, run_in_sandbox=spy)
    try:
        r = xq.R2XrefQueryTool(ctx).execute(file_ref="bin/app", symbol="fcn.004010c0")
    finally:
        restore()
    if not r.ok:
        fails.append(f"fcn.名转地址后 xref 应以 stdout 解析为准: {r.error}")
    else:
        cmd = " ".join(spy.last["args"][0])
        if "axtj 0x004010c0" not in cmd:
            fails.append(f"axtj 目标应为地址形态: {cmd}")
        if "fcn." in cmd or "sym.imp.0x" in cmd:
            fails.append(f"fcn.名不应原样下发、地址不应再补前缀: {cmd}")
    return fails


# ---------- C. 输入解析(畸形 Action Input) ----------

def test_malformed_inputs(ctx) -> list[str]:
    """畸形调用(ADR-0004):execute 按参数契约优雅拦截,不暴露 Python 异常文案。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.providers.tools.checksec import ChecksecTool
    t = ChecksecTool(ctx)

    # None 参数:契约层类型错误(优雅,非 TypeError 异常文案)
    r = t.execute(file_ref=None)
    if r.ok or "类型错误" not in (r.error or ""):
        fails.append(f"None 参数应契约层拒绝, got ok={r.ok} err={r.error}")
    if (r.error or "").startswith(("TypeError", "AttributeError")):
        fails.append(f"不得暴露 Python 异常文案, got {r.error}")

    # 缺必填参数:契约层列出缺失项
    r2 = t.execute()
    if r2.ok or "缺失必选参数: file_ref" not in (r2.error or ""):
        fails.append(f"缺参应优雅报缺失, got {r2.error}")

    # 未知参数(LLM 多给字段):契约层列出合法清单
    r3 = t.execute(file_ref="bin/app", bogus="x")
    if r3.ok or "未知参数 bogus" not in (r3.error or "") or "file_ref" not in (r3.error or ""):
        fails.append(f"未知参数应优雅列出合法清单, got {r3.error}")

    # execute 统一入口契约:elapsed/raw 填充
    r4 = t.execute(file_ref="../escape")
    if r4.ok:
        fails.append("越界路径应 ok=False")
    if r4.elapsed < 0:
        fails.append("elapsed 应非负")
    return fails


def test_container_path_security(ctx) -> list[str]:
    fails: list[str] = []
    # 正常相对路径
    if container_path(ctx, "bin/app") != "/work/extracted/bin/app":
        fails.append("正常路径换算失败")
    # Windows 反斜杠宽容
    if container_path(ctx, "bin\\app") != "/work/extracted/bin/app":
        fails.append("反斜杠应宽容换算")
    # 穿越拒绝
    for evil in ("../etc/passwd", "..\\..\\windows", "bin/../../x",
                 "/etc/passwd"):
        if container_path(ctx, evil) is not None:
            fails.append(f"穿越路径未被拒绝: {evil}")
    # 不存在的相对路径(容器路径形态合法,由 CLI 层报错)
    if container_path(ctx, "no/such") != "/work/extracted/no/such":
        fails.append("不存在路径应保留容器形态(由 CLI 报错)")
    return fails


# ---------- D. 沙箱挂载纪律(docker -v 宿主路径必须绝对) ----------

def test_run_in_sandbox_absolute_mounts() -> list[str]:
    """挂载宿主路径必须绝对(2026-08-19 checksec/r2_xref_query 实发 bug)。

    相对路径(如 target/1/process/extracted)会被 Docker 当命名卷:
    卷名禁含 "/",daemon 报 create <path>: invalid characters →
    容器未起即 exit 125。mock run_docker 捕获 mounts 断言全绝对。"""
    import os
    import tempfile
    from firmware_audit.step5_agent.providers.tools import cli_base

    fails: list[str] = []
    orig_run_docker = cli_base.run_docker
    old_cwd = os.getcwd()
    try:
        with tempfile.TemporaryDirectory() as td:
            os.chdir(td)
            (Path(td) / "ws" / "extracted").mkdir(parents=True)
            (Path(td) / "rules").mkdir()
            captured: dict = {}

            def fake_run_docker(image, args, mounts=None, **kw):
                captured["mounts"] = list(mounts or [])
                return 0, "", ""

            cli_base.run_docker = fake_run_docker
            # process_dir 故意用相对路径,复现"CLI 传相对 target"的用户形态
            ctx = ToolContext(process_dir=Path("ws"))
            cli_base.run_in_sandbox(
                ["--version"], "checksec", ctx,
                extra_mounts=[(Path("rules"), "/work/rules")])
            hosts = [m[0] for m in captured["mounts"]]
            if not hosts:
                fails.append("未捕获到任何挂载(mock 未生效?)")
            elif not all(Path(h).is_absolute() for h in hosts):
                fails.append(f"所有挂载宿主路径须绝对(相对会被 Docker 当命名卷): {hosts}")
            elif Path(hosts[0]) != (Path(td) / "ws" / "extracted").resolve():
                fails.append(f"extracted 挂载源应指向真实目录: {hosts[0]}")
            elif Path(hosts[1]) != (Path(td) / "rules").resolve():
                fails.append(f"extra_mounts 挂载源同样须绝对: {hosts[1]}")
            os.chdir(old_cwd)  # Windows:先离开 td,TemporaryDirectory 才能清理
    finally:
        cli_base.run_docker = orig_run_docker
        os.chdir(old_cwd)
    return fails


def test_semgrep_sdk_exclude(ctx) -> list[str]:
    """semgrep_scan 目录扫描注入 SDK 排除参数(--exclude 容器绝对路径)。"""
    import firmware_audit.step5_agent.providers.tools.semgrep_scan as ss
    from firmware_audit.step5_agent.providers.tools.cli_base import EXTRACTED_MOUNT
    fails: list[str] = []
    calls: list[list[str]] = []

    def fake_run_in_sandbox(args, entrypoint, ctx, timeout=300, extra_mounts=None):
        calls.append(list(args))
        return 0, '{"results": []}', ""

    orig = ss.run_in_sandbox
    ss.run_in_sandbox = fake_run_in_sandbox
    try:
        r = ss.SemgrepScanTool(ctx).execute(path=".")
        if not r.ok:
            fails.append(f"semgrep path=. 执行失败(应 mock 无障): {r.error}")
        # 双扫(2026-09-04):extracted 路带 SDK --exclude;analysis C 路不带
        ex_legs = [a for a in calls if "--exclude" in a]
        if not ex_legs:
            fails.append(f"无任何 --exclude(共 {len(calls)} 路调用)")
        elif not any(f"{EXTRACTED_MOUNT}/usr/local/lib" in a for a in ex_legs):
            fails.append(f"缺 SDK 排除目标 {EXTRACTED_MOUNT}/usr/local/lib")
        if len(calls) != 2:
            fails.append(f"path=. 应双扫两路(extracted+analysis),实际 {len(calls)} 路")
    finally:
        ss.run_in_sandbox = orig
    return fails


def test_main() -> int:
    """独立运行入口(pytest 下由 conftest 钩子接管断言)。"""
    import tempfile
    failures = 0
    with tempfile.TemporaryDirectory() as td:
        c = _make_ctx(Path(td))
        cases = [
            ("extract_json_forms", test_extract_json_forms),
            ("flatten_forms", test_flatten_forms),
            ("parse_r2_json", test_parse_r2_json),
            ("parse_ddg", test_parse_ddg),
            ("cve_format", test_cve_format),
            ("truncate_text", test_truncate_text),
            ("checksec_both_shapes", lambda: test_checksec_both_shapes(c)),
            ("gitleaks_scan_output_split", lambda: test_gitleaks_scan_output_split(c)),
            ("semgrep_exit_whitelist", lambda: test_semgrep_exit_whitelist(c)),
            ("xref_symbol_prefix", lambda: test_xref_symbol_prefix(c)),
            ("xref_fcn_symbol_becomes_addr", lambda: test_xref_fcn_symbol_becomes_addr(c)),
            ("malformed_inputs", lambda: test_malformed_inputs(c)),
            ("container_path_security", lambda: test_container_path_security(c)),
            ("run_in_sandbox_absolute_mounts", test_run_in_sandbox_absolute_mounts),
            ("semgrep_sdk_exclude", lambda: test_semgrep_sdk_exclude(c)),
            ("xref_data_symbol_hint", lambda: test_xref_data_symbol_hint(c)),
        ]
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
