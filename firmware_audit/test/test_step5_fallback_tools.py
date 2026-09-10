"""票02 strings_query / imports_query 混合型单测(离线,tmp_path 假工件 + mock 沙箱)。

只测外部行为(spec Testing Decisions Seam 1):边车命中零容器;缺边车自动 r2
兜底(izz 不限 ELF / iij 仅 ELF);pattern 双路过滤;都不可得 → 引导性报错。
mock 补丁点:r2 族共享名 run_in_sandbox 在 r2_base 命名空间(经 run_r2 调用);
替身用共享 ReplaySpy + patched(票02 评审收编,原 ReplaySpy/_install 删除)。
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import r2_base
from firmware_audit.step5_agent.providers.tools.base import ToolContext
from firmware_audit.step5_agent.providers.tools.imports_query import ImportsQueryTool
from firmware_audit.step5_agent.providers.tools.strings_query import StringsQueryTool
from firmware_audit.test.replay_spy import ReplaySpy, patched

_ELF_MAGIC = b"\x7fELF" + b"\x02\x01\x01" + b"\x00" * 8


def _make_ctx(root: Path, *, sidecar: bool = True) -> ToolContext:
    """工作区:extracted/bin/app(ELF)+ extracted/data/blob.bin(非 ELF);
    sidecar=True 时带 analysis/bin/app.{strings,imports}.json。"""
    (root / "extracted" / "bin").mkdir(parents=True, exist_ok=True)
    (root / "extracted" / "data").mkdir(parents=True, exist_ok=True)
    (root / "extracted" / "bin" / "app").write_bytes(_ELF_MAGIC)
    (root / "extracted" / "data" / "blob.bin").write_bytes(b"\xde\xad\xbe\xef" * 4)
    if sidecar:
        ana = root / "analysis" / "bin"
        ana.mkdir(parents=True, exist_ok=True)
        (ana / "app.strings.json").write_text(json.dumps({
            "strings": [
                {"address": "0x1000", "value": "http://vendor-ota.example.com/fw.bin", "refs": []},
                {"address": "0x2000", "value": "nothing special", "refs": []},
            ]}, ensure_ascii=False), encoding="utf-8")
        (ana / "app.imports.json").write_text(json.dumps([
            {"name": "system", "address": "0x00401060", "ref_count": 3,
             "call_sites": [{"from": "0x00400abc", "function": "main"}]},
            {"name": "memcpy", "address": "0x00401070", "ref_count": 9, "call_sites": []},
        ]), encoding="utf-8")
    return ToolContext(process_dir=root)


def _install(spy: ReplaySpy):
    return patched(r2_base, run_in_sandbox=spy)


def _izzj(pairs: list[tuple[str, str]]) -> str:
    return json.dumps([
        {"vaddr": addr, "paddr": addr, "ordinal": i, "size": len(s),
         "length": len(s), "section": "", "type": "ascii", "string": s}
        for i, (addr, s) in enumerate(pairs)
    ])


def test_strings_sidecar_hit_zero_container() -> list[str]:
    fails: list[str] = []
    spy = ReplaySpy()
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td), sidecar=True)
            r = StringsQueryTool(ctx).execute(file_ref="bin/app", pattern="url")
    finally:
        restore()
    if not r.ok:
        fails.append(f"边车路应成功: {r.error}")
    elif not r.data or r.data[0]["match"] != "http://vendor-ota.example.com/fw.bin":
        fails.append(f"边车命中异常: {r.data}")
    elif "边车" not in r.text:
        fails.append(f"text 应注明来源边车: {r.text[:120]}")
    if spy.calls:
        fails.append(f"边车命中不得调容器: {spy.calls}")
    return fails


def test_strings_fallback_with_pattern_non_elf() -> list[str]:
    """缺边车 → 自动 r2 izz 兜底;非 ELF 也放行(ADR-0010);pattern 双路过滤。"""
    fails: list[str] = []
    izzj = _izzj([
        ("0x1000", "http://evil.example.com/x"),
        ("0x2000", "just a plain string"),
        ("0x3000", "https://second.example.org/y"),
    ])
    spy = ReplaySpy((0, izzj, ""))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td), sidecar=False)
            r = StringsQueryTool(ctx).execute(file_ref="data/blob.bin", pattern="url")
    finally:
        restore()
    if not r.ok:
        fails.append(f"兜底路应成功(非 ELF 放行): {r.error}")
        return fails
    if len(r.data) != 2:
        fails.append(f"pattern 应过滤掉非命中项: {r.data}")
    elif "r2 izz" not in r.text:
        fails.append(f"text 应注明来源 r2 izz: {r.text[:120]}")
    if spy.last["args"][1] != "r2" or "izzj" not in " ".join(spy.last["args"][0]):
        fails.append(f"兜底应为 r2 izzj 命令: {spy.last['args']}")
    return fails


def test_strings_both_unavailable_guidance() -> list[str]:
    fails: list[str] = []
    spy = ReplaySpy((1, "", "r2 error"))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td), sidecar=False)
            r = StringsQueryTool(ctx).execute(file_ref="data/missing.bin", pattern="url")
    finally:
        restore()
    if r.ok:
        fails.append("都不可得应 ok=False")
    else:
        for needle in ("list_files", "binwalk_rescan", "read_file"):
            if needle not in (r.error or ""):
                fails.append(f"报错应含下一步指引 '{needle}': {r.error}")
    if len(spy.calls) != 1:
        fails.append(f"应恰试一次兜底: {spy.calls}")
    return fails


def test_strings_pattern_invalid_unchanged() -> list[str]:
    """未知模式仍契约层拒绝(不带 pattern 时与现状一致:缺必选参数优雅报错)。"""
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ctx = _make_ctx(Path(td), sidecar=True)
        r = StringsQueryTool(ctx).execute(file_ref="bin/app", pattern="bogus")
        if r.ok or "内置" not in (r.error or ""):
            fails.append(f"未知模式应报错: {r.error}")
        r2 = StringsQueryTool(ctx).execute(file_ref="bin/app")
        if r2.ok or "缺失必选参数: pattern" not in (r2.error or ""):
            fails.append(f"不带 pattern 应保持契约层缺失报错(现状兼容): {r2.error}")
    return fails


def test_strings_step4_patterns_migrated() -> list[str]:
    """Step4 _TEXT_PATTERNS 家族迁接为内置模式(票02 迁接项):wifi_psk/private_key。"""
    fails: list[str] = []
    izzj = _izzj([
        ("0x1000", "psk=supersecret123"),
        ("0x2000", "-----BEGIN RSA PRIVATE KEY-----"),
        ("0x3000", "nothing"),
    ])
    # 两次 execute 各回放一次(模式间互不共享结果)
    spy = ReplaySpy((0, izzj, ""), (0, izzj, ""))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td), sidecar=False)
            for pattern, want in (("wifi_psk", "supersecret123"),
                                  ("private_key", "BEGIN RSA PRIVATE KEY")):
                r = StringsQueryTool(ctx).execute(file_ref="data/blob.bin", pattern=pattern)
                if not r.ok or not r.data or want not in r.data[0]["value"]:
                    fails.append(f"模式 {pattern} 应命中: {r.error or r.data}")
    finally:
        restore()
    return fails


def test_imports_fallback_grading_and_hint() -> list[str]:
    """缺边车 → r2 iij 兜底;危险函数分级表生效;call_sites 空附 r2_xref_query 指引。"""
    fails: list[str] = []
    iij = json.dumps([
        {"name": "system", "plt": "0x00401060", "bind": "WEAK", "type": "FUNC"},
        {"name": "socket", "plt": "0x00401070", "bind": "GLOBAL", "type": "FUNC"},
        {"name": "safe_func", "plt": "0x00401080", "bind": "GLOBAL", "type": "FUNC"},
    ])
    spy = ReplaySpy((0, iij, ""))
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td), sidecar=False)
            r = ImportsQueryTool(ctx).execute(file_ref="bin/app")
    finally:
        restore()
    if not r.ok:
        fails.append(f"iij 兜底应成功: {r.error}")
        return fails
    if len(r.data) != 2 or [h["name"] for h in r.data] != ["system", "socket"]:
        fails.append(f"危险导入表应为 system(high)/socket(low) 排序: {r.data}")
    elif r.data[0].get("level") != "high":
        fails.append(f"system 应分级 high: {r.data[0]}")
    if "r2_xref_query" not in r.text:
        fails.append(f"call_sites 空应附 r2_xref_query 指引: {r.text[:200]}")
    if "r2 iij" not in r.text:
        fails.append(f"text 应注明来源: {r.text[:120]}")
    return fails


def test_imports_sidecar_hit_zero_container() -> list[str]:
    fails: list[str] = []
    spy = ReplaySpy()
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td), sidecar=True)
            r = ImportsQueryTool(ctx).execute(file_ref="bin/app")
    finally:
        restore()
    if not r.ok:
        fails.append(f"边车路应成功: {r.error}")
    elif "边车" not in r.text:
        fails.append(f"text 应注明来源边车: {r.text[:120]}")
    if spy.calls:
        fails.append(f"边车命中不得调容器: {spy.calls}")
    return fails


def test_imports_non_elf_guided_rejection() -> list[str]:
    """导入是 ELF 概念:非 ELF 引导性拒绝(指向 strings_query),零容器。"""
    fails: list[str] = []
    spy = ReplaySpy()
    restore = _install(spy)
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = _make_ctx(Path(td), sidecar=False)
            r = ImportsQueryTool(ctx).execute(file_ref="data/blob.bin")
    finally:
        restore()
    if r.ok or "strings_query" not in (r.error or ""):
        fails.append(f"非 ELF 应引导性拒绝: {r.error}")
    if spy.calls:
        fails.append(f"非 ELF 不应触发容器: {spy.calls}")
    return fails


def test_container_path_tool_prefix_tolerant() -> list[str]:
    """带 extracted/ 前缀的工具路径引用(findings.file 口径)应宽容剥前缀。"""
    from firmware_audit.step5_agent.providers.tools.cli_base import container_path

    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        ctx = _make_ctx(Path(td), sidecar=False)
        if container_path(ctx, "extracted/bin/app") != "/work/extracted/bin/app":
            fails.append("extracted/ 前缀应被剥除(ADR-0008 口径)")
        if container_path(ctx, "bin/app") != "/work/extracted/bin/app":
            fails.append("裸相对路径行为不变")
        if container_path(ctx, "extracted/../../etc/passwd") is not None:
            fails.append("前缀宽容不放松穿越拒绝")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("strings_sidecar_hit_zero_container", test_strings_sidecar_hit_zero_container),
        ("strings_fallback_with_pattern_non_elf", test_strings_fallback_with_pattern_non_elf),
        ("strings_both_unavailable_guidance", test_strings_both_unavailable_guidance),
        ("strings_pattern_invalid_unchanged", test_strings_pattern_invalid_unchanged),
        ("strings_step4_patterns_migrated", test_strings_step4_patterns_migrated),
        ("imports_fallback_grading_and_hint", test_imports_fallback_grading_and_hint),
        ("imports_sidecar_hit_zero_container", test_imports_sidecar_hit_zero_container),
        ("imports_non_elf_guided_rejection", test_imports_non_elf_guided_rejection),
        ("container_path_tool_prefix_tolerant", test_container_path_tool_prefix_tolerant),
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
