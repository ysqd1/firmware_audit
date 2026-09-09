"""r2 调用辅助(票01 prefactor,ADR-0010):容器命令构建/路径换算/超时/解析。

r2 族工具(r2_list_functions / r2_disassemble_function / r2_xref_query,及
票02 起 strings_query/imports_query 的兜底路)共用此辅助。每次调用都是全新
容器进程(无常驻 r2pipe session),extracted 只读挂载 + 断网安全基线由
run_in_sandbox 保证。

命名纪律(ADR-0010,用户定稿):工具名前缀 r2_* 表示"现算"(对原始二进制
现跑 radare2),与读缓存的 find_decompiled_function(只读反编译边车)区分,
防 LLM 混淆两条取证路径。
"""
from __future__ import annotations

import json

from .base import resolve_within
from .cli_base import container_path, extracted_root, run_in_sandbox

# aflj 需全量分析(aaa 级),大库上分钟级,成本预算进超时(ADR-0010 定值 600)
R2_ANALYZE_TIMEOUT = 600
# 单函数 af/pdf、axtj、ii、izz 等廉价命令的默认超时(对齐 xref 既有 180s)
R2_DEFAULT_TIMEOUT = 180

# func_or_addr 拼进 -c 命令串前的白名单字符(真实目标形态:sym.imp.system /
# fcn.00400900 / sub.monkey_401070 / 0x00400890 / mangled C++ _ZN...——字母数字
# 加 _ . : -)。其余一律拒绝:r2 把 ; 当命令分隔符(多命令注入面在工具层收口),
# $ <> 等在 r2 命令语法里有重定向/变量语义,一并挡在门外
_FUNC_ADDR_SAFE = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.:-")


def container_elf_path(ctx, file_ref: str) -> str | None:
    """file_ref → 容器绝对路径 /work/extracted/<rel>;越界 None(cli_base 既有换算)。"""
    return container_path(ctx, file_ref)


def elf_guard(ctx, file_ref: str) -> str | None:
    """r2/Ghidra 族前置守卫:路径越界/文件缺失/非 ELF → 引导性错误文本;ELF → None。

    宿主侧读 magic(4 字节)判定,不让非 ELF 白付一次容器启动(票01:
    "非 ELF/路径越界返回引导性 ok=False";票03 的 ghidra_decompile 同守卫)。
    注意:strings_query 的 r2 兜底**不走本守卫**(izz 对任意 extracted 文件
    有效,不限 ELF,ADR-0010),只复用其路径解析。
    """
    p = extracted_host_path(ctx, file_ref)
    if p is None:
        return (f"非法路径: {file_ref}(应为相对 extracted 根的路径,"
                "禁止 .. 与绝对路径;用 list_files 确认)")
    try:
        with open(p, "rb") as f:
            magic = f.read(4)
    except OSError:
        return f"文件不存在或不可读: extracted/{file_ref}(用 list_files 确认路径)"
    if magic != b"\x7fELF":
        return (f"extracted/{file_ref} 不是 ELF 文件(magic 非 \\x7fELF)。"
                "字符串审计用 strings_query(非 ELF 也可跑);嵌套容器用 binwalk_rescan;"
                "反编译(ghidra_decompile)仅支持 ELF。")
    return None


def extracted_host_path(ctx, file_ref: str):
    """file_ref → extracted 树内宿主绝对路径;越界 None。路径解析单一出处
    (elf_guard 与 r2 兜底共用;带 extracted/ 前缀的引用由 container_path
    同款宽容剥除)。"""
    ref = str(file_ref or "").strip().replace("\\", "/").removeprefix("extracted/")
    return resolve_within(extracted_root(ctx), ref)


def run_r2(ctx, cpath: str, r2_args: list[str], timeout: int = R2_DEFAULT_TIMEOUT):
    """构建并执行 r2 容器命令,返回 (rc, stdout, stderr)。

    r2_args 是 "-q" 之后的完整参数(含 -c 命令串与 -e 环境项),目标文件路径
    由本函数统一追加(cpath 来自 container_elf_path,调用方不再自行拼接)。
    """
    return run_in_sandbox(["-q", *r2_args, cpath], "r2", ctx, timeout=timeout)


def parse_r2_json(out: str) -> list | None:
    """r2 stdout 的 JSON 结果可能被缩进成跨多行的 JSON 数组(也称"pretty"),
    且前面有分析 WARN 日志。逐行找单行 `[` 会漏掉跨行数组 → 此处按括号深度
    配平扫描(字符串感知),找到首个以 `[` 开头的完整数组,json.loads 之。

    2026-08-22 实发: r2 -A 在 aarch64 上打印
      WARN: Unsupported reloc type 1030 for aarch64
    后 axtj 输出跨行数组,旧逻辑 reversed(splitlines()) 找不到单行 `[` 而误判失败。
    """
    idx = 0
    n = len(out)
    while idx < n:
        start = out.find("[", idx)
        if start < 0:
            return None
        depth = 0
        in_str = False
        esc = False
        i = start
        ok = True
        while i < n:
            ch = out[i]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            elif ch == '"':
                in_str = True
            elif ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0:
                    try:
                        data = json.loads(out[start:i + 1])
                        return data if isinstance(data, list) else None
                    except json.JSONDecodeError:
                        ok = False
                        break
            i += 1
        if not ok:
            break
        idx = start + 1
    return None


def sanitize_func_or_addr(target: str) -> bool:
    """func_or_addr 是否只含安全字符(符号名/地址形态)。False = 拒绝执行。"""
    return bool(target) and all(ch in _FUNC_ADDR_SAFE for ch in target)
