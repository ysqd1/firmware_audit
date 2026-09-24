"""票 27:工具参数契约送入角色上下文(ADR-0004 声明侧 A 送达闭环)。

只测外部行为,不调用真实 LLM、不读 GT:
  - role_tool_contract 与 make_tools/authorize_tool 同一注册表:只列该角色
    已授权工具,名称/用途/参数规格(必填/类型/默认/枚举/说明)齐全;
    strings_query 的 pattern 必填与 re:<正则> 用法、search_code 的 is_regex
    可从渲染文本核对。
  - 生产 Session(run_step5._session_factory)实际发送的 system 消息包含
    本角色参数契约;未授权工具不出现(recon 无深挖工具,三角色无 _NO_ROLES)。
  - 实际发送的提示常量与 prompt_version_document 冻结指纹逐字节一致
    (新世代有效提示与指纹一致;契约内容在指纹覆盖范围内)。
  - 无效参数反馈明确整份调用未执行,不再使用"已忽略"措辞。
"""
from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import (
    ToolAuthorizationError,
    make_tools,
    role_tool_contract,
    tool_names_for_role,
)
from firmware_audit.step5_agent.providers.tools.base import (
    ToolContext,
    validate_params,
)

_ROLES = ("recon", "analysis", "verification")
_NO_ROLE_TOOLS = ("cve_lookup", "cve_bin_tool_scan", "web_search")
_DEEP_ONLY_TOOLS = ("find_decompiled_function", "r2_list_functions",
                    "r2_disassemble_function", "r2_xref_query",
                    "ghidra_decompile", "sandbox_verify", "qemu_precheck",
                    "qemu_execute")


def _tools() -> dict:
    return make_tools(ToolContext(process_dir=Path(tempfile.mkdtemp())))


class _CaptureLLM:
    """记录每次 chat 收到的完整 messages;回复内容与本票无关。"""

    available = True

    def __init__(self):
        self.calls: list[list[dict]] = []

    def chat(self, messages):
        self.calls.append([dict(m) for m in messages])
        return "{}", {"prompt_tokens": 1, "completion_tokens": 1}


def test_role_tool_contract_covers_authorized_tools() -> list[str]:
    """每角色契约包含全部已授权工具的名称/用途/参数声明,关键用法可核对。"""
    fails: list[str] = []
    tools = _tools()
    for role in _ROLES:
        contract = role_tool_contract(role)
        for name in tool_names_for_role(role):
            if f"#### {name}" not in contract:
                fails.append(f"{role} 契约缺已授权工具 {name}")
                continue
            block = contract.split(f"#### {name}", 1)[1].split("#### ", 1)[0]
            desc = tools[name].description
            if desc and desc not in block:
                fails.append(f"{role} 契约 {name} 用途与声明不一致: {block[:120]}")
            if "参数声明" not in block:
                fails.append(f"{role} 契约 {name} 缺参数声明段")
            for pname, decl in tools[name].params.items():
                line = next(
                    (ln for ln in block.splitlines()
                     if ln.strip().startswith(f"{pname} (")), None)
                if line is None:
                    fails.append(f"{role} 契约 {name} 缺参数 {pname}")
                    continue
                if decl.get("required") and "必填" not in line:
                    fails.append(f"{role} 契约 {name}.{pname} 必填未标注: {line}")
    # AC2 锚点:strings_query 正则用法与 search_code 的 is_regex 必须可见
    analysis = role_tool_contract("analysis")
    sq = analysis.split("#### strings_query", 1)[1].split("#### ", 1)[0]
    if "re:<正则>" not in sq:
        fails.append(f"strings_query 契约缺 re:<正则> 用法: {sq[:200]}")
    sc = analysis.split("#### search_code", 1)[1].split("#### ", 1)[0]
    if "is_regex" not in sc:
        fails.append(f"search_code 契约缺 is_regex: {sc[:200]}")
    return fails


def test_role_tool_contract_excludes_unauthorized() -> list[str]:
    """未授权工具不得出现在该角色契约:recon 无深挖工具,三角色无 _NO_ROLES。"""
    fails: list[str] = []
    for deep_tool in _DEEP_ONLY_TOOLS:
        if f"#### {deep_tool}" in role_tool_contract("recon"):
            fails.append(f"recon 契约不得包含深挖工具 {deep_tool}")
    for role in _ROLES:
        contract = role_tool_contract(role)
        for name in _NO_ROLE_TOOLS:
            if f"#### {name}" in contract:
                fails.append(f"{role} 契约不得包含 _NO_ROLES 工具 {name}")
    try:
        role_tool_contract("not-a-role")
        fails.append("未知角色应拒绝")
    except ToolAuthorizationError:
        pass
    return fails


def test_production_session_delivers_role_contract() -> list[str]:
    """生产 Session 实际发送的 system 消息包含本角色契约(权限隔离随发送核对)。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.run_step5 import _session_factory

    for role in _ROLES:
        llm = _CaptureLLM()
        session = _session_factory(llm)(role, None, run_dir=None)
        session.step("首轮输入")
        if not llm.calls:
            fails.append(f"{role}: Session 未发起模型请求")
            continue
        sent = llm.calls[0][0]
        if sent.get("role") != "system":
            fails.append(f"{role}: 首条消息应为 system,实际 {sent.get('role')}")
            continue
        content = sent["content"]
        if role_tool_contract(role) not in content:
            fails.append(f"{role}: 实际发送的 system 消息不含本角色参数契约")
        if role == "recon":
            for deep_tool in ("qemu_precheck", "qemu_execute"):
                if f"#### {deep_tool}" in content:
                    fails.append(f"recon 实际发送内容不得宣传 {deep_tool}")
        if role == "analysis" and "re:<正则>" not in content:
            fails.append("analysis 实际发送内容缺 strings_query 正则用法")
    return fails


def test_prompt_fingerprint_covers_tool_contract() -> list[str]:
    """有效提示常量与 prompt_version_document 指纹逐字节一致,契约在覆盖范围内。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.host.analysis import ANALYSIS_SESSION_SYSTEM
    from firmware_audit.step5_agent.host.recon import RECON_SESSION_SYSTEM
    from firmware_audit.step5_agent.host.verification import (
        VERIFICATION_SESSION_SYSTEM,
    )
    from firmware_audit.step5_agent.host.driver import prompt_version_document
    from firmware_audit.step5_agent.host.session import protocol_instruction

    prompts = {"recon": RECON_SESSION_SYSTEM,
               "analysis": ANALYSIS_SESSION_SYSTEM,
               "verification": VERIFICATION_SESSION_SYSTEM}
    fingerprints = prompt_version_document()
    for role, prompt in prompts.items():
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        if fingerprints[role] != digest:
            fails.append(f"{role}: 提示词指纹与常量不一致")
        if role_tool_contract(role) not in prompt:
            fails.append(f"{role}: 参数契约未拼入被指纹覆盖的提示常量")
        # 发送形态钉子:实际发送 = 常量 + 确定性协议后缀;常量部分即指纹对象
        expected_sent = f"{prompt}\n\n{protocol_instruction(role)}"
        llm = _CaptureLLM()
        from firmware_audit.step5_agent.engine.context import ContextManager
        from firmware_audit.step5_agent.host.session import AgentSession
        session = AgentSession(role, llm, ContextManager(prompt, ""))
        session.step(None)
        sent_system = llm.calls[0][0]["content"]
        if sent_system != expected_sent:
            fails.append(f"{role}: 实际发送的 system 消息与'常量+协议后缀'不一致")
    return fails


def test_invalid_param_feedback_says_not_executed() -> list[str]:
    """无效参数反馈明确整份调用未执行,不再使用'已忽略'造成部分生效误解。"""
    fails: list[str] = []
    spec = {"path": {"type": "str", "required": True},
            "offset": {"type": "int", "default": 0}}
    _, err = validate_params(spec, {"path": "x", "recursive": True})
    if err is None or "未执行" not in err:
        fails.append(f"未知参数反馈应声明整份未执行: {err}")
    if err and "已忽略" in err:
        fails.append(f"反馈不得再使用'已忽略'措辞: {err}")
    if err is None or "path/offset" not in err:
        fails.append(f"反馈应保留合法参数清单: {err}")
    # 执行入口同文案(execute → validate_params 单一出处)
    tools = _tools()
    r = tools["read_file"].execute(path="x", recursive=True)
    if r.ok or "未执行" not in (r.error or ""):
        fails.append(f"execute 侧反馈应声明整份未执行: {r.error}")
    return fails


def test_main() -> int:
    """独立运行入口(与 conftest pytest_pyfunc_call 同口径汇总)。"""
    failures = 0
    for name, fn in (
        ("role_tool_contract_covers_authorized_tools",
         test_role_tool_contract_covers_authorized_tools),
        ("role_tool_contract_excludes_unauthorized",
         test_role_tool_contract_excludes_unauthorized),
        ("production_session_delivers_role_contract",
         test_production_session_delivers_role_contract),
        ("prompt_fingerprint_covers_tool_contract",
         test_prompt_fingerprint_covers_tool_contract),
        ("invalid_param_feedback_says_not_executed",
         test_invalid_param_feedback_says_not_executed),
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
