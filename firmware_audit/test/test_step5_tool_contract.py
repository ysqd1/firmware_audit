"""Step5 工具接口契约单测(ADR-0004 / spec 决策 2,Seam 2)。

只测外部行为:给定非法参数调用 execute() → 断言 ok=False + 优雅错误文本
(而非 Python 异常文案)。校验在 execute 入口拦截,_run 不触发,故可纯离线
覆盖全部注册工具(含依赖 Docker 的 CLI 工具,构造不触发 Docker)。

覆盖:
  - 每个工具:未知参数 / 类型错误 / 缺失必选 → ok=False + 可自纠错误文本
  - read_file 收到 recursive → "未知参数 recursive,已忽略;合法参数:path/offset/limit"
  - params_doc 与校验共享同一份 params 声明(单一来源,ADR-0004 A 侧)
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import make_tools
from firmware_audit.step5_agent.providers.tools.base import (
    ToolContext,
    render_params_doc,
    validate_params,
)

# 契约侧工具清单(与注册表一致;params 声明本身由各工具提供,
# 测试不重复编码参数清单——派生自 t.params,避免双源漂移)
_CONTRACT_TOOLS = [
    "read_file", "list_files", "search_code", "strings_query", "imports_query",
    "find_decompiled_function", "r2_list_functions", "r2_disassemble_function",
    "r2_xref_query", "ghidra_decompile", "checksec", "cve_bin_tool_scan",
    "semgrep_scan", "gitleaks_scan", "sandbox_verify", "binwalk_rescan",
    "cve_lookup", "web_search",
]


def _tools() -> dict:
    return make_tools(ToolContext(process_dir=Path(tempfile.mkdtemp())))


def test_validate_params_unknown() -> list[str]:
    """未知参数 → 优雅错误,列出合法参数清单(不抛异常)。"""
    fails: list[str] = []
    spec = {"path": {"type": "str", "required": True},
            "offset": {"type": "int", "default": 0}}
    out, err = validate_params(spec, {"path": "x", "recursive": True})
    if out is not None:
        fails.append("未知参数应返回 (None, err)")
    if "未知参数 recursive" not in (err or "") or "path/offset" not in (err or ""):
        fails.append(f"错误应列出未知参数与合法清单: {err}")
    return fails


def test_validate_params_missing_required() -> list[str]:
    """缺失必选 → 列出缺失项。"""
    fails: list[str] = []
    spec = {"file_ref": {"type": "str", "required": True}}
    out, err = validate_params(spec, {})
    if out is not None or "缺失必选参数: file_ref" not in (err or ""):
        fails.append(f"缺失必选应优雅报错: {err}")
    return fails


def test_validate_params_type_error() -> list[str]:
    """类型错误 → 期望类型 vs 收到类型。"""
    fails: list[str] = []
    spec = {"offset": {"type": "int"}}
    out, err = validate_params(spec, {"offset": "abc"})
    if out is not None or "参数 offset 类型错误" not in (err or ""):
        fails.append(f"类型错误应优雅报错: {err}")
    # bool 类型:recursive 声明为 bool,收到字符串 'yes' → 类型错误
    spec2 = {"recursive": {"type": "bool"}}
    out2, err2 = validate_params(spec2, {"recursive": "yes"})
    if out2 is not None or "参数 recursive 类型错误" not in (err2 or ""):
        fails.append(f"bool 类型错误应优雅报错: {err2}")
    # bool 是 int 子类(isinstance(True, int)==True)→ int 参数收到 True 必须拒绝
    spec3 = {"max_files": {"type": "int"}}
    out3, err3 = validate_params(spec3, {"max_files": True})
    if out3 is not None or "参数 max_files 类型错误" not in (err3 or ""):
        fails.append(f"int 参数收到 bool 应拒绝(防 True 当 1 混用): {err3}")
    # 不支持的 type 声明 → 校验失败不静默放行
    spec4 = {"x": {"type": "float"}}
    out4, err4 = validate_params(spec4, {"x": 1.0})
    if out4 is not None or "不支持的 type" not in (err4 or ""):
        fails.append(f"未知 type 声明应拒绝: {err4}")
    return fails


def test_validate_params_enum_case_insensitive() -> list[str]:
    """str 枚举大小写不敏感(与 _run 的 .lower() 归一一致):PYTHON 应通过。"""
    fails: list[str] = []
    spec = {"language": {"type": "str", "default": "python",
                         "enum": ["python", "node", "php"]}}
    _, err = validate_params(spec, {"language": "PYTHON"})
    if err is not None:
        fails.append(f"PYTHON 应通过 str 枚举(大小写不敏感): {err}")
    # 非法值仍拒绝
    out2, err2 = validate_params(spec, {"language": "bash"})
    if out2 is not None or "取值非法" not in (err2 or ""):
        fails.append(f"bash 应被枚举拒绝: {err2}")
    return fails


def test_validate_params_enum() -> list[str]:
    """枚举越界 → 列出可选值。"""
    fails: list[str] = []
    spec = {"language": {"type": "str", "default": "python",
                         "enum": ["python", "node", "php"]}}
    out, err = validate_params(spec, {"language": "bash"})
    if out is not None or "取值非法" not in (err or "") or "python/node/php" not in (err or ""):
        fails.append(f"枚举越界应优雅报错: {err}")
    return fails


def test_validate_params_valid() -> list[str]:
    """合法参数原样通过(类型已检查)。"""
    fails: list[str] = []
    spec = {"path": {"type": "str", "required": True},
            "offset": {"type": "int", "default": 0}}
    out, err = validate_params(spec, {"path": "a", "offset": 3})
    if err is not None or out != {"path": "a", "offset": 3}:
        fails.append(f"合法参数应通过: out={out} err={err}")
    # 缺省不传 → checked 只含传入键(默认值由 _run 签名兜底)
    out2, err2 = validate_params(spec, {"path": "a"})
    if err2 is not None or out2 != {"path": "a"}:
        fails.append(f"缺省参数不强制补默认: out={out2} err={err2}")
    return fails


def test_render_params_doc() -> list[str]:
    """params_doc 从声明渲染:JSON 骨架 + 每参数类型/必填/默认。"""
    fails: list[str] = []
    doc = render_params_doc({
        "path": {"type": "str", "required": True, "desc": "相对路径"},
        "offset": {"type": "int", "default": 0, "desc": "起始行"},
    })
    if "path" not in doc or "offset" not in doc:
        fails.append(f"渲染应含参数名: {doc}")
    if "必填" not in doc:
        fails.append(f"必填参数应标注: {doc}")
    if "默认 0" not in doc:
        fails.append(f"默认值应渲染: {doc}")
    # 空声明 → 空串(无契约工具)
    if render_params_doc({}) != "":
        fails.append("空声明应返回空串")
    return fails


def _spec_from_tool(t) -> dict[str, dict]:
    """从工具声明派生 (params, 必填集);派生源即 t.params(单一来源)。"""
    return dict(t.params)


def test_tools_declare_params() -> list[str]:
    """全部生产工具声明了 params(契约 A 侧);params_doc 渲染出类型/必填信息。"""
    fails: list[str] = []
    tools = _tools()
    for name in sorted(_CONTRACT_TOOLS):
        t = tools.get(name)
        if t is None:
            fails.append(f"注册表缺 {name}")
            continue
        if not t.params:
            fails.append(f"{name} 未声明 params")
        if not t.params_doc:
            fails.append(f"{name}.params_doc 渲染为空")
        # 每个声明参数都应出现在渲染的 params_doc 中(单一来源契约)
        for pname in t.params:
            if pname not in t.params_doc:
                fails.append(f"{name}.params_doc 缺参数 '{pname}': {t.params_doc[:80]}")
        # 必填参数不应以空串默认值出现在 JSON 骨架(避免 LLM 照抄空串)
        for pname, decl in t.params.items():
            if decl.get("required") and '"' + pname + '": ""' in t.params_doc:
                fails.append(f"{name}.{pname} 必填参数不得渲染成空串默认值")
    return fails


def test_every_tool_rejects_invalid_params() -> list[str]:
    """每个工具:非法参数调用 → ok=False + 优雅错误(未知/类型/缺失必选各一例)。"""
    fails: list[str] = []
    tools = _tools()

    def check(name: str, kw: dict, needle: str, tag: str) -> None:
        t = tools[name]
        r = t.execute(**kw)
        if r.ok:
            fails.append(f"{name} {tag}: 应 ok=False, got ok=True")
            return
        err = r.error or ""
        if needle not in err:
            fails.append(f"{name} {tag}: 错误应含 '{needle}', got {err[:120]}")
        # 优雅错误 ≠ Python 异常文案
        if err.startswith(("TypeError", "AttributeError", "ValueError")):
            fails.append(f"{name} {tag}: 不得暴露 Python 异常文案, got {err[:80]}")

    for name in _CONTRACT_TOOLS:
        spec = _spec_from_tool(tools[name])
        required = [p for p, d in spec.items() if d.get("required")]
        # 合法必填参数填充值(类型正确的样例,供类型错误探测用)
        fill = {p: "x" for p in required}
        # 未知参数
        check(name, {"_bogus_key": 1}, "未知参数 _bogus_key", "未知参数")
        # 类型错误:每个 str/bool 参数传 int 都该被拒(先填齐必填,避免缺参抢先报错)。
        # int 参数传 int 属合法(如 max_files=123),契约放行后由 _run 内部钳制。
        for p, d in spec.items():
            if d.get("type") == "int":
                continue
            r2 = tools[name].execute(**{**fill, p: 123})
            if r2.ok:
                fails.append(f"{name}.{p} 传 int 应 ok=False")
            elif "类型错误" not in (r2.error or ""):
                fails.append(f"{name}.{p} 传 int 应类型错误, got {r2.error[:80]}")
        # int 参数收到 bool 应拒绝(防 True 当 1 混用)
        for p, d in spec.items():
            if d.get("type") == "int":
                r3 = tools[name].execute(**{**fill, p: True})
                if r3.ok:
                    fails.append(f"{name}.{p} 传 True 应 ok=False(bool 冒充 int)")
        # 缺失必选:缺一个必填参数即报缺失清单
        if required:
            check(name, {}, f"缺失必选参数: {', '.join(required)}", "缺失必选")
    return fails


def test_read_file_recursive_graceful() -> list[str]:
    """read_file 收到 recursive → '未知参数 recursive,已忽略;合法参数:path/offset/limit'。"""
    fails: list[str] = []
    r = _tools()["read_file"].execute(path="x", recursive=True)
    expected = "未知参数 recursive,已忽略;合法参数:path/offset/limit"
    if r.ok or expected not in (r.error or ""):
        fails.append(f"recursive 应优雅拦截: ok={r.ok} err={r.error}")
    if (r.error or "").startswith(("TypeError", "AttributeError")):
        fails.append(f"不得暴露 Python 异常: {r.error}")
    return fails


def test_read_file_valid_params_pass_through() -> list[str]:
    """合法参数正常放行:契约不误伤正常调用(纯校验层,文件不存在属于业务错误)。"""
    fails: list[str] = []
    r = _tools()["read_file"].execute(path="no/such/file.json", offset=0, limit=5)
    if r.ok or "类型错误" in (r.error or "") or "未知参数" in (r.error or ""):
        fails.append(f"合法参数不应被契约拒绝: ok={r.ok} err={r.error}")
    return fails


def test_tools_declare_replay_policy() -> list[str]:
    """注册契约审计每个工具的中断重放策略，不从工具名推断。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.providers import tools as tools_module

    required_api = ("ReplayPolicy", "tool_contracts")
    missing_api = [name for name in required_api if not hasattr(tools_module, name)]
    if missing_api:
        return [f"工具注册表缺重放契约 API: {missing_api}"]

    policies = tools_module.ReplayPolicy
    contracts = tools_module.tool_contracts()
    if len(contracts) != len(_CONTRACT_TOOLS) or set(contracts) != set(_CONTRACT_TOOLS):
        fails.append(
            f"重放契约必须覆盖全部注册工具: contracts={sorted(contracts)}"
        )
        return fails

    legal = set(policies)
    for name, contract in contracts.items():
        if contract.replay_policy not in legal:
            fails.append(f"{name} replay_policy 非法: {contract.replay_policy!r}")

    expected = {
        name: policies.READ_ONLY_IDEMPOTENT for name in _CONTRACT_TOOLS
    }
    expected["ghidra_decompile"] = policies.CACHE_VALIDATED
    expected["sandbox_verify"] = policies.NEVER
    expected["web_search"] = policies.NEVER
    actual = {name: contract.replay_policy for name, contract in contracts.items()}
    if actual != expected:
        fails.append(f"现有工具 replay policy 审计结果漂移: {actual}")
    return fails


def test_blind_discovery_role_contract() -> list[str]:
    """Blind Discovery 三角色只从注册契约取得固定工具权限。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.providers import tools as tools_module

    if not hasattr(tools_module, "tool_names_for_role"):
        return ["工具注册表缺 tool_names_for_role 角色权限 API"]

    shallow = {
        "list_files", "read_file", "search_code", "strings_query",
        "imports_query", "checksec", "semgrep_scan", "gitleaks_scan",
        "binwalk_rescan",
    }
    # find_decompiled_function 读已有反编译边车(不发起 Ghidra),授权深挖
    # 角色、拒绝 recon(ADR-0012 2026-09-16 D1)。
    deep = shallow | {
        "find_decompiled_function",
        "r2_list_functions", "r2_disassemble_function", "r2_xref_query",
        "ghidra_decompile", "sandbox_verify",
    }
    expected = {"recon": shallow, "analysis": deep, "verification": deep}
    with tempfile.TemporaryDirectory() as td:
        ctx = ToolContext(process_dir=Path(td))
        for role, wanted in expected.items():
            actual = set(tools_module.tool_names_for_role(role))
            if actual != wanted:
                fails.append(f"{role} Blind Discovery 工具集漂移: {sorted(actual)}")
            try:
                provisioned = tools_module.make_tools(ctx, role=role)
            except TypeError as exc:
                fails.append(f"make_tools 应支持按角色直接构造授权实例集: {exc}")
            else:
                if set(provisioned) != wanted:
                    fails.append(
                        f"{role} 实例化工具集绕过角色契约: {sorted(provisioned)}"
                    )

    forbidden = {"cve_bin_tool_scan", "cve_lookup", "web_search"}
    for role in expected:
        leaked = forbidden & set(tools_module.tool_names_for_role(role))
        if leaked:
            fails.append(f"{role} 不得获得公开问题知识工具: {sorted(leaked)}")
    return fails


def test_role_contract_rejects_unauthorized_action() -> list[str]:
    """模型提出越权动作时由契约拒绝；调用方不靠过滤后的 dict 猜原因。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.providers import tools as tools_module

    required_api = ("ToolAuthorizationError", "authorize_tool")
    missing_api = [name for name in required_api if not hasattr(tools_module, name)]
    if missing_api:
        return [f"工具注册表缺授权判定 API: {missing_api}"]

    for tool_name in ("r2_list_functions", "ghidra_decompile", "web_search",
                      "find_decompiled_function"):
        try:
            tools_module.authorize_tool("recon", tool_name)
        except tools_module.ToolAuthorizationError as exc:
            detail = str(exc)
            if "recon" not in detail or tool_name not in detail:
                fails.append(f"拒绝文案应含角色与工具名: {detail}")
            if "可用工具" not in detail:
                fails.append(f"拒绝文案应指引该角色的可用工具: {detail}")
        else:
            fails.append(f"recon 越权动作应被契约拒绝: {tool_name}")

    # D1:find_decompiled_function 对深挖角色合法授权(读边车,不发起 Ghidra)。
    for role in ("analysis", "verification"):
        allowed = tools_module.authorize_tool(role, "find_decompiled_function")
        if allowed.name != "find_decompiled_function":
            fails.append(f"{role} 应能授权 find_decompiled_function: {allowed}")
    verification_tools = ", ".join(tools_module.tool_names_for_role("verification"))
    analysis_tools = ", ".join(tools_module.tool_names_for_role("analysis"))
    if "find_decompiled_function" not in verification_tools:
        fails.append("verification 有效工具目录应含 find_decompiled_function")
    if "find_decompiled_function" not in analysis_tools:
        fails.append("analysis 有效工具目录应含 find_decompiled_function")
    recon_tools = ", ".join(tools_module.tool_names_for_role("recon"))
    if "find_decompiled_function" in recon_tools:
        fails.append("recon 有效工具目录不得含 find_decompiled_function")

    allowed = tools_module.authorize_tool("analysis", "ghidra_decompile")
    if allowed.name != "ghidra_decompile":
        fails.append(f"合法授权应返回对应注册契约: {allowed}")
    return fails


def test_role_prompts_match_tool_contract() -> list[str]:
    """D1:模型可见的角色提示词与实际工具权限一致——recon 不见深挖工具,
    analysis/verification 明示 find_decompiled_function(读边车,不发起 Ghidra)。"""
    fails: list[str] = []
    from firmware_audit.step5_agent.host.analysis import ANALYSIS_SESSION_SYSTEM
    from firmware_audit.step5_agent.host.recon import RECON_SESSION_SYSTEM
    from firmware_audit.step5_agent.host.verification import (
        VERIFICATION_SESSION_SYSTEM,
    )

    for name, prompt in (("analysis", ANALYSIS_SESSION_SYSTEM),
                         ("verification", VERIFICATION_SESSION_SYSTEM)):
        if "find_decompiled_function" not in prompt:
            fails.append(f"{name} 提示词应列明 find_decompiled_function")
    if "find_decompiled_function" in RECON_SESSION_SYSTEM:
        fails.append("recon 提示词不得出现 find_decompiled_function")
    # recon 提示词对深挖工具只允许"不可见"纪律式提及,不得宣传为可用
    for deep_tool in ("ghidra_decompile", "sandbox_verify"):
        if deep_tool in RECON_SESSION_SYSTEM and "不可见" not in RECON_SESSION_SYSTEM:
            fails.append(f"recon 提示词提及 {deep_tool} 时必须声明不可见")
    if "不可见" not in RECON_SESSION_SYSTEM:
        fails.append("recon 提示词应声明深挖工具不可见(纪律句)")
    # recon 提示词宣传的浅层清单与注册表一致(抽样锚定)
    for shallow_tool in ("list_files", "read_file", "search_code",
                         "strings_query", "imports_query", "checksec",
                         "semgrep_scan", "gitleaks_scan", "binwalk_rescan"):
        if shallow_tool not in RECON_SESSION_SYSTEM:
            fails.append(f"recon 提示词应列明授权工具 {shallow_tool}")
    return fails


def test_role_prompts_pin_version_mapping_ban() -> list[str]:
    """票 24:生产装配的三角色系统提示词必须显式带版本映射禁令(AC1)。

    Blind Discovery 的版本映射禁令不能只靠禁用 CVE 工具承载;run_step5 的
    _ROLE_WIRING 是生产装配点,这里按装配表逐角色校验纪律锚点。
    """
    fails: list[str] = []
    import hashlib

    from firmware_audit.step5_agent.host.driver import prompt_version_document
    from firmware_audit.step5_agent.run_step5 import _ROLE_WIRING

    versions = prompt_version_document()
    for role, (prompt, _) in _ROLE_WIRING.items():
        if "版本映射" not in prompt:
            fails.append(f"{role} 生产提示词缺少版本映射禁令锚点")
        if "服务启动字符串" not in prompt:
            fails.append(f"{role} 生产提示词缺少版本/配置/服务字符串证据纪律")
        # 装配表与快照指纹必须出自同一组提示词常量,两处映射不得各自漂移。
        digest = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
        if versions.get(role) != digest:
            fails.append(f"{role} 生产装配提示词与快照指纹出处不一致")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("validate_params_unknown", test_validate_params_unknown),
        ("validate_params_missing_required", test_validate_params_missing_required),
        ("validate_params_type_error", test_validate_params_type_error),
        ("validate_params_enum", test_validate_params_enum),
        ("validate_params_enum_case_insensitive", test_validate_params_enum_case_insensitive),
        ("validate_params_valid", test_validate_params_valid),
        ("render_params_doc", test_render_params_doc),
        ("tools_declare_params", test_tools_declare_params),
        ("every_tool_rejects_invalid_params", test_every_tool_rejects_invalid_params),
        ("read_file_recursive_graceful", test_read_file_recursive_graceful),
        ("read_file_valid_params_pass_through", test_read_file_valid_params_pass_through),
        ("tools_declare_replay_policy", test_tools_declare_replay_policy),
        ("blind_discovery_role_contract", test_blind_discovery_role_contract),
        ("role_contract_rejects_unauthorized_action", test_role_contract_rejects_unauthorized_action),
        ("role_prompts_match_tool_contract", test_role_prompts_match_tool_contract),
        ("role_prompts_pin_version_mapping_ban", test_role_prompts_pin_version_mapping_ban),
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
