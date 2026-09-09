"""imports_query:查二进制导入符号,圈危险函数与调用点(混合型,ADR-0010 票02)。

边车优先:analysis/<rel>.imports.json 存在则读边车(毫秒级,不调容器)。
缺边车就地对 ELF 跑 r2 iij 兜底(经沙箱,extracted 只读挂载、断网),同样套
既有危险函数分级表;导入是 ELF 概念,非 ELF 走引导性拒绝。兜底条目无调用点
记录(call_sites 空),format_hits 的既有触发层指引会把 Agent 引向
r2_xref_query 定位真实调用者。
"""
from __future__ import annotations

import json

from .base import AgentTool, ToolResult, resolve_analysis_file
from .r2_base import elf_guard, parse_r2_json, run_r2
from .cli_base import container_path

# 危险导入表(高/中/低三级;规则:命中即上报,级别只影响展示排序)
DANGEROUS_IMPORTS: dict[str, str] = {
    # 命令执行
    "system": "high", "popen": "high", "execve": "high", "execv": "high",
    "execl": "high", "execlp": "high", "execvp": "high", "execle": "high",
    # 无界内存操作
    "strcpy": "high", "strcat": "high", "stpcpy": "high", "sprintf": "high",
    "vsprintf": "high", "gets": "high",
    # 格式化/输入
    "scanf": "medium", "sscanf": "medium", "vscanf": "medium",
    # 权限变更
    "setuid": "medium", "setgid": "medium", "seteuid": "medium",
    "setegid": "medium", "chmod": "medium", "fchmod": "medium", "chown": "medium",
    # 动态加载
    "dlopen": "medium", "dlsym": "medium",
    # 弱随机
    "rand": "low", "srand": "low",
    # 网络
    "socket": "low", "bind": "low", "listen": "low", "accept": "low", "connect": "low",
}


def load_imports(imports_path) -> list[dict]:
    return json.loads(imports_path.read_text(encoding="utf-8"))


def _fmt_call_sites(sites) -> str:
    """调用点列表 → 文本。边车条目是 dict({from, function},Ghidra 产物),
    r2 兜底条目缺省;纯 str 条目(历史数据)原样保留。"""
    out = []
    for s in sites or []:
        if isinstance(s, dict):
            fn = s.get("function") or ""
            addr = str(s.get("from", ""))
            out.append(f"{fn}@{addr}" if fn else addr)
        else:
            out.append(str(s))
    return ", ".join(out) or "无调用点记录"


def format_hits(hits: list[dict]) -> str:
    """危险导入命中列表 → 文本;call_sites 全空的场景附加触发层指引。

    触发层(2026-08-23,三层策略第 2 层):call_sites 为空只代表 Ghidra 未
    提取到调用位置,不等于该导入未被调用。实测 webrtc_bridge 案例 Agent 曾
    据此误判"死导入"并放弃追查,而 videohub 同场景下 r2 xref 却挖出真实
    system 调用点。此处仅在**存在调用点缺失的命中**时附一句指引,引导 Agent
    用 r2_xref_query 补查,避免跳成"未调用"的早熟结论。
    """
    lines = []
    has_empty = False
    for h in hits:
        sites = _fmt_call_sites(h.get("call_sites"))
        if not h.get("call_sites"):
            has_empty = True
        lines.append(f"{h['name']} [{h.get('level', '?')}] ref_count={h.get('ref_count', 0)} 调用点: {sites}")
    if has_empty:
        lines.append("提示: 部分导入调用点记录为空——这仅代表提取层未取到调用位置,"
                     "**不等于该导入未被调用**;请用 r2_xref_query 查该符号(sym.imp.<name>)"
                     "定位真实调用者,勿直接判定为未调用/死导入。")
    return "\n".join(lines)


class ImportsQueryTool(AgentTool):
    name = "imports_query"
    description = ("查询二进制的导入符号(优先读 analysis 边车;缺边车自动回退 r2 导入表,"
                   "套危险函数分级):默认列出全部危险函数(system/strcpy/exec 系等)及调用点;"
                   "也可按名字过滤任意导入。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的 ELF 路径"},
        "name": {"type": "str", "default": "", "desc": "按符号名精确过滤;缺省列危险导入全表"},
    }

    def _run(self, file_ref: str, name: str = "") -> ToolResult:
        imports, source = self._load_imports(file_ref)
        if imports is None:
            return ToolResult(
                ok=False, text="",
                error=(f"{file_ref} 既无 analysis/<rel>.imports.json 边车,r2 也未取得导入表"
                       "(非 ELF/文件不存在/r2 异常)。导入审计仅对 ELF 有效;用 list_files "
                       "确认路径,字符串审计可用 strings_query(不限 ELF)。"),
            )
        if name:
            hits = [i for i in imports if i.get("name") == name]
            if not hits:
                return ToolResult(ok=True, text=f"{file_ref} 无导入 '{name}'({source})", data=[])
            return ToolResult(ok=True, text=f"来源 {source}:\n{format_hits(hits)}", data=hits)

        # 默认:危险导入全表,按级别排序
        hits = []
        for i in imports:
            level = DANGEROUS_IMPORTS.get(i.get("name", ""))
            if level:
                hits.append({**i, "level": level})
        hits.sort(key=lambda h: ("low", "medium", "high").index(h["level"]), reverse=True)
        if not hits:
            return ToolResult(ok=True, text=f"{file_ref} 未命中危险导入表({source})", data=[])
        return ToolResult(
            ok=True,
            text=f"危险导入 {len(hits)} 项(按级别排序,来源 {source}):\n{format_hits(hits)}",
            data=hits,
        )

    def _load_imports(self, file_ref: str) -> tuple[list | None, str]:
        """边车优先 → (导入列表, "边车");缺边车 r2 iij 兜底 → (列表, "r2 iij");
        都不可得 → (None, "")。"""
        path = resolve_analysis_file(self.ctx, file_ref, ".imports.json")
        if path is not None:
            return load_imports(path), "边车"
        # 导入是 ELF 概念:非 ELF/越界走引导性拒绝,不付容器
        guard = elf_guard(self.ctx, file_ref)
        if guard:
            return None, ""
        cpath = container_path(self.ctx, file_ref)
        if cpath is None:
            return None, ""
        _rc, out, _err = run_r2(self.ctx, cpath, ["-c", "iij"])
        data = parse_r2_json(out)
        if data is None:
            return None, ""
        imports = [
            {"name": d.get("name", ""), "address": str(d.get("plt") or d.get("vaddr") or ""),
             "ref_count": 0, "call_sites": []}
            for d in data if isinstance(d, dict) and d.get("name")
        ]
        return imports, "r2 iij"
