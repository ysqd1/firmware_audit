"""imports_query:读 Step4 imports.json,圈危险函数与调用点。"""
from __future__ import annotations

import json

from .base import AgentTool, ToolResult, resolve_analysis_file

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


def format_hits(hits: list[dict]) -> str:
    """危险导入命中列表 → 文本;call_sites 全空的场景附加触发层指引。

    触发层(2026-08-23,三层策略第 2 层):call_sites 为空只代表 Ghidra 未
    提取到调用位置,不等于该导入未被调用。实测 webrtc_bridge 案例 Agent 曾
    据此误判"死导入"并放弃追查,而 videohub 同场景下 r2 xref 却挖出真实
    system 调用点。此处仅在**存在调用点缺失的命中**时附一句指引,引导 Agent
    用 xref_query 补查,避免跳成"未调用"的早熟结论。
    """
    lines = []
    has_empty = False
    for h in hits:
        sites = ", ".join(h.get("call_sites") or []) or "无调用点记录"
        if not h.get("call_sites"):
            has_empty = True
        lines.append(f"{h['name']} [{h.get('level', '?')}] ref_count={h.get('ref_count', 0)} 调用点: {sites}")
    if has_empty:
        lines.append("提示: 部分导入调用点记录为空——这仅代表 Ghidra 未提取到调用位置,"
                     "**不等于该导入未被调用**;请用 xref_query 查该符号(sym.imp.<name>)"
                     "定位真实调用者,勿直接判定为未调用/死导入。")
    return "\n".join(lines)


class ImportsQueryTool(AgentTool):
    name = "imports_query"
    description = "查询 ELF 的导入符号:默认列出全部危险函数(system/strcpy/exec 系等)及调用点;也可按名字过滤任意导入。"
    params_doc = ('Action Input: {"file_ref": "unitree/bin/idlc", "name": "system"} '
                  "—— name 可选;不带 name 列危险导入全表")

    def _run(self, file_ref: str, name: str = "") -> ToolResult:
        path = resolve_analysis_file(self.ctx, file_ref, ".imports.json")
        if path is None:
            return ToolResult(
                ok=False, text="",
                error=f"未找到 analysis/{file_ref}.imports.json(仅 ELF 有导入表)",
            )
        imports = load_imports(path)
        if name:
            hits = [i for i in imports if i.get("name") == name]
            if not hits:
                return ToolResult(ok=True, text=f"{file_ref} 无导入 '{name}'", data=[])
            return ToolResult(ok=True, text=format_hits(hits), data=hits)

        # 默认:危险导入全表,按级别排序
        hits = []
        for i in imports:
            level = DANGEROUS_IMPORTS.get(i.get("name", ""))
            if level:
                hits.append({**i, "level": level})
        hits.sort(key=lambda h: ("low", "medium", "high").index(h["level"]), reverse=True)
        if not hits:
            return ToolResult(ok=True, text=f"{file_ref} 未命中危险导入表", data=[])
        return ToolResult(
            ok=True,
            text=f"危险导入 {len(hits)} 项(按级别排序):\n{format_hits(hits)}",
            data=hits,
        )
