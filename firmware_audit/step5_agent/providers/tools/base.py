"""Agent 工具基类与统一返回结构。

ToolResult 是数据口袋:ReAct 循环只消费它,不感知工具的数据来源
(CLI 进程 / Step4 工件读盘 / HTTP API 三类,详见 agents.md §三)。
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

# Observation 入上下文预算(agents.md 约定 ≤8KB,全文另落盘 transcript)
MAX_TEXT_CHARS = 8000


@dataclass
class ToolResult:
    ok: bool
    text: str
    data: dict | list | None = None
    error: str | None = None
    elapsed: float = 0.0
    raw: str = ""  # 截断前原文(execute 统一填充;全文落盘用,入上下文的是 text)


@dataclass
class ToolContext:
    """一次 Step5 运行内不变的环境锚点。"""

    process_dir: Path  # target/<N>/process(工件根,也是 read_file 白名单根)


def truncate_text(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    """Observation 入上下文截断(学 DeepAudit:截断必告知总量,头尾保留)。

    头 75% + 尾 20%(头部有 JSON/代码结构,尾部常有结论行);提示注明
    省略字符数与全文总长,并指引全文位置(obs/ 目录,见 react_loop._save_obs),
    LLM 可据此改用分页参数重读。
    """
    if len(text) <= limit:
        return text
    head, tail = int(limit * 0.75), int(limit * 0.20)
    omitted = len(text) - head - tail
    notice = (f"\n... [已截断:省略中间 {omitted} 字符,全文共 {len(text)} 字符,"
              f"具体回读路径见本条 Observation 末尾] ...\n")
    return text[:head] + notice + text[-tail:]


class AgentTool(ABC):
    name: str = ""
    description: str = ""  # 写进系统提示词,LLM 据此选工具
    params_doc: str = ""   # 参数说明,LLM 据此填 Action Input

    def __init__(self, ctx: ToolContext):
        self.ctx = ctx

    def execute(self, **kw) -> ToolResult:
        """统一入口:计时、异常捕获、text 截断(原文留 raw 供落盘)。失败不崩。"""
        start = time.time()
        try:
            result = self._run(**kw)
        except Exception as e:
            result = ToolResult(ok=False, text="", error=f"{type(e).__name__}: {e}")
        result.elapsed = round(time.time() - start, 3)
        result.raw = result.text
        result.text = truncate_text(result.text)
        return result

    @abstractmethod
    def _run(self, **kw) -> ToolResult: ...


# Agent 引用文件时可能带的各种后缀(先长后短,避免 .json 吃掉 .strings.json)
_KNOWN_SUFFIXES = (".strings.json", ".imports.json", ".functions.json", ".c", ".json")


def resolve_analysis_file(ctx: ToolContext, file_ref: str, suffix: str) -> Path | None:
    """file_ref → process/analysis/<rel><suffix>,宽容解析,找不到返回 None。

    接受三种引用:rel_path("unitree/bin/idlc")、误带后缀("idlc.c")、绝对路径。
    """
    ref = file_ref.strip().replace("\\", "/")
    p = Path(ref)
    if p.is_absolute():
        return p if p.exists() else None
    for ext in _KNOWN_SUFFIXES:
        if ref.endswith(ext):
            ref = ref[: -len(ext)]
            break
    cand = ctx.process_dir / "analysis" / (ref + suffix)
    return cand if cand.exists() else None
