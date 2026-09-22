"""Agent 工具基类与统一返回结构。

ToolResult 是数据口袋:ReAct 循环只消费它,不感知工具的数据来源
(CLI 进程 / Step4 工件读盘 / HTTP API 三类,详见 agents.md §三)。
"""
from __future__ import annotations

import json
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

# Observation 入上下文预算:全局默认 16000 字符(2026-09-06 票01,由 8KB
# 小窗口时代的保守值上调——target/1 实测 141 个 Observation 仅 12 个超 8k,
# 16k 覆盖除 summarize 外全部超限样本);单工具可用类属性 max_text_chars 覆盖
MAX_TEXT_CHARS = 16000


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
    # 当前活动世代目录(票 16):Host 在建/选世代后回填,工具据此把会话台账
    # 写进世代内;独立演示(None,默认)回落 process_dir 下 qemu_sessions/。
    generation_dir: Path | None = None


# 盘符前缀(C:/ 或 C:形态,反斜杠换算后)按绝对引用拒绝——Windows 上 Path
# 语义本就如此,POSIX 上需显式判定(CONTEXT.md 路径白名单"绝对盘符 → ok=False")
_DRIVE_PREFIX_RE = re.compile(r"^[A-Za-z]:")


def resolve_within(root: Path, ref: str | None) -> Path | None:
    """把 ref(相对路径,可能带 \\ 分隔)解析为 root 下的绝对路径;越界返回 None。

    C4(2026-08-31)收敛:各工具"防路径穿越"判定原为同一句
      if p != root and root not in p.parents
    复制在 base.resolve_analysis_file / cli_base.container_path / read_file /
    list_files / search_code._resolve_scope / binwalk_rescan 六处,规则已分叉。
    统一收口到此;空串/None/越界(.. / 绝对路径/盘符前缀)一律返回 None,由
    调用方决定是报错还是静默跳过(失败不崩,见 rules.md)。根目录自身(如 ".")
    按 containment 语义视为合法,返回 root(调用方若要"根即越界"需自行特判)。
    """
    base = Path(root).resolve()
    r = str(ref or "").strip().replace("\\", "/")
    if not r:
        return None
    if _DRIVE_PREFIX_RE.match(r):
        return None
    cand = (base / r).resolve()
    if cand != base and base not in cand.parents:
        return None
    return cand


def truncate_text(text: str, limit: int = MAX_TEXT_CHARS) -> str:
    """Observation 入上下文截断(学 DeepAudit:截断必告知总量,头尾保留)。

    头 75% + 尾 20%(头部有 JSON/代码结构,尾部常有结论行);提示注明
    省略字符数与全文总长,并指引全文位置(obs/ 目录,见 Transcript.save_obs),
    LLM 可据此改用分页参数重读。
    """
    if len(text) <= limit:
        return text
    head, tail = int(limit * 0.75), int(limit * 0.20)
    omitted = len(text) - head - tail
    notice = (f"\n... [已截断:省略中间 {omitted} 字符,全文共 {len(text)} 字符,"
              f"具体回读路径见本条 Observation 末尾] ...\n")
    return text[:head] + notice + text[-tail:]


# 声明字段 type 的取值 → Python 类型 / JSON 骨架占位符(单一 map,避免对同一
# 字符串判别的重复 switch;声明了不支持的 type 时校验失败不静默放行)
_TYPE_CHECKS = {"str": str, "int": int, "bool": bool}
_PLACEHOLDERS = {"str": "<str>", "int": 0, "bool": False}


def validate_params(spec: dict, kwargs: dict) -> tuple[dict | None, str | None]:
    """按结构化参数声明校验(执行侧 B,ADR-0004)。

    未知键 / 类型错误 / 枚举越界 / 缺失必选 → 返回 (None, 优雅错误文本),
    由 execute 转成 ok=False;校验失败一律不触发 _run,不让 Python 异常文案
    暴露给 LLM(§7#2 根因:畸形调用收到的是 TypeError 而不是可自纠的指引)。

    声明字段:type(str/int/bool)/required/default/enum(可选)。dict 保留声明
    顺序,"合法参数"清单按声明顺序列出(如 read_file → path/offset/limit)。
    """
    legal = set(spec)
    unknown = [k for k in kwargs if k not in legal]  # 按调用方传入顺序列出
    if unknown:
        return None, f"未知参数 {', '.join(unknown)},已忽略;合法参数:{'/'.join(spec)}"

    checked: dict[str, object] = {}
    for name, decl in spec.items():
        if name not in kwargs:
            continue
        val = kwargs[name]
        t = decl.get("type", "str")
        cls = _TYPE_CHECKS.get(t)
        if cls is None:
            return None, f"参数 {name} 声明了不支持的 type '{t}'"
        # bool 是 int 的子类(isinstance(True, int) 为真),int 参数须显式排除 bool
        if not isinstance(val, cls) or (t == "int" and isinstance(val, bool)):
            return None, f"参数 {name} 类型错误: 期望 {t},收到 {type(val).__name__}"
        enum = decl.get("enum")
        if enum:
            # str 枚举大小写不敏感(如 language: 'python'/'PYTHON' 等价,与 _run 的
            # .lower() 归一一致);非 str 枚举仍按值精确比较
            hit = (isinstance(val, str)
                   and val.strip().lower() in {str(e).lower() for e in enum}) \
                if t == "str" else val in enum
            if not hit:
                return None, (f"参数 {name} 取值非法: {val!r};"
                              f"可选: {'/'.join(map(str, enum))}")
        checked[name] = val

    missing = [n for n in spec if spec[n].get("required") and n not in kwargs]
    if missing:
        return None, f"缺失必选参数: {', '.join(missing)}"

    return checked, None


def render_params_doc(params: dict) -> str:
    """结构化参数声明 → LLM 可读参数规格(声明侧 A,ADR-0004)。

    与校验共享同一份声明(单一来源):首行是 JSON 骨架(必填参数用 <type>
    占位,可选参数填默认值;默认值为空串/None 时也用 <type> 占位,避免 LLM
    照抄空串),后续每行一个参数列出 类型/必填/默认/枚举 + 说明。
    空声明返回空串(无契约工具,如测试替身)。
    """
    if not params:
        return ""

    skeleton: dict[str, object] = {}
    lines: list[str] = []
    for name, d in params.items():
        t = d.get("type", "str")
        placeholder = _PLACEHOLDERS.get(t, "<str>")
        default = d.get("default")
        required = bool(d.get("required"))
        skeleton[name] = placeholder if (required or default in (None, "")) else default
        bits = [t]
        if required:
            bits.append("必填")
        elif default not in (None, ""):
            bits.append(f"默认 {default}")
        else:
            bits.append("可选")
        if d.get("enum"):
            bits.append("可选值: " + "/".join(map(str, d["enum"])))
        head = f"{name} ({', '.join(bits)})"
        desc = d.get("desc", "")
        lines.append(f"  {head}: {desc}" if desc else f"  {head}")
    return json.dumps(skeleton, ensure_ascii=False) + "\n" + "\n".join(lines)


class AgentTool(ABC):
    name: str = ""
    description: str = ""  # 写进系统提示词,LLM 据此选工具
    params: dict[str, dict] = {}  # 结构化参数声明(单一来源:params_doc 渲染 + execute 校验共用)
    # Observation 入上下文字符上限覆盖(票01):None=用全局默认 MAX_TEXT_CHARS;
    # 素材类工具声明更大值(取值依据见 SummarizeTool 声明点)
    max_text_chars: int | None = None

    def __init__(self, ctx: ToolContext, role: str | None = None):
        self.ctx = ctx
        # 角色随构造传入(票 16:执行会话按 (角色, 归属) 记账);None = 未按
        # 角色过滤的 legacy 实例化(测试/演示)。
        self.role = role

    @property
    def text_limit(self) -> int:
        """本工具 Observation 入上下文的字符上限(per-tool 覆盖优先于全局默认)。"""
        return MAX_TEXT_CHARS if self.max_text_chars is None else self.max_text_chars

    def _finalize(self, result: ToolResult, start: float) -> ToolResult:
        """统一收尾:计时/原文保留/截断(单一出处——数值与规则变更只动这里)。"""
        result.elapsed = round(time.time() - start, 3)
        result.raw = result.text
        result.text = truncate_text(result.text, self.text_limit)
        return result

    @property
    def params_doc(self) -> str:
        """参数说明(声明侧 A):从 params 结构化声明渲染,LLM 据此填 Action Input。

        子类可沿用旧的类属性 params_doc 字符串(测试/演示替身)覆盖此属性;
        声明了 params 的生产工具自动渲染,不再手写散文。
        """
        return render_params_doc(self.params)

    def execute(self, **kw) -> ToolResult:
        """统一入口:参数校验(契约) → 执行 → 计时、异常捕获、text 截断。失败不崩。

        声明了 params 的工具先按声明校验:未知键/类型错误/缺失必选 → 优雅错误
        返回(不抛异常);未声明 params 的工具保持透传(legacy 兼容)。
        """
        start = time.time()
        try:
            if self.params:
                checked, err = validate_params(self.params, kw)
                if err is not None:
                    result = ToolResult(ok=False, text="", error=err)
                else:
                    result = self._run(**checked)
            else:
                result = self._run(**kw)
        except Exception as e:
            result = ToolResult(ok=False, text="", error=f"{type(e).__name__}: {e}")
        return self._finalize(result, start)

    @abstractmethod
    def _run(self, **kw) -> ToolResult: ...


# Agent 引用文件时可能带的各种后缀(先长后短,避免 .json 吃掉 .strings.json)
_KNOWN_SUFFIXES = (".strings.json", ".imports.json", ".functions.json", ".c", ".json")


def resolve_analysis_file(ctx: ToolContext, file_ref: str, suffix: str) -> Path | None:
    """file_ref → process/analysis/<rel><suffix>,宽容解析,找不到返回 None。

    接受引用:rel_path("unitree/bin/idlc")、误带后缀("idlc.c")、
    前缀工具路径("extracted/unitree/bin/idlc"——ADR-0008 后 file 字段统一
    工具路径,剥前缀再解析;"analysis/unitree/x.c"——semgrep C 双扫命中的
    file 本身在 analysis 树下,剥掉后指向同树内边车/源文件)。
    安全约束(2026-08-27):解析后必须仍位于 process/analysis/ 之下——
    拒绝绝对路径与 .. 越界,防 Agent(或被污染的 file_ref)借 find/query 系列
    工具任意读宿主文件。越界一律返回 None。
    """
    base = (ctx.process_dir / "analysis").resolve()
    ref = (file_ref.strip().replace("\\", "/")
           .removeprefix("extracted/").removeprefix("analysis/"))
    for ext in _KNOWN_SUFFIXES:
        if ref.endswith(ext):
            ref = ref[: -len(ext)]
            break
    cand = resolve_within(base, ref + suffix)
    return cand if cand and cand.exists() else None
