"""transcript 落盘与 Observation 全文持久化(L3 持久化层)。

Transcript 封装一个 Agent 运行的全部磁盘痕迹:
  - <name>/transcript.jsonl  逐轮事件流(assistant/tool/observation/协议错误),
    每条带 ts 时间戳;assistant 事件带 in_chars/usage/elapsed(LLM 调用留痕)
  - <name>/obs/step<N>_<tool>.txt  每次工具结果的未截断全文(回读通道)

路径约定:transcript.jsonl 位于 process/agent/<name>/ 下,obs/ 与其同层;
obs 文件返回相对 process/ 的路径,与 read_file 白名单同根(LLM 可自主分页回读)。
行为等价自旧 react_loop 的 _log/_save_obs/_wrap_long_lines(2026-08-18 纯搬迁)。
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path


def wrap_long_lines(text: str, width: int = 4000) -> str:
    """超长行软折行:obs 文件要供 read_file 按行分页回读,单行超过 Observation
    入上下文预算会让分页失效(整行读出又触发截断,中间段永远取不回)。JSON/代码
    按 width 折行后仍肉眼可读;不影响入上下文的 text(折行只发生在落盘副本)。"""
    out: list[str] = []
    for line in text.splitlines():
        while len(line) > width:
            out.append(line[:width])
            line = line[width:]
        out.append(line)
    return "\n".join(out)


def reset_transcript(path: Path) -> None:
    """跑前清空 transcript(T6 收编的统一入口):重跑覆盖旧记录。

    transcript 目录布局(会话自身目录)与 obs/ 同层;obs 文件返回相对
    process/ 的路径,与 read_file 白名单同根。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("", encoding="utf-8")


class Transcript:
    """一次 Agent 运行的落盘器。path=None 时全部调用变 no-op(测试/静默模式)。"""

    def __init__(self, path: Path | None):
        self.path = path

    def log(self, step: int, phase: str, content: str, **extra) -> None:
        """追加一条 JSONL 事件(带 ts 时间戳)。

        忠实记录(票02,2026-09-06):content 一律全文落盘,不设记录层截断——
        transcript 是"LLM 实际看到了什么"的存证,截断提示等中间内容被记录层
        裁掉会二次误导排查(2026-09-05 target/1 实测)。尺寸天然有界:
        observation 受入上下文上限约束(全局 16k / per-tool 覆盖),
        assistant/tool 事件源自 LLM 回复,受 max_tokens 约束。
        """
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)  # 独立调用无 runner 预建
        entry = {"step": step, "phase": phase,
                 "ts": datetime.now().isoformat(timespec="seconds"),
                 "content": content, **extra}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def save_obs(self, step: int, tool: str, obs_full: str) -> str | None:
        """Observation 全文另存 obs/step<N>_<tool>.txt。

        返回相对 process/ 的路径(入 transcript 的 obs_file 字段,也是
        read_file 回读参数);path=None 返回 None。文件名含步骤号+工具名,
        超长工具(如 cve_bin_tool_scan JSON)截断丢掉的中间部分可分页回查。
        """
        if self.path is None:
            return None
        d = self.path.parent / "obs"
        d.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^\w.-]", "_", tool) or "tool"
        p = d / f"step{step:03d}_{safe}.txt"
        p.write_text(wrap_long_lines(obs_full), encoding="utf-8")
        try:
            return p.relative_to(self.path.parents[2]).as_posix()  # agent/<name>/obs/...
        except (ValueError, IndexError):
            return str(p)
