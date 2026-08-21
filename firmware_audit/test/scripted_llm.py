"""Step5 测试替身:ScriptedLLM(按序吐预置回复,零 API)。

项目约定:测试替身放测试目录,不进生产代码文件(2026-08-19 结构规范化,
自 providers/llm_client.py 迁入,行为不变)。
"""
from __future__ import annotations


class ScriptedLLM:
    """按序吐预置回复,耗尽即抛错(防测试静默通过)。"""

    def __init__(self, replies: list[str]):
        self.replies = list(replies)
        self.calls: list[list[dict]] = []  # 记录每次请求的 messages
        self._idx = 0
        self.model = "scripted"  # runner 日志/make_llm 鸭子类型兼容

    @property
    def available(self) -> bool:
        return True

    @property
    def total_usage(self) -> dict:
        return {"prompt_tokens": 0, "completion_tokens": 0}

    def chat(self, messages: list[dict], **kw) -> tuple[str, dict]:
        # 存快照防后续 append 污染(测试要检查历史各轮内容)
        self.calls.append(list(messages))
        if self._idx >= len(self.replies):
            raise RuntimeError(f"ScriptedLLM 回复已耗尽(第 {self._idx + 1} 次调用)")
        reply = self.replies[self._idx]
        self._idx += 1
        return reply, {"prompt_tokens": 0, "completion_tokens": 0}
