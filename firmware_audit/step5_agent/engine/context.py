"""四分区上下文管理 + 超阈值压缩。

四分区(agents.md 已定):
  1. system   系统提示词(不动)
  2. init     初始任务注入(工件摘要,不动)
  3. summary  概括区(压缩产物,单条 user)
  4. recent   保留区(逐轮 assistant/user(Observation) 交替)

压缩:估算 token 超阈值时,把保留区最老一半交给 LLM 概括
(四类信息:已确认事实/已排除项/未决问题/证据指针),摘要并入概括区。

阈值(2026-08-18):deepseek-v4-flash 上下文窗口 1M,窗口 × 0.6 = 600k
est tokens 触发压缩(留 40% 余量给单轮 Observation 峰值与概括回写)。
"""
from __future__ import annotations

COMPACT_PROMPT = """你是审计会话压缩器。把下面的对话历史压缩成一份摘要,供继续审计时使用。
必须保留四类信息,逐条列出:
1. 已确认事实(工具返回的关键结论)
2. 已排除项(查过且无问题的)
3. 未决问题(还没查/查了一半的)
4. 证据指针(涉及的文件路径/函数/地址,原样保留)

只输出摘要正文,不要客套。历史:
"""


def est_tokens(messages: list[dict]) -> int:
    # 中英混合近似:1 token ≈ 2 字符(估算足够触发判断,不追求精确)
    return sum(len(m.get("content", "")) for m in messages) // 2


class ContextManager:
    def __init__(self, system_prompt: str, init_user: str,
                 max_est_tokens: int = 1_000_000, trigger_ratio: float = 0.6):
        # 阈值 = max_est_tokens × trigger_ratio = 1M × 0.6 = 600k est tokens
        self.system = {"role": "system", "content": system_prompt}
        self.init = {"role": "user", "content": init_user}
        self.summaries: list[str] = []   # 概括区(可能压缩多次)
        self.recent: list[dict] = []     # 保留区
        self.max_est_tokens = max_est_tokens
        self.trigger_ratio = trigger_ratio
        self.compactions = 0

    # ---- 消息构建与追加 ----

    def build_messages(self) -> list[dict]:
        msgs = [self.system, self.init]
        if self.summaries:
            msgs.append({"role": "user",
                         "content": "[前情摘要(早期轮次已压缩)]\n" + "\n---\n".join(self.summaries)})
        msgs.extend({"role": m["role"], "content": m["content"]} for m in self.recent)
        return msgs

    def append(self, role: str, content: str) -> None:
        self.recent.append({"role": role, "content": content})

    # ---- 压缩 ----

    def needs_compaction(self) -> bool:
        return est_tokens(self.build_messages()) > int(self.max_est_tokens * self.trigger_ratio)

    def compact(self, llm) -> bool:
        """压缩保留区最老一半。返回是否执行(LLM 失败时返回 False,本轮跳过)。"""
        if len(self.recent) < 4:
            return False  # 太少不值得压缩
        half = len(self.recent) // 2
        # 对齐到 user(Observation)边界,避免把 assistant 悬空开头
        while half < len(self.recent) and self.recent[half]["role"] != "assistant":
            half += 1
        if half <= 0 or half >= len(self.recent):
            return False
        old = self.recent[:half]
        self.recent = self.recent[half:]

        transcript = "\n".join(f"{m['role']}: {m['content']}" for m in old)
        try:
            summary, _ = llm.chat([
                {"role": "system", "content": COMPACT_PROMPT},
                {"role": "user", "content": transcript[-30000:]},
            ], max_tokens=4096)
        except Exception:
            # 压缩失败不能丢历史:还原保留区
            self.recent = old + self.recent
            return False
        self.summaries.append(summary.strip())
        self.compactions += 1
        return True

    def maybe_compact(self, llm) -> bool:
        """超阈值则压缩(循环兜底,单次调用通常足够)。"""
        if not self.needs_compaction():
            return False
        return self.compact(llm)
