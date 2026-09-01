"""Step5 LLMClient 重试机制单测(打桩 urlopen 与 sleep,零真实等待/零真实 API)。

覆盖:不可重试 HTTP 立即终止不重试 / 可重试错误按 10-20s 间隔自动重试且可恢复 /
全部重试耗尽后抛含最终详情的 LLMError / 空回复属可重试 / 间隔常量合法性 /
重试日志含时间戳·错误类型·次数·等待时长。
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import urllib.error
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import firmware_audit.step5_agent.providers.llm_client as lc
from firmware_audit.step5_agent.providers.llm_client import LLMClient, LLMError


def _ok_body(content: str = "ok") -> bytes:
    return json.dumps({
        "choices": [{"message": {"content": content}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }).encode("utf-8")


def _empty_body() -> bytes:
    return json.dumps({
        "choices": [{"message": {"content": "", "reasoning_content": ""}}],
        "usage": {},
    }).encode("utf-8")


def _reasoning_body(reasoning: str, content: str = "") -> bytes:
    return json.dumps({
        "choices": [{"message": {"content": content,
                                 "reasoning_content": reasoning}}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }).encode("utf-8")


class _Resp:
    def __init__(self, body: bytes):
        self._b = body

    def read(self) -> bytes:
        return self._b

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _Net:
    """按序触发预设行为(Exception 直接抛);耗尽后重复最后一个。

    记调用数 + 每次请求的原始 body(供断言续写请求内容)。"""

    def __init__(self, behaviors: list):
        self.behaviors = behaviors
        self.calls = 0
        self.request_bodies: list[bytes] = []

    def urlopen(self, req, timeout=None):
        b = self.behaviors[min(self.calls, len(self.behaviors) - 1)]
        self.calls += 1
        if hasattr(req, "data"):
            self.request_bodies.append(req.data)
        if isinstance(b, Exception):
            raise b
        return _Resp(b)


@contextlib.contextmanager
def _stub_net(behaviors: list, sleeps: list[float]):
    """替换 lc.time(sleep/strftime)与 urlopen;退出恢复。"""
    real_time, real_urlopen = lc.time, lc.urllib.request.urlopen
    net = _Net(behaviors)
    lc.time = SimpleNamespace(sleep=lambda s: sleeps.append(s),
                              strftime=real_time.strftime)
    lc.urllib.request.urlopen = net.urlopen
    try:
        yield net
    finally:
        lc.time = real_time
        lc.urllib.request.urlopen = real_urlopen


def _client() -> LLMClient:
    return LLMClient(api_key="test-key", base_url="http://stub", model="stub")


def test_non_retryable_http() -> list[str]:
    fails: list[str] = []
    sleeps: list[float] = []
    err = urllib.error.HTTPError("u", 401, "Unauthorized", None, io.BytesIO(b"bad key"))
    with _stub_net([err], sleeps) as net:
        try:
            _client().chat([{"role": "user", "content": "hi"}])
            fails.append("401 应抛 LLMError")
        except LLMError as e:
            if "不可重试" not in str(e):
                fails.append(f"错误信息应标明不可重试: {e}")
        if net.calls != 1:
            fails.append(f"401 应只发一次请求(不重试), got {net.calls}")
    if sleeps:
        fails.append(f"401 不应 sleep, got {sleeps}")
    return fails


def test_retry_then_success() -> list[str]:
    fails: list[str] = []
    sleeps: list[float] = []
    behaviors = [
        urllib.error.HTTPError("u", 500, "Server Error", None, io.BytesIO(b"boom")),
        TimeoutError("read timeout"),
        _ok_body("recovered"),
    ]
    with _stub_net(behaviors, sleeps) as net:
        content, _u = _client().chat([{"role": "user", "content": "hi"}])
        if content != "recovered":
            fails.append(f"重试后应返回成功回复, got {content!r}")
        if net.calls != 3:
            fails.append(f"应共请求 3 次(首次+2 重试), got {net.calls}")
    if sleeps != [10, 15]:
        fails.append(f"两次重试应等待 10/15 秒, got {sleeps}")
    return fails


def test_exhaust_all_retries() -> list[str]:
    fails: list[str] = []
    sleeps: list[float] = []
    with _stub_net([TimeoutError("down")], sleeps) as net:
        try:
            _client().chat([{"role": "user", "content": "hi"}])
            fails.append("全部重试失败应抛 LLMError")
        except LLMError as e:
            msg = str(e)
            if "全部失败" not in msg or "TimeoutError" not in msg:
                fails.append(f"最终错误应含重试次数与最后错误类型: {msg}")
        if net.calls != 1 + lc.MAX_RETRIES:
            fails.append(f"应共请求 {1 + lc.MAX_RETRIES} 次, got {net.calls}")
    if sleeps != list(lc.RETRY_INTERVALS):
        fails.append(f"sleep 序列应等于 RETRY_INTERVALS, got {sleeps}")
    return fails


def test_empty_reply_is_retryable() -> list[str]:
    fails: list[str] = []
    sleeps: list[float] = []
    with _stub_net([_empty_body(), _ok_body("second")], sleeps) as net:
        content, _u = _client().chat([{"role": "user", "content": "hi"}])
        if content != "second" or net.calls != 2:
            fails.append(f"空回复应被重试且可恢复, calls={net.calls} content={content!r}")
    if sleeps != [lc.RETRY_INTERVALS[0]]:
        fails.append(f"空回复应触发一次重试等待, got {sleeps}")
    return fails


def test_reasoning_split_return() -> list[str]:
    """2026-08-30 拆分语义:chat 只返回正文,思考随 usage.reasoning_content 携带。

    防止推理段的"草稿 Action"被 ReAct 解析器当真实调用执行。"""
    fails: list[str] = []
    with _stub_net([_reasoning_body(
        "内部思考草稿 Action: echo", "Thought: 查\nAction: echo\nAction Input: {}")], []) as _net:
        content, usage = _client().chat([{"role": "user", "content": "hi"}])
        if "草稿" in content or content.strip() != "Thought: 查\nAction: echo\nAction Input: {}":
            fails.append(f"chat 应只返回正文: {content!r}")
        if usage.get("reasoning_content") != "内部思考草稿 Action: echo":
            fails.append(f"思考应随 usage.reasoning_content 提供: {usage}")
    return fails


def test_empty_content_with_reasoning_continuation() -> list[str]:
    """ADR-0005:content 空 + reasoning 非空 → 截断续写,不判空回复硬重试。

    断言:续写请求发出(assistant 带 reasoning_content + 续写提示 + 原 max_tokens)、
    返回续写 content、无重试等待、续写消息不污染调用方原 messages。"""
    fails: list[str] = []
    sleeps: list[float] = []
    orig_msgs = [{"role": "user", "content": "hi"}]
    with _stub_net([_reasoning_body("想烧满预算的思考"), _ok_body("接续后的正文")],
                   sleeps) as net:
        content, usage = _client().chat(orig_msgs)
        if content != "接续后的正文":
            fails.append(f"应返回续写 content: {content!r}")
        if net.calls != 2:
            fails.append(f"应共 2 次请求(原请求 + 1 次续写), got {net.calls}")
        if sleeps:
            fails.append(f"续写成功不应触发重试等待: {sleeps}")
        # 续写请求内容:assistant 带 reasoning_content + 续写提示 + 原 max_tokens
        req1 = json.loads(net.request_bodies[0].decode("utf-8"))
        req2 = json.loads(net.request_bodies[1].decode("utf-8"))
        msgs2 = req2["messages"]
        if msgs2[-2].get("role") != "assistant" or \
                msgs2[-2].get("reasoning_content") != "想烧满预算的思考":
            fails.append(f"续写请求应带 assistant reasoning_content: {msgs2[-2]}")
        if msgs2[-1].get("role") != "user" or \
                "别展开思考" not in msgs2[-1].get("content", ""):
            fails.append(f"续写请求应带续写提示: {msgs2[-1]}")
        if req2.get("max_tokens") != req1.get("max_tokens"):
            fails.append("续写应使用原 max_tokens 再调")
        # chat 对上层透明:原 messages 不被续写污染(续写只回传 API)
        if orig_msgs != [{"role": "user", "content": "hi"}]:
            fails.append(f"续写不得改写调用方 messages: {orig_msgs}")
        # 思考随 usage 返回(截断段 + 续写段),供 transcript 留档审计
        if usage.get("reasoning_content") != "想烧满预算的思考":
            fails.append(f"usage 应携带被截断的思考: {usage}")
        # usage 全量合并:两次调用的 token 用量都计入(prompt/completion 各 1+1)
        if usage.get("prompt_tokens") != 2 or usage.get("completion_tokens") != 2:
            fails.append(f"usage 应合并两次调用用量: {usage}")
    return fails


def test_continuation_reasoning_merge() -> list[str]:
    """ADR-0005:续写响应本身带 reasoning_content → 思考拼回完整段(截断+续写)。"""
    fails: list[str] = []
    sleeps: list[float] = []
    with _stub_net([_reasoning_body("截断思考"), _reasoning_body("续写思考", "续写正文")],
                   sleeps) as _net:
        content, usage = _client().chat([{"role": "user", "content": "hi"}])
        if content != "续写正文":
            fails.append(f"应返回续写 content: {content!r}")
        if usage.get("reasoning_content") != "截断思考\n续写思考":
            fails.append(f"思考应拼回完整段: {usage.get('reasoning_content')!r}")
        # 合并 token 用量(prompt/completion 各 1+1)
        if usage.get("prompt_tokens") != 2 or usage.get("completion_tokens") != 2:
            fails.append(f"usage 应合并两次调用用量: {usage}")
    return fails


def test_continuation_failure_degrades_to_retry() -> list[str]:
    """ADR-0005:续写请求失败(400 等)→ 降级为普通重试,不阻塞流程。

    第 1 次:content 空 + reasoning 非空 → 触发续写(第 2 次请求);
    续写返回 400 → 降级普通重试(第 3 次请求重发原请求——不含 reasoning_content
    ——并成功);续写只尝试一次,不反复打不兼容供应商。"""
    fails: list[str] = []
    sleeps: list[float] = []
    behaviors = [
        _reasoning_body("想烧满预算的思考"),
        urllib.error.HTTPError("u", 400, "Bad Request", None,
                               io.BytesIO(b"reasoning_content unsupported")),
        _ok_body("重试后的最终回复"),
    ]
    with _stub_net(behaviors, sleeps) as net:
        content, _ = _client().chat([{"role": "user", "content": "hi"}])
        if content != "重试后的最终回复":
            fails.append(f"续写失败后应降级重试并恢复: {content!r}")
        if net.calls != 3:
            fails.append(f"应共 3 次请求(原+续写+降级重试), got {net.calls}")
        # 第 3 次(降级重试)是原请求重发,不得再带 reasoning_content 续写消息
        req3 = json.loads(net.request_bodies[2].decode("utf-8"))
        for m in req3["messages"]:
            if "reasoning_content" in m:
                fails.append(f"降级重试不得带 reasoning_content: {m}")
                break
    if sleeps != [lc.RETRY_INTERVALS[0]]:
        fails.append(f"降级重试应等待 {lc.RETRY_INTERVALS[0]}s, got {sleeps}")
    return fails


def test_default_max_tokens_bumped() -> list[str]:
    """ADR-0005:DEFAULT_MAX_TOKENS 16384→32768;env LLM_MAX_TOKENS 仍可覆盖。"""
    fails: list[str] = []
    if lc.DEFAULT_MAX_TOKENS != 32_768:
        fails.append(f"DEFAULT_MAX_TOKENS 应为 32768, got {lc.DEFAULT_MAX_TOKENS}")
    os.environ["LLM_MAX_TOKENS"] = "8192"
    sleeps: list[float] = []
    try:
        with _stub_net([_ok_body("ok")], sleeps) as net:
            _client().chat([{"role": "user", "content": "hi"}])
        req = json.loads(net.request_bodies[0].decode("utf-8"))
        if req.get("max_tokens") != 8192:
            fails.append(f"env 应覆盖 max_tokens: {req.get('max_tokens')}")
    finally:
        os.environ.pop("LLM_MAX_TOKENS", None)
    return fails


def test_intervals_in_range_and_logs() -> list[str]:
    fails: list[str] = []
    if len(lc.RETRY_INTERVALS) != lc.MAX_RETRIES:
        fails.append("RETRY_INTERVALS 长度应等于 MAX_RETRIES")
    for w in lc.RETRY_INTERVALS:
        if not (10 <= w <= 20):
            fails.append(f"重试间隔应处于 10-20s: {w}")
    # 日志内容:时间戳前缀/错误类型/重试次数/等待时长
    sleeps: list[float] = []
    buf = io.StringIO()
    behaviors = [urllib.error.HTTPError("u", 503, "NA", None, io.BytesIO(b"down"))]
    with _stub_net(behaviors, sleeps), contextlib.redirect_stderr(buf), \
        contextlib.suppress(LLMError):
        _client().chat([{"role": "user", "content": "hi"}])
    log = buf.getvalue()
    for needle in ("[llm-retry]", "HTTP 503", "1/3", "10s 后重试"):
        if needle not in log:
            fails.append(f"重试日志缺关键信息 {needle!r}: {log[:200]!r}")
    if log.count("[llm-retry]") < lc.MAX_RETRIES:
        fails.append(f"日志行数应不少于重试次数: {log.count('[llm-retry]')}")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("non_retryable_http", test_non_retryable_http),
        ("retry_then_success", test_retry_then_success),
        ("exhaust_all_retries", test_exhaust_all_retries),
        ("empty_reply_is_retryable", test_empty_reply_is_retryable),
        ("reasoning_split_return", test_reasoning_split_return),
        ("empty_content_with_reasoning_continuation", test_empty_content_with_reasoning_continuation),
        ("continuation_reasoning_merge", test_continuation_reasoning_merge),
        ("continuation_failure_degrades_to_retry", test_continuation_failure_degrades_to_retry),
        ("default_max_tokens_bumped", test_default_max_tokens_bumped),
        ("intervals_in_range_and_logs", test_intervals_in_range_and_logs),
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
