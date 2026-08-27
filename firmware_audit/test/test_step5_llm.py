"""Step5 LLMClient 重试机制单测(打桩 urlopen 与 sleep,零真实等待/零真实 API)。

覆盖:不可重试 HTTP 立即终止不重试 / 可重试错误按 10-20s 间隔自动重试且可恢复 /
全部重试耗尽后抛含最终详情的 LLMError / 空回复属可重试 / 间隔常量合法性 /
重试日志含时间戳·错误类型·次数·等待时长。
"""
from __future__ import annotations

import contextlib
import io
import json
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
    """按序触发预设行为(Exception 直接抛);耗尽后重复最后一个。记调用数。"""

    def __init__(self, behaviors: list):
        self.behaviors = behaviors
        self.calls = 0

    def urlopen(self, req, timeout=None):
        b = self.behaviors[min(self.calls, len(self.behaviors) - 1)]
        self.calls += 1
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
    with _stub_net(behaviors, sleeps):
        with contextlib.redirect_stderr(buf):
            try:
                _client().chat([{"role": "user", "content": "hi"}])
            except LLMError:
                pass
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
