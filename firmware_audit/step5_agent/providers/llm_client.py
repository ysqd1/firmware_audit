"""LLM 客户端:OpenAI 兼容 /chat/completions,非流式。

配置全走环境变量(不硬编码供应商,agents.md §四):
  FIRMWARE_AUDIT_LLM_API_KEY  必填(无则 Step5 立即终止,不做降级)
  FIRMWARE_AUDIT_LLM_BASE_URL 默认 https://api.deepseek.com
  FIRMWARE_AUDIT_LLM_MODEL    默认 deepseek-v4-flash
  兼容别名:DEEPSEEK_API_KEY / LLM_API_KEY / LLM_BASE_URL / LLM_MODEL

.env 自动加载(2026-08-19):LLMClient 构造时从 firmware_audit/.env(规范位置)
与 CWD 上级链搜索 .env 并注入进程环境;已设置的环境变量优先,不被文件覆盖。
_ENV_ANCHORS 供测试把搜索位置重定向到临时目录(设 None 恢复默认)。

流式与否:agents.md 已定 MVP 非流式——ReAct 循环要完整回复才能正则解析,
流式收益为零;预留 stream 参数,二期做实时进度再实现 SSE。

重试机制(2026-08-18):首次失败后按错误类型分流——
  可重试(网络瞬断/超时/HTTP 5xx/429/空回复/响应非 JSON)→ 按 RETRY_INTERVALS
  (10-20s)间隔自动重试,至多 MAX_RETRIES 次;每次重试向 stderr 输出带时间戳的
  日志(错误类型+重试次数+等待时长);全部失败后抛携带最终错误详情的 LLMError。
  不可重试(HTTP 400/401/403/404 配置类错误)→ 立即抛 LLMError,不做任何重试。
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_BASE_URL = "https://api.deepseek.com"
DEFAULT_MODEL = "deepseek-v4-flash"
TIMEOUT = 180        # 秒:非流式长回复 + 网络抖动余量
MAX_RETRIES = 3      # 首次失败后的最大重试次数(共 1+3=4 次尝试)
RETRY_INTERVALS = (10, 15, 20)  # 每次重试前的等待秒数,恒在 10-20s 区间
NON_RETRYABLE_HTTP = (400, 401, 403, 404)  # 请求/配置类错误,重试无意义
# 输出预算(2026-08-22 实测教训:8192 会截断 Final Answer):
# 推理模型的思考(reasoning_content)与正文共享 max_tokens,13 条 findings 的
# JSON(约 2.5k token)+思考很容易超 8192 → 正文腰斩 → JSON 解析失败降级 .md。
# 默认 16384,环境变量 LLM_MAX_TOKENS 可覆盖(如 API 上限更低时调回)。
DEFAULT_MAX_TOKENS = 16_384

# .env 搜索位置重定向(测试用;None = 默认:firmware_audit 包根 + CWD 上级链)
_ENV_ANCHORS: list[Path] | None = None

_ENV_LINE_RE = re.compile(r"\s*([A-Za-z_]\w*)\s*=\s*(.+?)\s*$")


def load_env_file() -> Path | None:
    """定位并加载 .env 到进程环境(已设的环境变量优先,不覆盖)。

    搜索顺序:firmware_audit 包根(.env 规范位置)→ CWD 及其上两层。
    找到即解析 KEY=VALUE 行(跳过 # 注释)并返回该 .env 路径(供报错定位);
    未找到返回 None。幂等:os.environ 判重保证重复调用无副作用。
    """
    pkg_root = Path(__file__).resolve().parents[2]  # firmware_audit/
    if _ENV_ANCHORS is not None:  # 测试重定向:只用指定目录,不叠加默认链
        candidates = [a / ".env" for a in _ENV_ANCHORS]
    else:
        candidates = [pkg_root / ".env"]
        d = Path.cwd().resolve()
        for _ in range(3):
            candidates.append(d / ".env")
            if d.parent == d:
                break
            d = d.parent
    for cand in candidates:
        if not cand.is_file():
            continue
        for line in cand.read_text(encoding="utf-8", errors="replace").splitlines():
            m = _ENV_LINE_RE.match(line)
            if m and m.group(1) not in os.environ:
                os.environ[m.group(1)] = m.group(2)
        return cand
    return None


class LLMError(Exception):
    pass


class _RetryableError(Exception):
    """内部标记:值得重试的瞬时失败(如空回复)。"""


def _log_retry(event: str, err: str, wait: float | None = None) -> None:
    """重试日志 → stderr:本地时间戳 + 事件(含次数)+ 错误详情 + 等待时长。"""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    tail = f", {wait:.0f}s 后重试" if wait is not None else ""
    print(f"[llm-retry] {ts} {event}: {err}{tail}", file=sys.stderr)


class LLMClient:
    """非流式 chat 补全。失败抛 LLMError(调用方应立即终止,不做降级)。"""

    def __init__(self, api_key: str | None = None, base_url: str | None = None,
                 model: str | None = None, stream: bool = False):
        load_env_file()  # .env 自动加载(环境变量优先,见函数 docstring)
        env = os.environ.get
        self.api_key = (api_key or env("FIRMWARE_AUDIT_LLM_API_KEY")
                        or env("DEEPSEEK_API_KEY") or env("LLM_API_KEY") or "")
        self.base_url = (base_url or env("FIRMWARE_AUDIT_LLM_BASE_URL")
                         or env("LLM_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.model = (model or env("FIRMWARE_AUDIT_LLM_MODEL")
                      or env("LLM_MODEL") or DEFAULT_MODEL)
        self.stream = stream  # 预留:MVP 固定非流式,True 会报错(未实现)
        self._total_usage = {"prompt_tokens": 0, "completion_tokens": 0}

    @property
    def available(self) -> bool:
        return bool(self.api_key)

    def chat(self, messages: list[dict], temperature: float = 0.2,
             max_tokens: int | None = None) -> tuple[str, dict]:
        """返回 (content, usage)。usage 为本次用量;累计量见 total_usage。

        max_tokens 缺省取环境变量 LLM_MAX_TOKENS 或 DEFAULT_MAX_TOKENS(16384)。
        重试语义:可重试错误按 RETRY_INTERVALS 间隔自动重试至多 MAX_RETRIES 次
        (每次打点日志);不可重试 HTTP 状态码立即抛;全部失败抛 LLMError。
        """
        if max_tokens is None:
            try:
                max_tokens = int(os.environ.get("LLM_MAX_TOKENS") or DEFAULT_MAX_TOKENS)
            except ValueError:
                max_tokens = DEFAULT_MAX_TOKENS
        if not self.available:
            raise LLMError(
                "无 API key(环境变量 FIRMWARE_AUDIT_LLM_API_KEY / "
                "DEEPSEEK_API_KEY / LLM_API_KEY 均未设置;密钥在 .env 里的需先导出,"
                "见 run_step5 报错中的指引)")
        if self.stream:
            raise LLMError("stream=True 未实现(MVP 非流式,见 agents.md)")

        payload = json.dumps({
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        last_err = ""
        for attempt in range(1 + MAX_RETRIES):
            try:
                with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                    body = json.loads(resp.read().decode("utf-8"))
                msg = (body.get("choices") or [{}])[0].get("message", {})
                # 推理模型(deepseek-v4-flash/mimo 实测):思考在 reasoning_content,
                # 正文在 content;思考与正文共享 max_tokens,思考耗尽时 content 为空
                # (瞬时,可重试)。**只把正文当回复**:思考是模型内部草稿,不参与
                # ReAct 协议解析(防"草稿 Action"被当成真实调用执行)、不进回喂
                # 上下文;思考单独随 usage.reasoning_content 返回,由调用方在
                # transcript 留档审计(content 为空即视为空回复,走重试)。
                reasoning = msg.get("reasoning_content") or ""
                content = (msg.get("content") or "").strip()
                if not content:
                    raise _RetryableError(
                        f"空回复(思考耗尽或响应异常,reasoning {len(reasoning)} 字符): "
                        f"{json.dumps(body, ensure_ascii=False)[:300]}")
                usage = dict(body.get("usage") or {})
                if reasoning:
                    usage["reasoning_content"] = reasoning
                for k in self._total_usage:
                    self._total_usage[k] += usage.get(k, 0)
                if attempt > 0:
                    _log_retry(f"第 {attempt + 1} 次尝试成功(经 {attempt} 次重试)", "")
                return content, usage
            except urllib.error.HTTPError as e:
                detail = f"HTTP {e.code}: {e.read().decode('utf-8', 'replace')[:200]}"
                if e.code in NON_RETRYABLE_HTTP:
                    _log_retry("不可重试错误,立即终止", detail)
                    raise LLMError(f"不可重试错误(不重试): {detail}")
                last_err = detail
            except _RetryableError as e:
                last_err = str(e)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
                last_err = f"{type(e).__name__}: {e}"
            except json.JSONDecodeError as e:
                last_err = f"响应非 JSON: {e}"
            if attempt < MAX_RETRIES:
                wait = RETRY_INTERVALS[attempt]
                _log_retry(
                    f"第 {attempt + 1} 次尝试失败(将进行第 {attempt + 1}/{MAX_RETRIES} 次重试)",
                    last_err, wait)
                time.sleep(wait)
        _log_retry(f"全部 {MAX_RETRIES} 次重试失败(共 {1 + MAX_RETRIES} 次尝试)", last_err)
        raise LLMError(f"首次尝试 + {MAX_RETRIES} 次重试全部失败: {last_err}")

    @property
    def total_usage(self) -> dict:
        return dict(self._total_usage)
