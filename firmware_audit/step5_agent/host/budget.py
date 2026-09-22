"""Run 级预算台账、耗尽守卫与四层配置解析(ADR-0012 L71-75)。

预算按真实消耗计量:每次完成的模型请求(含协议重生成与恢复重请求)计入
llm_calls 并累计 token,回复被应用才计 validated_rounds;每次真实工具执行
计入 tool_attempts,逻辑调用另计。active time 只累计活动执行段,停机与等待
恢复的间隔不计——崩溃遗留的悬挂段在加载时按"已保存活跃量 + 丢弃尾部"收口。

配置解析优先级固定:显式参数 > 本机环境 > 版本化 profile > 代码默认值;
最终生效值与键级来源写入 ``config.json`` 快照,结果可按实际预算解释。
``RunBudget`` 把台账与上限打包成三角色 runner 共用的守卫 seam;耗尽抛
``BudgetExhaustedError``(runner 内现场已由既有 checkpoint 保存,当前调查
不落终态;调用方按票 21 收束——剩余 queued 标 not_started,进行中调查以
unresolved/budget_exhausted 终结,随后同一 run 内正常封存)。
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from .store import StoreError, atomic_json

BUDGET_SCHEMA_VERSION = 1
CONFIG_SCHEMA_VERSION = 1

# 会话内执行次数上限的配置键(票 17):DEFAULT_BUDGET_CONFIG / ENV_KEYS /
# 消费点(host.tooling 下发给 qemu_execute)共用同一出处。
QEMU_MAX_SESSION_EXECUTIONS_KEY = "qemu_max_session_executions"

# 初始单案例上限(ADR-0012 L71:实现与前三例试运行的初始值,不是成绩)。
# qemu_max_session_executions(票 17):单会话执行次数上限,临时默认 4,
# 最终默认由票 19 真实样本校准定稿;生效值与来源随 config.json 快照冻结。
DEFAULT_BUDGET_CONFIG: dict[str, float] = {
    "recon_max_rounds": 30,
    "analysis_max_rounds": 30,
    "verification_max_rounds": 15,
    "max_llm_calls": 400,
    "max_tool_attempts": 320,
    "max_active_seconds": 7200.0,
    "max_candidates": 8,
    QEMU_MAX_SESSION_EXECUTIONS_KEY: 4,
}

# 本机环境覆盖层的键名单一出处;角色轮次旋钮沿用各 runner 既同名变量
# (STEP5_*_MAX_ITERS,票 14 后单一消费方为 Host),max_candidates 沿用票 07
# 的 STEP5_CANDIDATE_SLOTS——同一旋钮不造第二个名字。
ENV_KEYS: dict[str, str] = {
    "recon_max_rounds": "STEP5_RECON_MAX_ITERS",
    "analysis_max_rounds": "STEP5_ANALYSIS_MAX_ITERS",
    "verification_max_rounds": "STEP5_VERIFICATION_MAX_ITERS",
    "max_llm_calls": "STEP5_MAX_LLM_CALLS",
    "max_tool_attempts": "STEP5_MAX_TOOL_ATTEMPTS",
    "max_active_seconds": "STEP5_MAX_ACTIVE_SECONDS",
    "max_candidates": "STEP5_CANDIDATE_SLOTS",
    QEMU_MAX_SESSION_EXECUTIONS_KEY: "STEP5_QEMU_MAX_SESSION_EXECUTIONS",
}

_INT_KEYS = frozenset({
    "recon_max_rounds", "analysis_max_rounds", "verification_max_rounds",
    "max_llm_calls", "max_tool_attempts", "max_candidates",
    QEMU_MAX_SESSION_EXECUTIONS_KEY,
})


class ConfigError(ValueError):
    """配置层结构失约;调用方或 profile 损坏应当显式失败,不静默回落。"""


class BudgetExhaustedError(RuntimeError):
    """运行总预算耗尽;现场已保存,当前调查不落终态,供调用方收束队列。"""


def _validate_value(key: str, value: Any, origin: str) -> int | float:
    if key in _INT_KEYS:
        if type(value) is not int or value < 1:
            raise ConfigError(f"{origin} 配置 {key} 必须是 >=1 的整数,实际为 {value!r}")
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(
            f"{origin} 配置 {key} 必须是正数,实际为 {value!r}")
    return float(value)


def _env_value(raw: str | None, key: str) -> int | float | None:
    """环境层缺失/非法(含越界)视为缺省,不惊扰本机实验。

    与各角色 resolver 的"缺失/非法回落默认"同口径;数值越界(如负上限)
    同属非法,静默落到下一层而不是带病生效。
    """
    if raw is None or not str(raw).strip():
        return None
    text = str(raw).strip()
    try:
        value: int | float = int(text) if key in _INT_KEYS else float(text)
    except ValueError:
        return None
    try:
        return _validate_value(key, value, "环境变量")
    except ConfigError:
        return None


def resolve_effective_config(
    *,
    explicit: Mapping[str, Any] | None = None,
    env: Mapping[str, str] | None = None,
    profile: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """按显式参数 > 本机环境 > 版本化 profile > 代码默认值逐键解析。

    环境层非法值静默视为缺省;显式参数与 profile 的非法值是调用方错误,
    抛 ConfigError。返回 ``{"resolved": {...}, "sources": {key: 层名}}``。
    """
    sources: dict[str, str] = {}
    resolved: dict[str, int | float] = {}
    for key, default in DEFAULT_BUDGET_CONFIG.items():
        if explicit is not None and key in explicit:
            resolved[key] = _validate_value(key, explicit[key], "显式参数")
            sources[key] = "explicit"
            continue
        if env is not None:
            from_env = _env_value(env.get(ENV_KEYS[key]), key)
            if from_env is not None:
                resolved[key] = from_env
                sources[key] = "environment"
                continue
        if profile is not None and key in profile:
            resolved[key] = _validate_value(key, profile[key], "profile")
            sources[key] = "profile"
            continue
        resolved[key] = default
        sources[key] = "default"
    return {"resolved": resolved, "sources": sources}


def config_snapshot_path(run_dir: Path) -> Path:
    return Path(run_dir) / "config.json"


def persist_config_snapshot(run_dir: Path, config: dict[str, Any]) -> Path:
    """把生效配置与键级来源原子落盘;结果按实际预算可解释的运行工件。

    ``prompts`` 段可选(票 24):新世代随快照冻结三角色系统提示词的内容
    指纹,提示版本可追溯;恢复路径读回冻结快照,不重写。
    """
    if "resolved" not in config or "sources" not in config:
        raise ConfigError("配置快照必须来自 resolve_effective_config 的返回值")
    path = config_snapshot_path(run_dir)
    document: dict[str, Any] = {
        "schema_version": CONFIG_SCHEMA_VERSION,
        "resolved": dict(config["resolved"]),
        "sources": dict(config["sources"]),
    }
    prompts = config.get("prompts")
    if prompts is not None:
        document["prompts"] = dict(prompts)
    atomic_json(path, document)
    return path


def load_config_snapshot(run_dir: Path) -> dict[str, Any] | None:
    path = config_snapshot_path(run_dir)
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise StoreError(f"配置快照损坏；请检查原运行目录: {exc}") from exc
    prompts = payload.get("prompts") if isinstance(payload, dict) else None
    if prompts is not None and (
            not isinstance(prompts, dict)
            or not all(isinstance(key, str) and isinstance(value, str)
                       for key, value in prompts.items())):
        raise StoreError("配置快照结构或版本损坏；请检查原运行目录")
    if (not isinstance(payload, dict)
            or payload.get("schema_version") != CONFIG_SCHEMA_VERSION
            or not isinstance(payload.get("resolved"), dict)
            or not isinstance(payload.get("sources"), dict)):
        raise StoreError("配置快照结构或版本损坏；请检查原运行目录")
    return payload


class BudgetLedger:
    """追加式资源台账:真实请求/生效轮/工具执行与活动时长,原子持久化。"""

    def __init__(self, path: Path, *, clock: Callable[[], float] = time.monotonic):
        self.path = Path(path)
        self.clock = clock
        self.llm_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.validated_rounds = 0
        self.tool_attempts = 0
        self.logical_tool_calls = 0
        self._active_base = 0.0
        self._segment_start: float | None = None
        if self.path.exists():
            self._load()

    # ---- 恢复 ----

    def _load(self) -> None:
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise StoreError(f"预算台账损坏；请检查原运行目录: {exc}") from exc
        if (not isinstance(payload, dict)
                or payload.get("schema_version") != BUDGET_SCHEMA_VERSION
                or not all(type(payload.get(key)) is int and payload[key] >= 0
                           for key in ("llm_calls", "prompt_tokens",
                                       "completion_tokens", "validated_rounds",
                                       "tool_attempts", "logical_tool_calls"))
                or isinstance(payload.get("active_seconds"), bool)
                or not isinstance(payload.get("active_seconds"), (int, float))
                or payload["active_seconds"] < 0):
            raise StoreError("预算台账结构或版本损坏；请检查原运行目录")
        # 崩溃遗留的悬挂活动段直接弃置:停机与等待恢复的间隔不得计入
        # active time,保存点之后的尾部活动量是可接受的有界少计。
        self.llm_calls = payload["llm_calls"]
        self.prompt_tokens = payload["prompt_tokens"]
        self.completion_tokens = payload["completion_tokens"]
        self.validated_rounds = payload["validated_rounds"]
        self.tool_attempts = payload["tool_attempts"]
        self.logical_tool_calls = payload["logical_tool_calls"]
        self._active_base = float(payload["active_seconds"])
        self._segment_start = None

    def _save(self) -> None:
        atomic_json(self.path, {
            "schema_version": BUDGET_SCHEMA_VERSION,
            "llm_calls": self.llm_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "validated_rounds": self.validated_rounds,
            "tool_attempts": self.tool_attempts,
            "logical_tool_calls": self.logical_tool_calls,
            "active_seconds": self.active_seconds,
        })

    # ---- 活动时长 ----

    @property
    def is_active(self) -> bool:
        """是否处于开放活动段(驱动层去重/评分请求自管活动段用)。"""
        return self._segment_start is not None

    @property
    def active_seconds(self) -> float:
        open_delta = (self.clock() - self._segment_start
                      if self._segment_start is not None else 0.0)
        return self._active_base + open_delta

    def start_active(self) -> None:
        """进入活动执行段;停机/等待恢复的间隔天然落在段外。"""
        if self._segment_start is None:
            self._segment_start = self.clock()
            self._save()

    def stop_active(self) -> None:
        if self._segment_start is not None:
            self._active_base += self.clock() - self._segment_start
            self._segment_start = None
            self._save()

    # ---- 记账 ----

    def record_llm_call(self, usage: Mapping[str, Any] | None = None) -> None:
        """一次完成的模型请求(重生成/恢复重请求同计);失败请求无回复不计。"""
        self.llm_calls += 1
        if isinstance(usage, Mapping):
            prompt = usage.get("prompt_tokens")
            completion = usage.get("completion_tokens")
            if type(prompt) is int and prompt > 0:
                self.prompt_tokens += prompt
            if type(completion) is int and completion > 0:
                self.completion_tokens += completion
        self._save()

    def record_validated_round(self) -> None:
        """回复被应用才计生效轮;无效重生成只进 llm_calls。"""
        self.validated_rounds += 1
        self._save()

    def record_logical_tool_call(self) -> None:
        """逻辑调用获准(获得 Evidence 身份)即计;与真实执行成本分开。"""
        self.logical_tool_calls += 1
        self._save()

    def record_tool_execution(self) -> None:
        """每次真实执行(含同 call_id 重放 attempt)都计,重试成本可见。"""
        self.tool_attempts += 1
        self._save()

    def snapshot(self) -> dict[str, Any]:
        return {
            "llm_calls": self.llm_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "validated_rounds": self.validated_rounds,
            "tool_attempts": self.tool_attempts,
            "logical_tool_calls": self.logical_tool_calls,
            "active_seconds": self.active_seconds,
        }


class RunBudget:
    """台账 + 上限的运行级守卫;三角色 runner 在发请求/执行工具前过闸。"""

    def __init__(self, ledger: BudgetLedger, resolved: Mapping[str, Any]):
        self.ledger = ledger
        self.resolved = dict(resolved)

    @classmethod
    def load(
        cls,
        run_dir: Path,
        *,
        clock: Callable[[], float] = time.monotonic,
        config: Mapping[str, Any] | None = None,
        persist: bool = True,
    ) -> "RunBudget":
        """默认按环境层解析并落配置快照;注入 config 时跳过解析。"""
        run_dir = Path(run_dir)
        if config is None:
            document = resolve_effective_config(env=os.environ)
            if persist:
                persist_config_snapshot(run_dir, document)
            resolved = document["resolved"]
        else:
            # 注入的是已解析映射(测试/接线 seam):键值仍须过同一校验,
            # 不允许带病上限(如负数)直达守卫。
            resolved = {
                key: (_validate_value(key, value, "RunBudget 配置")
                      if key in DEFAULT_BUDGET_CONFIG else value)
                for key, value in dict(config).items()
            }
        return cls(BudgetLedger(run_dir / "budget.json", clock=clock), resolved)

    # ---- 守卫 ----

    def _require_active(self, action: str) -> None:
        limit = self.resolved["max_active_seconds"]
        if self.ledger.active_seconds >= limit:
            raise BudgetExhaustedError(
                f"运行总预算耗尽:active_seconds 已达 {self.ledger.active_seconds:.3f}s"
                f"(上限 {limit}s);{action}被拒绝,现场已保存")

    def require_llm(self) -> None:
        limit = self.resolved["max_llm_calls"]
        if self.ledger.llm_calls >= limit:
            raise BudgetExhaustedError(
                f"运行总预算耗尽:llm_calls 已达 {self.ledger.llm_calls}"
                f"(上限 {limit});模型请求被拒,现场已保存")
        self._require_active("模型请求")

    def require_tool(self) -> None:
        limit = self.resolved["max_tool_attempts"]
        if self.ledger.tool_attempts >= limit:
            raise BudgetExhaustedError(
                f"运行总预算耗尽:tool_attempts 已达 {self.ledger.tool_attempts}"
                f"(上限 {limit});工具执行被拒,现场已保存")
        self._require_active("工具执行")

    # ---- 记账委托 ----

    def record_llm_call(self, usage: Mapping[str, Any] | None = None) -> None:
        self.ledger.record_llm_call(usage)

    def record_validated_round(self) -> None:
        self.ledger.record_validated_round()

    def record_logical_tool_call(self) -> None:
        self.ledger.record_logical_tool_call()

    def record_tool_execution(self) -> None:
        self.ledger.record_tool_execution()

    def start_active(self) -> None:
        self.ledger.start_active()

    def stop_active(self) -> None:
        self.ledger.stop_active()
