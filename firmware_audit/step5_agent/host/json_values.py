"""Strict JSON-value validation shared by Host protocol and Evidence boundaries."""
from __future__ import annotations

import json
import math
from typing import Any


class JsonValueError(ValueError):
    """A Python value cannot be represented unchanged by the JSON protocol."""


def _validate_json_value(value: Any, path: str, ancestors: set[int]) -> None:
    value_type = type(value)
    if value is None or value_type in (str, bool, int):
        return
    if value_type is float:
        if not math.isfinite(value):
            raise JsonValueError(f"{path} 必须是有限 JSON number")
        return
    if value_type is list:
        identity = id(value)
        if identity in ancestors:
            raise JsonValueError(f"{path} 不得包含循环引用")
        ancestors.add(identity)
        try:
            for index, item in enumerate(value):
                _validate_json_value(item, f"{path}[{index}]", ancestors)
        finally:
            ancestors.remove(identity)
        return
    # Session parser uses a dict subclass to retain duplicate-key diagnostics.
    # Its JSON members remain valid; tuples and non-string keys still fail.
    if isinstance(value, dict):
        identity = id(value)
        if identity in ancestors:
            raise JsonValueError(f"{path} 不得包含循环引用")
        ancestors.add(identity)
        try:
            for key, item in value.items():
                if type(key) is not str:
                    raise JsonValueError(
                        f"{path} 的 object key 必须是 string，实际为 {type(key).__name__}"
                    )
                _validate_json_value(item, f"{path}.{key}", ancestors)
        finally:
            ancestors.remove(identity)
        return
    raise JsonValueError(
        f"{path} 必须是标准 JSON 值，实际为 {type(value).__name__}"
    )


def clone_json_value(value: Any, label: str) -> Any:
    """Reject lossy Python-to-JSON coercions, then return a detached JSON value."""
    try:
        _validate_json_value(value, "$", set())
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        return json.loads(encoded)
    except (JsonValueError, RecursionError, TypeError, ValueError) as exc:
        raise JsonValueError(f"{label} 必须是标准 JSON 值: {exc}") from exc
