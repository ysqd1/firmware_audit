"""cve_lookup:NVD REST API 2.0 查 CVE 详情(CVSS/描述)。

无 key 限 5 req/30s → 进程内节流;查询结果落盘缓存(同参同果,幂等)。
urllib 标准库,失败降级返回错误不崩(报告标注该 CVE 未复核)。
"""
from __future__ import annotations

import hashlib
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .base import AgentTool, ToolResult

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RATE_WINDOW = 30.0  # 秒
RATE_LIMIT = 5      # 无 key 限额(有 NVD_API_KEY 时禁用节流)

# 进程级节流状态(所有 CveLookupTool 实例共享)
_call_times: list[float] = []


class CveLookupTool(AgentTool):
    name = "cve_lookup"
    description = "查 CVE 详情(CVSS 评分/描述/NVD 数据)。cve_bin_tool_scan 命中的 CVE 用它取严重度与描述,补齐证据链。"
    params = {
        "cve_id": {"type": "str", "default": "", "desc": "CVE 编号(如 CVE-2024-1234)"},
        "keyword": {"type": "str", "default": "", "desc": "关键词搜索(与 cve_id 二选一,cve_id 优先)"},
    }

    def _run(self, cve_id: str = "", keyword: str = "") -> ToolResult:
        if not cve_id and not keyword:
            return ToolResult(ok=False, text="", error="需要 cve_id 或 keyword 之一")
        params: dict[str, str] = {}
        if cve_id:
            cid = cve_id.strip().upper()
            if not cid.startswith("CVE-"):
                return ToolResult(ok=False, text="", error=f"cve_id 形如 CVE-2024-1234, got: {cve_id}")
            params["cveId"] = cid
        else:
            params["keywordSearch"] = keyword.strip()

        cache = self._cache_path(params)
        if cache.exists():
            # 缓存快照即结果(幂等:同参同果)
            data = json.loads(cache.read_text(encoding="utf-8"))
            return ToolResult(ok=True, text=_format(data), data=data, elapsed=0.0)

        raw = self._fetch_with_throttle(params)
        if raw is None:
            return ToolResult(
                ok=False, text="",
                error=f"NVD 查询失败(网络/限速): {cve_id or keyword}",
            )
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(raw, ensure_ascii=False), encoding="utf-8")
        return ToolResult(ok=True, text=_format(raw), data=raw)

    # ---- 基础设施 ----

    def _cache_path(self, params: dict) -> Path:
        qs = urllib.parse.urlencode(params)
        h = hashlib.md5(qs.encode()).hexdigest()[:16]
        return self.ctx.process_dir / ".cve_cache" / f"nvd_{h}.json"

    def _fetch_with_throttle(self, params: dict) -> dict | None:
        import os
        api_key = os.environ.get("NVD_API_KEY", "")
        if not api_key:
            _throttle()
        qs = urllib.parse.urlencode(params)
        req = urllib.request.Request(
            f"{NVD_BASE}?{qs}",
            headers={
                "User-Agent": "firmware_audit/0.1",
                **({"apiKey": api_key} if api_key else {}),
            },
        )
        for attempt in (1, 2):
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError):
                if attempt == 2:
                    return None
                time.sleep(2)
        return None


def _throttle() -> None:
    """无 key 节流:窗口内调用次数超限则 sleep 到窗口滑动。"""
    now = time.time()
    while _call_times and now - _call_times[0] > RATE_WINDOW:
        _call_times.pop(0)
    if len(_call_times) >= RATE_LIMIT:
        sleep_for = RATE_WINDOW - (now - _call_times[0]) + 0.5
        time.sleep(max(sleep_for, 0))
    _call_times.append(time.time())


def _format(raw: dict) -> str:
    total = raw.get("totalResults", 0)
    vulns = raw.get("vulnerabilities", [])
    if total == 0 or not vulns:
        return "NVD 无记录(可能为拒绝号/新号未收录)"
    out = [f"NVD 命中 {total} 条:"]
    for v in vulns[:10]:
        cve = v.get("cve", {})
        cid = cve.get("id", "?")
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break
        score = "?"
        for metric in cve.get("metrics", {}).values():
            items = metric if isinstance(metric, list) else []
            if items:
                score = items[0].get("cvssData", {}).get("baseScore", "?")
                break
        out.append(f"{cid}  CVSS={score}  {desc[:150]}")
    return "\n".join(out)
