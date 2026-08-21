"""web_search:检索固件组件的公开漏洞/公告/exploit(无 key 免费后端)。

用于 analysis 阶段确认某个组件版本是否真有公开漏洞:
  - 厂商安全公告(mirror code.cc/lf.colliders)
  - exploit-db / GitHub issue
  - 通用关键词检索(keyword + 组件版本)

后端:DuckDuckGo HTML(无需 key)。Docker 容器外是宿主网络,直接 urllib 请求;
失败降级返回错误不崩(报告标注未检索到)。

注意:这是宿主侧 API 工具,不依赖 sandbox 镜像。
"""
from __future__ import annotations

import re
import urllib.parse
import urllib.request

from .base import AgentTool, ToolResult
from .cve_lookup import _throttle  # 复用 NVD 的无 key 节流,避免请求过快被限

DDG_URL = "https://html.duckduckgo.com/html/"
_MAX_RESULTS = 8


class WebSearchTool(AgentTool):
    name = "web_search"
    description = ("检索固件组件/版本的公开漏洞信息(厂商公告/exploit/GitHub Issue)。"
                   "用于确认某组件版本是否确有公开可利用漏洞,补 cve_lookup 覆盖不足。")
    params_doc = 'Action Input: {"query": "<关键词,如 fastjson 1.2.24 CVE>"}'

    def _run(self, query: str = "") -> ToolResult:
        if not query or not query.strip():
            return ToolResult(ok=False, text="", error="需要 query")
        _throttle()  # 复用无 key 节流(5 req/30s)
        qs = urllib.parse.urlencode({"q": query})
        req = urllib.request.Request(
            f"{DDG_URL}?{qs}",
            headers={"User-Agent": "firmware_audit/0.1"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                html = resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ToolResult(ok=False, text="", error=f"web_search 网络失败: {query}")

        results = _parse_ddg(html)[:_MAX_RESULTS]
        if not results:
            return ToolResult(ok=True, text=f"web_search: 未检索到公开结果: {query}", data=[])
        lines = [f"web_search『{query}』命中 {len(results)} 条:"]
        for i, r in enumerate(results, 1):
            lines.append(f"{i}. {r['title']}")
            lines.append(f"   URL: {r['url']}")
            if r.get("snippet"):
                lines.append(f"   {r['snippet'][:150]}")
        return ToolResult(ok=True, text="\n".join(lines), data=results)


def _parse_ddg(html: str) -> list[dict]:
    """DuckDuckGo HTML 结果解析:按结果块切分提取 title/url/snippet。"""
    results: list[dict] = []
    # 结果块: <a class="result__a" href="...">title</a> ... <a class="result__snippet">..</a>
    for block in re.split(r'<div class="result', html)[1:]:
        m = re.search(r'<a[^>]*class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', block, re.S)
        if not m:
            continue
        url, title = m.group(1), re.sub(r"<[^>]+>", "", m.group(2)).strip()
        if "uddg=" in url:  # 重定向包装,解出真实 URL
            parsed = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
            real = parsed.get("uddg", [""])[0]
            if real:
                url = real
        snippet = ""
        m2 = re.search(r'class="result__snippet"[^>]*>(.*?)</a>', block, re.S)
        if m2:
            snippet = re.sub(r"<[^>]+>", "", m2.group(1)).strip()
        if url and title:
            results.append({"title": title, "url": url, "snippet": snippet})
    return results