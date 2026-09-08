"""cve_bin_tool_scan:沙箱容器内 cve-bin-tool,按产品版本特征匹配已知 CVE。

CVE 数据库不烘镜像:宿主缓存目录 volume 挂载进容器复用,
首跑下载 NVD 数据(无 key 限速,可能数分钟),超时降级报错不崩。
退出码约定(cve-bin-tool v3):0=无发现, 1=有 CVE 命中, ≥2=错误。

缓存目录(2026-09-08 工单 03):默认 target 各自的 process/.cve_cache(与
历史行为逐字节一致);env FIRMWARE_AUDIT_CVE_CACHE_DIR 指到共享目录
(如 firmware_audit/.cve_cache)即可预热一次跨 target 复用——替代
Windows junction 方案(WSL 迁移后 junction 已不可用),预热命令见 README。

挂载路径修正(2026-08-22 实测):cve-bin-tool 3.4 的缓存根是 $HOME/.cache/cve-bin-tool/
(CVEDB.CACHEDIR = ~/.cache/cve-bin-tool),不是老约定的 ~/.cache/cvedb。
-> 挂整块宿主缓存目录到容器 $HOME/.cache(即 /home/sandbox/.cache),
让工具自己管理子目录;若仍挂到 ~/.cache/cvedb,后者不存在导致库永远找不到(码 40)。
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .base import AgentTool, ToolResult
from .cli_base import container_path, run_in_sandbox

CVE_CACHE_MOUNT = "/home/sandbox/.cache"

CVE_CACHE_ENV = "FIRMWARE_AUDIT_CVE_CACHE_DIR"


def resolve_cve_cache_dir(process_dir: Path) -> Path:
    """CVE 缓存宿主目录:env FIRMWARE_AUDIT_CVE_CACHE_DIR 覆盖,缺省 per-target。

    缺省/空白 = process_dir/.cve_cache(与既有行为逐字节一致);env 非空时
    用指定目录(~ 展开),预热一次跨 target 复用。
    """
    raw = os.environ.get(CVE_CACHE_ENV, "").strip()
    if raw:
        return Path(raw).expanduser()
    return process_dir / ".cve_cache"


class CveBinToolScanTool(AgentTool):
    name = "cve_bin_tool_scan"
    description = "对单个 ELF 或目录跑已知漏洞扫描(cve-bin-tool,按产品名+版本特征匹配 400+ 检查器)。首跑要下载 CVE 库,较慢。"
    params = {
        "file_ref": {"type": "str", "required": True,
                     "desc": "相对 extracted 根的路径,支持单文件或目录"},
    }

    def _run(self, file_ref: str) -> ToolResult:
        cpath = container_path(self.ctx, file_ref)
        if cpath is None:
            return ToolResult(ok=False, text="", error=f"非法路径: {file_ref}")
        cache = resolve_cve_cache_dir(self.ctx.process_dir)
        cache.mkdir(parents=True, exist_ok=True)
        # 参数依据(cve-bin-tool 3.4 实测):
        #   --disable-data-source PURL2CPE  首跑必崩(no such table: purl2cpe)
        #   --disable-version-check  自检新版本要访问 PyPI,容器无外网时
        #     version.py 里 None.splitlines() 直接崩(AttributeError)
        #   --offline  跳过 NVD 增量更新(库由 .cve_cache 预热维护),
        #     省掉每次扫描数分钟的 NVD 限速等待
        #   -o -       3.4 的 --format json 默认把 JSON 写到文件而非 stdout
        #     (output.cve-bin-tool.<ts>.json,在 CWD);工具从 stdout 解析,
        #     必须加 -o - 让 JSON 打到 stdout(2026-08-22 实测只跑通全部 CVE 库)
        rc, out, err = run_in_sandbox(
            ["--quiet", "--format", "json", "-o", "-", "--offline",
             "--disable-version-check", "--disable-data-source", "PURL2CPE", cpath],
            "cve-bin-tool", self.ctx, timeout=900,
            extra_mounts=[(cache, CVE_CACHE_MOUNT)],
        )
        if rc >= 2 or rc == 124:
            return ToolResult(
                ok=False, text="",
                error=f"cve-bin-tool 失败(码 {rc}): {(err or out).strip()[:300]}",
            )
        data = _extract_json(out)
        if data is None:
            # -o - 下 0 命中时 stdout 为空(实测 2026-08-22),属合法"无 CVE",
            # 而非错误;只有输出非空却解析失败才算真正问题。
            stripped = out.strip()
            if not stripped:
                return ToolResult(ok=True, text=f"{file_ref}: 无已知 CVE 命中", data=[])
            return ToolResult(ok=False, text="", error=f"输出无 JSON: {out[:200]}")
        hits = _flatten(data)
        if not hits:
            return ToolResult(ok=True, text=f"{file_ref}: 无已知 CVE 命中", data=[])
        lines = [
            f"{h.get('product', '?')} {h.get('version', '?')} → {h.get('cve_number', '?')}"
            f" [{h.get('severity', '?')}]"
            for h in hits
        ]
        return ToolResult(
            ok=True,
            text=f"{file_ref} 命中 {len(hits)} 条 CVE:\n" + "\n".join(lines),
            data=hits,
        )


def _extract_json(out: str):
    """cve-bin-tool --format json 把 JSON 打在 stdout,可能混有日志;找最长的 JSON 块。"""
    best = None
    buf = []
    depth = 0
    for line in out.splitlines():
        s = line.strip()
        if depth == 0 and not (s.startswith("{") or s.startswith("[")):
            continue
        buf.append(line)
        depth += s.count("{") + s.count("[") - s.count("}") - s.count("]")
        if depth <= 0:
            try:
                obj = json.loads("\n".join(buf))
                text = "\n".join(buf)
                if best is None or len(text) > len(best[1]):
                    best = (obj, text)
            except json.JSONDecodeError:
                pass
            buf, depth = [], 0
    return best[0] if best else None


def _flatten(data) -> list[dict]:
    """cve-bin-tool 各版本 JSON 结构不一(list 或 {results: [...]});
    统一压成扁平 hit 列表,字段宽容取。"""
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("results") or data.get("hits") or []
    else:
        return []
    flat = []
    for it in items:
        if isinstance(it, dict):
            flat.append(it)
    return flat
