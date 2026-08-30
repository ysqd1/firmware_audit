"""search_code:按内容关键词/正则混合检索(边车索引 + extracted 文本 grep)。

参考 deepaudit 的 FileSearchTool(file_tool.py:keyword/file_pattern/directory/
max_results + 越界防护),按 firmware_audit 特性**混合设计**:

- 边车索引路: 搜索 process/analysis/ 下 Step4 预产边车——*.strings.json
  (ELF 字符串值,带 address/refs)、*.imports.json(导入符号)、*.text.json
  (Step4 文本扫描命中)。快、零容器、带地址锚点。
- 文本 grep 路: 对 extracted/ 文本文件(白名单扩展名)按行匹配;二进制嗅探
  跳过、SDK/系统库目录排除、大文件跳过。

命中即 Observation 证据(与"证据可溯源"纪律兼容);路径统一为相对 process/
的 posix,可直接 read_file 回查。失败不崩(逐文件 try/except)。
"""
from __future__ import annotations

import json
import re
from fnmatch import fnmatch
from pathlib import Path

from ....file_rules import is_search_excluded
from .base import AgentTool, ToolResult

MAX_RESULTS_DEFAULT = 50
MAX_RESULTS_CAP = 100
TEXT_MAX_BYTES = 512 * 1024          # 文本 grep 单文件上限(防大 log 拖死)
BINARY_SNIFF = 8192                  # 二进制嗅探读取字节数

# 边车索引路:目录扫描后缀(按"小文件先"排,无命中场景先止损)
_SIDECARS = (".imports.json", ".text.json", ".strings.json")

# 文本 grep 路:白名单扩展名(避免命中二进制/未知格式)
_TEXT_EXTS = {".py", ".sh", ".conf", ".cfg", ".ini", ".json", ".c", ".h",
              ".lua", ".js", ".php", ".xml", ".yaml", ".yml", ".txt",
              ".profile", ".env", ".service", ".rules", ".toml", ".sql"}


def _path_excluded(rel: str) -> bool:
    """SDK/系统库路径前缀排除(与 list_files 口径一致)。

    rel 是相对 process/ 的路径(默认 grep scope=extracted/ 时带 extracted/
    前缀),排除集条目不带该前缀——同时匹配两种形态(剥前缀后再判)。
    名单来自 file_rules(profile SEARCH_EXCLUDE_DIRS,2026-08-30 收敛)。
    """
    r = rel.rstrip("/")
    if is_search_excluded(r):
        return True
    r2 = r.removeprefix("extracted/")
    return is_search_excluded(r2)


def _is_text(path: Path) -> bool:
    """二进制嗅探:前 8KB 含 NUL 视为二进制,跳过。"""
    try:
        with path.open("rb") as f:
            return b"\x00" not in f.read(BINARY_SNIFF)
    except OSError:
        return False


class SearchCodeTool(AgentTool):
    name = "search_code"
    description = ("按内容搜索关键词/正则,命中即 Observation 证据。双路混合:"
                   "①ELF 字符串/导入/文本扫描边车(process/analysis/*.json);"
                   "②extracted/ 文本文件按行 grep(自动跳过二进制与 SDK 目录)。"
                   "返回 文件:锚点 命中行,可直接 read_file 回查。")
    params_doc = ('{"keyword": "password", "file_pattern": "*.py", '
                  '"directory": "extracted/unitree", "is_regex": false, '
                  '"max_results": 50} —— keyword 必填;其余可选(默认搜全 extracted)')

    def _run(self, keyword: str = "", file_pattern: str = "",
             directory: str = "", is_regex: bool = False,
             max_results: int = MAX_RESULTS_DEFAULT) -> ToolResult:
        kw = (keyword or "").strip()
        if not kw:
            return ToolResult(ok=False, text="", error="keyword 不能为空")
        try:
            n = max(1, min(int(max_results), MAX_RESULTS_CAP))
        except (TypeError, ValueError):
            n = MAX_RESULTS_DEFAULT
        try:
            pat = re.compile(kw if is_regex else re.escape(kw),
                             0 if is_regex else re.IGNORECASE)
        except re.error as e:
            return ToolResult(ok=False, text="", error=f"无效的搜索模式: {e}")

        root = self.ctx.process_dir.resolve()
        matches: list[dict] = []            # {path, anchor, text}
        searched = {"sidecar": 0, "text": 0}

        def push(rel: str, anchor: str, content: str) -> bool:
            """收录一条命中;到达上限返回 True(停止后续搜索)。"""
            matches.append({"path": rel, "anchor": anchor,
                            "text": (content or "").strip()[:160]})
            return len(matches) >= n

        # ---- ① 边车索引路(总是扫 analysis/,快且幂等) ----
        analysis_dir = root / "analysis"
        if analysis_dir.is_dir():
            for suffix in _SIDECARS:
                # 按文件大小升序:小边车(imports/text)先扫,命中/无命中更快止损;
                # 大字符串表放最后,避免无命中时先读超大文件
                files = sorted(analysis_dir.rglob(f"*{suffix}"),
                               key=lambda p: p.stat().st_size)
                for p in files:
                    searched["sidecar"] += 1
                    if self._match_sidecar(p, suffix, pat, root, push):
                        break
                if len(matches) >= n:
                    break

        # ---- ② 文本 grep 路(directory 收窄;默认 extracted/) ----
        if len(matches) < n:
            scope = self._resolve_scope(root, directory)
            if scope is None:
                # 默认 extracted/ 缺失 → 静默跳过(边车命中仍返回);
                # 显式 directory 越界/不存在 → 明确报错,防静默空结果
                if directory and not matches:
                    return ToolResult(
                        ok=False, text="",
                        error=f"目录越界或不存在: {directory}")
            else:
                self._grep_text(scope, file_pattern, pat, root, push, searched)

        if not matches:
            return ToolResult(
                ok=True, text=(f"未找到匹配 '{keyword}'"
                               f"(搜索 边车 {searched['sidecar']} + "
                               f"文本 {searched['text']} 文件)"), data=[])
        lines = [f"## search_code: '{keyword}' 命中 {len(matches)} 条"]
        lines += [f"- {m['path']}:{m['anchor']}  {m['text']}" for m in matches]
        lines.append(f"(搜索 边车 {searched['sidecar']} + 文本 "
                     f"{searched['text']} 文件;达 {n} 条截断,可用 "
                     f"directory/file_pattern 收窄或调大 max_results)")
        return ToolResult(ok=True, text="\n".join(lines), data={
            "count": len(matches), "matches": matches[:MAX_RESULTS_CAP]})

    # ---- 边车索引匹配 ----

    def _match_sidecar(self, p: Path, suffix: str, pat, root: Path,
                       push) -> bool:
        """匹配一个边车 JSON;返回 True 表示已达上限应停止。"""
        try:
            obj = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        rel = p.relative_to(root).as_posix()
        if suffix == ".strings.json":
            for s in ((obj.get("strings") or []) if isinstance(obj, dict) else []):
                # .strtab/* 段是符号表噪音(如 ".strtab::00000b82 system.c"),滤掉
                addr = str(s.get("address", "") or "")
                if addr.startswith(".strtab"):
                    continue
                val = str(s.get("value", ""))
                if not pat.search(val):
                    continue
                refs = ", ".join(str(x) for x in (s.get("refs") or [])[:3])
                if push(rel, addr or "?",
                        f"\"{val}\"" + (f" refs=[{refs}]" if refs else "")):
                    return True
        elif suffix == ".imports.json":
            for i in obj if isinstance(obj, list) else []:
                name = i.get("name", "")
                if not pat.search(str(name)):
                    continue
                sites = ", ".join(str(x) for x in (i.get("call_sites") or [])[:3])
                if push(rel, i.get("address", "?"),
                        name + (f" call_sites=[{sites}]" if sites else "")):
                    return True
        elif suffix == ".text.json":
            for f in ((obj.get("findings") or []) if isinstance(obj, dict) else []):
                m = str(f.get("match", ""))
                if not pat.search(m):
                    continue
                if push(rel, f.get("line", "?"), m):
                    return True
        return False

    # ---- 文本 grep ----

    def _resolve_scope(self, root: Path, directory: str) -> Path | None:
        """grep 范围:目录默认 extracted/;directory 指定则收窄/扩到 process/ 下。"""
        ref = (directory or "extracted").replace("\\", "/").strip("/")
        target = (root / ref).resolve() if ref else root
        if target != root and root not in target.parents:
            return None
        return target if target.is_dir() else None

    def _grep_text(self, scope: Path, file_pattern: str, pat, root: Path,
                   push, searched: dict) -> None:
        """遍历文本文件按行 grep;命中调 push。"""
        for p in scope.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            # SDK/系统库路径前缀排除(与 list_files 口径一致;含 extracted/ 前缀形态)
            if _path_excluded(rel):
                continue
            if file_pattern and not fnmatch(p.name, file_pattern):
                continue
            if p.suffix.lower() not in _TEXT_EXTS:
                continue
            try:
                if p.stat().st_size > TEXT_MAX_BYTES or not _is_text(p):
                    continue
            except OSError:
                continue
            searched["text"] += 1
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for i, line in enumerate(lines, 1):
                if not pat.search(line):
                    continue
                if push(rel, str(i), line.strip() or "(空行)"):
                    return