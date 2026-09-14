"""ghidra_decompile:Step5 唯一 Ghidra 入口——单 ELF 按需反编译(ADR-0010 票03)。

两级分析漏斗的升级层:r2 廉价层信息不够时才调用(分钟级容器)。幂等缓存 +
sha256 内容去重 + 边车三件套(.c/.strings.json/.imports.json):
  - 缓存命中:目标 analysis/<rel>.c 存在且头部 extractinfo_version 匹配、
    decompile_success>0 → 零容器直接返回(老工作区边车天然是缓存,零迁移);
  - 版本失效/空壳 → 重跑覆盖;
  - 同内容不同路径 → sha256 查 dedup.json 索引,命中把已有边车硬链接到新路径
    (os.link 失败降级拷贝),下游指针逻辑零改动;
  - 非 ELF/越界 → 即时引导性拒绝(r2_base.elf_guard,不付 900s 容器);
  - Observation 轻量:只回指针 + 函数数,不回 C 内容(读代码走
    find_decompiled_function)。

容器现制沿用原 Step4 批量反编译(ExtractInfo.py 零改动、extractinfo_version
不涨):ghidra 镜像、-analysisTimeoutPerFile 300、docker timeout=900、宿主
uid:gid、HOME=/tmp、一次性临时工程。本工具是 Step5 唯一写审计工件的工具
(cve_bin_tool 的缓存卷与引擎留痕除外),写路径经 resolve_within 收口在
analysis/ 之下。
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import time
from pathlib import Path

from .base import AgentTool, ToolResult, resolve_within, validate_params
from .cli_base import analysis_root
from .ghidra_cache import publish_receipt, sha256_of, validated_manifest
from .r2_base import elf_guard, extracted_host_path
from ....docker.docker_utils import run_docker  # 模块属性:测试假件补丁点

# 与原 Step4/ExtractInfo.py 一致(脚本零改动、版本号不涨:老工件天然是缓存)
GHIDRA_IMAGE = "ghidra"
_EXTRACTINFO_VERSION = 2

# 容器内固定路径(与 Step4 相同)
_CONT_INPUT = "/work/input"
_CONT_OUTPUT = "/work/output"
_CONT_PROJECT = "/work/project"

# 边车三件套:JSON 产物名 → 边车后缀(functions/meta/symbols 无工具消费者,不拷)
_SIDECAR_JSONS = ("imports.json", "strings.json")

# 宿主 uid:gid:容器以此身份跑,挂载写出的产物归宿主用户(WSL 下容器默认
# root,产物 root:root 宿主读不回;非 POSIX 平台无 getuid → None 不注入)
_HOST_UID_GID = f"{os.getuid()}:{os.getgid()}" if hasattr(os, "getuid") else None

# dedup 索引(analysis/ 下,sha256 → 首个反编译的 rel)
_DEDUP_INDEX = "dedup.json"


def _header_field(c_path: Path, pattern: str) -> int:
    """读 .c 头部前几行的 machine-readable 字段(版本/成功数);失败返回 0。

    为什么读头部而非只看文件大小: Ghidra 无条件写头部,全部函数反编译失败
    时 decompiled.c 也有字节,按大小判断恒真,会把空壳当有效缓存永久跳过。
    """
    try:
        with c_path.open("r", encoding="utf-8", errors="ignore") as f:
            for _ in range(8):
                line = f.readline()
                m = re.search(pattern, line)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 0


def _cache_valid(c_path: Path) -> bool:
    """缓存有效性:.c 存在且版本匹配且真实反编译成功数>0(空壳重跑)。"""
    if not c_path.is_file():
        return False
    if _header_field(c_path, rf"extractinfo_version:\s*(\d+)") != _EXTRACTINFO_VERSION:
        return False
    return _header_field(c_path, r"decompile_success:\s*(\d+)") > 0


def _load_dedup(analysis_dir: Path) -> dict:
    p = analysis_dir / _DEDUP_INDEX
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_dedup(analysis_dir: Path, index: dict) -> None:
    p = analysis_dir / _DEDUP_INDEX
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")


def _materialize(src: Path, dst: Path) -> None:
    """把已有边车物化到新路径:硬链接优先(零拷贝),失败降级拷贝。"""
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def _replace_artifact(src: Path, dst: Path) -> None:
    """Replace a directory entry, never truncate another cache's shared inode."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".ghidra-", dir=dst.parent)
    os.close(descriptor)
    try:
        shutil.copy2(src, temporary)
        os.replace(temporary, dst)
    finally:
        Path(temporary).unlink(missing_ok=True)


class GhidraDecompileTool(AgentTool):
    name = "ghidra_decompile"
    description = ("反编译单个 ELF 为 C 代码并落盘边车(分钟级容器,按需升级调用:先 r2 层,"
                   "信息不够才用本工具)。幂等缓存:已反编译立即返回;同内容文件自动复用"
                   "已有边车(sha256)。只回产物指针与函数数;读函数用 find_decompiled_function。")
    params = {
        "file_ref": {"type": "str", "required": True, "desc": "相对 extracted 根的 ELF 路径"},
    }

    def recover_cached_result(self, *, file_ref: str) -> ToolResult | None:
        """Host recovery probe: accept only complete cache bound to this input."""
        if elf_guard(self.ctx, file_ref):
            return None
        host = extracted_host_path(self.ctx, file_ref)
        rel = file_ref.strip().replace("\\", "/").removeprefix("extracted/")
        analysis_dir = analysis_root(self.ctx)
        c_path = resolve_within(analysis_dir, f"{rel}.c")
        if c_path is None or not _cache_valid(c_path):
            return None
        manifest = validated_manifest(analysis_dir, rel, sha256_of(host))
        if manifest is None:
            return None
        n = _header_field(c_path, r"decompile_success:\s*(\d+)")
        text = (f"已反编译(完整缓存与 digest 校验通过): analysis/{rel}.c({n} 个函数);"
                "读函数用 find_decompiled_function。")
        return ToolResult(ok=True, text=text, raw=text, data={
            "file": f"analysis/{rel}.c", "functions": n, "cache": "validated",
            "artifacts": manifest["artifacts"],
        })

    def _run(self, file_ref: str) -> ToolResult:
        return self._decompile(file_ref, allow_legacy_cache=True)

    def execute_after_interruption(self, **arguments) -> ToolResult:
        """Host-only retry after a failed cache probe; never re-enter weak caches.

        This control is not an LLM parameter. Keep normal execute semantics for
        validation, failure Observation, timing and raw text preservation.
        """
        start = time.time()
        try:
            checked, error = validate_params(self.params, arguments)
            if error:
                result = ToolResult(ok=False, text="", error=error)
            else:
                result = self._decompile(**checked, allow_legacy_cache=False)
        except Exception as exc:
            result = ToolResult(ok=False, text="", error=f"{type(exc).__name__}: {exc}；请改用 r2 层取证")
        return self._finalize(result, start)

    def _decompile(self, file_ref: str, *, allow_legacy_cache: bool) -> ToolResult:
        guard = elf_guard(self.ctx, file_ref)
        if guard:
            return ToolResult(ok=False, text="", error=guard)
        host = extracted_host_path(self.ctx, file_ref)
        rel = str(file_ref).strip().replace("\\", "/").removeprefix("extracted/")
        analysis_dir = analysis_root(self.ctx)
        # 写路径防御(纵深):guard 已拒 ..,此处再收口"产物必落 analysis/ 之下"
        c_path = resolve_within(analysis_dir, f"{rel}.c")
        if c_path is None:
            return ToolResult(ok=False, text="", error=f"非法路径: {file_ref}")

        # 1) 幂等缓存:版本匹配且非空壳 → 零容器
        if allow_legacy_cache and _cache_valid(c_path):
            n = _header_field(c_path, r"decompile_success:\s*(\d+)")
            return ToolResult(
                ok=True,
                text=(f"已反编译(缓存命中): analysis/{rel}.c({n} 个函数);"
                      "边车 .strings.json/.imports.json 同目录。"
                      "读函数用 find_decompiled_function。"),
                data={"file": f"analysis/{rel}.c", "functions": n, "cache": "hit"},
            )

        # 2) 内容去重:sha256 查索引,命中复用已有边车(硬链接,降级拷贝)
        sha = sha256_of(host)
        dedup = _load_dedup(analysis_dir)
        first_rel = dedup.get(sha)
        if allow_legacy_cache and first_rel and first_rel != rel:
            # 反查值与自写 key 同样收口:索引损坏/被手改时不把 analysis/ 之外
            # 的宿主文件物化进边车位
            first_c = resolve_within(analysis_dir, f"{first_rel}.c")
            if first_c is not None and _cache_valid(first_c):
                _materialize(first_c, c_path)
                for jname in _SIDECAR_JSONS:
                    src = analysis_dir / f"{first_rel}.{jname}"
                    if src.is_file():
                        _materialize(src, analysis_dir / f"{rel}.{jname}")
                n = _header_field(c_path, r"decompile_success:\s*(\d+)")
                return ToolResult(
                    ok=True,
                    text=(f"反编译完成(内容与 {first_rel} 相同,sha256 比对,已复用其边车): "
                          f"analysis/{rel}.c({n} 个函数)。读函数用 find_decompiled_function。"),
                    data={"file": f"analysis/{rel}.c", "functions": n,
                          "cache": "dedup", "dedup_from": first_rel},
                )

        # 3) 容器反编译(ghidra 镜像,Step4 现制)
        receipt_path = resolve_within(analysis_dir, f"{rel}.cache.json")
        if receipt_path is None:
            return ToolResult(ok=False, text="", error="非法缓存路径；请检查 analysis 目录")
        # A failed/incomplete replacement must not inherit the prior certificate.
        receipt_path.unlink(missing_ok=True)
        ok, detail = self._run_ghidra(host, rel, analysis_dir)
        if not ok:
            return ToolResult(
                ok=False, text="",
                error=(f"ghidra_decompile 失败: {detail}。"
                       "可改用 r2 层(r2_list_functions/r2_disassemble_function/"
                       "r2_xref_query)继续取证;稍后重试也可能成功(分析超时零产出)。"),
            )
        n = _header_field(c_path, r"decompile_success:\s*(\d+)")
        # 成功才登记 dedup 索引(sha → 首个反编译路径)
        publish_receipt(analysis_dir, rel, sha)
        dedup[sha] = rel
        _save_dedup(analysis_dir, dedup)
        return ToolResult(
            ok=True,
            text=(f"反编译完成: analysis/{rel}.c({n} 个函数);"
                  "边车 .strings.json/.imports.json 同目录。"
                  "读函数用 find_decompiled_function,读边车用 strings_query/imports_query。"),
            data={"file": f"analysis/{rel}.c", "functions": n, "cache": "miss"},
        )

    def _run_ghidra(self, host: Path, rel: str, analysis_dir: Path) -> tuple[bool, str]:
        """一次容器调用产出三件套;返回 (成功, 失败详情)。"""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            project_dir = tmpdir / "project"
            project_dir.mkdir()
            ghidra_output = tmpdir / "output"
            ghidra_output.mkdir()

            args = [
                _CONT_PROJECT, "audit",
                "-import", f"{_CONT_INPUT}/{host.name}",
                # 分析阶段超时:Ghidra 原生截断,超时中断分析、保留已完成
                # analyzer 结果、继续 postScript(Step4 实测 300s 足够小库)
                "-analysisTimeoutPerFile", "300",
                "-postScript", "ExtractInfo.py", _CONT_OUTPUT,
                "-deleteProject",
                "-overwrite",
                "-scriptPath", "/opt/ghidra/Ghidra/Features/Decompiler/ghidra_scripts",
            ]
            mounts = [
                # 输入只读:被分析对象是攻击者可控固件,容器不许写回解包树
                # (Step5 工具安全基线;Step4 时代的 rw 豁免不继承)
                (host.parent, _CONT_INPUT, "ro"),
                (ghidra_output, _CONT_OUTPUT),
                (project_dir, _CONT_PROJECT),
            ]
            # docker timeout 900:分析 300s 截断后 postScript 反编译仍需时间
            # (Step4 实测依据);HOME=/tmp 供非 root 身份建 ~/.ghidra 设置目录;
            # 断网(--network none)对齐 Step5 全部工具的安全基线
            rc, _stdout, stderr = run_docker(
                GHIDRA_IMAGE, args, mounts=mounts, timeout=900,
                user=_HOST_UID_GID, network="none",
                env={"HOME": "/tmp"} if _HOST_UID_GID else None,
            )
            if rc != 0:
                return False, f"容器退出码 {rc}: {(stderr or '')[:300]}"

            decompiled_src = ghidra_output / "decompiled.c"
            if not decompiled_src.is_file() or decompiled_src.stat().st_size == 0:
                return False, "容器无 decompiled.c 产出"
            # Validate this generation before copying; old sidecars at the target
            # must never fill holes in an interrupted or incomplete generation.
            for jname in _SIDECAR_JSONS:
                src = ghidra_output / jname
                try:
                    value = json.loads(src.read_text(encoding="utf-8"))
                    expected = list if jname == "imports.json" else dict
                    if not isinstance(value, expected):
                        raise ValueError("JSON 结构不匹配")
                except (OSError, ValueError) as exc:
                    return False, f"容器边车 {jname} 缺失或损坏: {exc}"
            dest = analysis_dir / f"{rel}.c"
            dest.parent.mkdir(parents=True, exist_ok=True)
            _replace_artifact(decompiled_src, dest)
            if not _cache_valid(dest):
                return False, "反编译无有效产出(全部函数失败或旧版本空壳)"

            for jname in _SIDECAR_JSONS:
                src = ghidra_output / jname
                if src.is_file() and src.stat().st_size > 0:
                    side = analysis_dir / f"{rel}.{jname}"
                    side.parent.mkdir(parents=True, exist_ok=True)
                    _replace_artifact(src, side)
            return True, ""
