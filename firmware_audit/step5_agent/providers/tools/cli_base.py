"""CLI 类工具公共逻辑:沙箱容器挂载与路径换算。

沙箱镜像 firm_audit/sandbox:latest 的 ENTRYPOINT 是 Ghidra analyzeHeadless,
调任何非 Ghidra CLI 必须覆盖 entrypoint(rules.md 已知坑)。
"""
from __future__ import annotations

from pathlib import Path

from ....docker.docker_utils import run_docker
from .base import ToolContext

SANDBOX_IMAGE = "firm_audit/sandbox:latest"
EXTRACTED_MOUNT = "/work/extracted"


def extracted_root(ctx: ToolContext) -> Path:
    return ctx.process_dir / "extracted"


def container_path(ctx: ToolContext, file_ref: str) -> str | None:
    """file_ref → /work/extracted/<rel>;含路径穿越(../)或越界时返回 None。"""
    root = extracted_root(ctx).resolve()
    ref = file_ref.strip().replace("\\", "/")
    p = (root / ref).resolve()
    if p != root and root not in p.parents:
        return None
    return f"{EXTRACTED_MOUNT}/{ref}"


def run_in_sandbox(args: list[str], entrypoint: str, ctx: ToolContext,
                   timeout: int = 120, extra_mounts: list[tuple[Path, str]] | None = None):
    """在沙箱容器执行命令。Agent 工具安全基线(2026-08-18 落实):

    - extracted/ **只读**挂载(:ro)——工具只消费解包树,签名扫描/复核脚本
      一律不许写回固件目录
    - **断网**(--network none)——checksec/r2/semgrep(本地规则)/gitleaks/
      binwalk 签名/sandbox_verify 均不需外网;cve_bin_tool_scan 的 CVE 库走
      .cve_cache 卷 + --offline,也不依赖运行时网络
    - extra_mounts 保持 rw(cve_bin_tool_scan 的 CVE 缓存卷要写锁文件;
      sandbox_verify 的脚本临时目录本就宿主侧写好)

    挂载纪律(2026-08-19):所有宿主路径先 .resolve() 绝对化——
    相对路径(如 target/1/process/extracted)传入 docker -v 会被 Docker
    当命名卷,卷名禁含 "/" → daemon 报 create <path>: invalid
    characters → 容器未起即 exit 125。此层兜底覆盖全部 CLI 工具。
    """
    mounts: list[tuple[Path, str, str]] = [
        (extracted_root(ctx).resolve(), EXTRACTED_MOUNT, "ro"),
    ] + [(Path(h).resolve(), c, "rw") for h, c in (extra_mounts or [])]
    return run_docker(SANDBOX_IMAGE, args, mounts=mounts,
                      entrypoint=entrypoint, timeout=timeout, network="none")
