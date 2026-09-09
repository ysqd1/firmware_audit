"""CLI 类工具公共逻辑:沙箱容器挂载与路径换算。

沙箱镜像 firm_audit/sandbox:latest 的 ENTRYPOINT 是 Ghidra analyzeHeadless,
调任何非 Ghidra CLI 必须覆盖 entrypoint(rules.md 已知坑)。
"""
from __future__ import annotations

from pathlib import Path

from ....docker.docker_utils import run_docker
from ....file_rules import get_search_exclude_dirs
from .base import ToolContext, resolve_within

SANDBOX_IMAGE = "firm_audit/sandbox:latest"
EXTRACTED_MOUNT = "/work/extracted"
ANALYSIS_MOUNT = "/work/analysis"


def sdk_exclude_flags(container_root: str = EXTRACTED_MOUNT) -> list[str]:
    """把搜索过滤名单转成工具的排除参数(当前按 semgrep --exclude 形态)。

    名单来自 file_rules(profile SEARCH_EXCLUDE_DIRS,2026-08-30 收敛)。
    container_root 用实际扫描根(EXTRACTED_MOUNT);
    以绝对容器路径排除,避免误伤同名顶层(如 etc/lib)。仅对支持 --exclude 的工具使用。
    """
    flags: list[str] = []
    root = container_root.rstrip("/")
    for pre in get_search_exclude_dirs():
        flags += ["--exclude", f"{root}/{pre.rstrip('/')}"]
    return flags


def extracted_root(ctx: ToolContext) -> Path:
    return ctx.process_dir / "extracted"


def analysis_root(ctx: ToolContext) -> Path:
    return ctx.process_dir / "analysis"


def container_path(ctx: ToolContext, file_ref: str,
                   base: str = "extracted") -> str | None:
    """file_ref → /work/<base>/<rel>;含路径穿越(../)或越界时返回 None。

    base="extracted"(默认,ELF/脚本取证)或 "analysis"(边车产物)。
    工具路径宽容(ADR-0008,票02):带 base 同名前缀的引用
    ("extracted/unitree/x"——findings.file 的统一口径)剥前缀后解析,
    与 resolve_analysis_file 的宽容同源;extracted 树内真实同名顶层目录
    会被遮蔽,接受该代价。
    注:file_ref 为 None 时保持原契约(.strip() 抛 AttributeError,由 execute
    统一捕获为"失败不崩"),不静默转成空串去碰 Docker。空串按越界拒绝
    (C4 起,原行为是放行到挂载根——那本是不该暴露的边界,故收敛为拒绝)。
    """
    root = (ctx.process_dir / base).resolve()
    ref = file_ref.strip().replace("\\", "/").removeprefix(base + "/")
    if resolve_within(root, ref) is None:
        return None
    return f"/work/{base}/{ref}"


def extracted_tool_path(scan_root: str, reported: str, *,
                        mount: str = EXTRACTED_MOUNT,
                        prefix: str = "extracted") -> str:
    """容器报告的固件路径 → 工具路径(ADR-0008)。

    semgrep/gitleaks 的 JSON 报告路径是容器挂载根相对口径(逻辑路径),
    Agent 会把它照抄进 findings.file/survey.high_risk_areas——必须在工具
    输出层换算,让"原文照抄"红线天然产出工具路径。reported 两种形态:
    相对扫描根("unitree/x.py")、带挂载前缀("/work/extracted/unitree/x.py");
    scan_root 是本工具的 path 参数(相对挂载根,"."=根)。
    prefix="analysis" + mount=ANALYSIS_MOUNT 用于 semgrep 的 analysis 树扫描。
    """
    r = (reported or "").replace("\\", "/").strip()
    if r.startswith(mount + "/"):
        r = r[len(mount) + 1:]
    elif r == mount:
        r = ""
    root = (scan_root or "").replace("\\", "/").strip().strip("/")
    root = root.removeprefix(prefix + "/")   # analysis 树的显式引用可能带前缀
    pre = "" if root in ("", ".") else f"{root}/"
    if pre and r.startswith(pre):   # 绝对形态剥挂载后已含扫描根,防重复
        pre = ""
    return f"{prefix}/{pre}{r}"


def run_in_sandbox(args: list[str], entrypoint: str, ctx: ToolContext,
                   timeout: int = 120,
                   extra_mounts: list[tuple] | None = None):
    """在沙箱容器执行命令。Agent 工具安全基线(2026-08-18 落实):

    - extracted/ **只读**挂载(:ro)——工具只消费解包树,签名扫描/复核脚本
      一律不许写回固件目录
    - **断网**(--network none)——checksec/r2/semgrep(本地规则)/gitleaks/
      binwalk 签名/sandbox_verify 均不需外网;cve_bin_tool_scan 的 CVE 库走
      .cve_cache 卷 + --offline,也不依赖运行时网络
    - extra_mounts 保持 rw(cve_bin_tool_scan 的 CVE 缓存卷要写锁文件;
      sandbox_verify 的脚本临时目录本就宿主侧写好);三元组
      (host, container, mode) 可显式给 ro(如 semgrep 的 analysis 只读挂载)

    挂载纪律(2026-08-19):所有宿主路径先 .resolve() 绝对化——
    相对路径(如 target/1/process/extracted)传入 docker -v 会被 Docker
    当命名卷,卷名禁含 "/" → daemon 报 create <path>: invalid
    characters → 容器未起即 exit 125。此层兜底覆盖全部 CLI 工具。
    """
    mounts: list[tuple[Path, str, str]] = [
        (extracted_root(ctx).resolve(), EXTRACTED_MOUNT, "ro"),
    ]
    for m in (extra_mounts or []):
        if len(m) == 3:
            h, c, mode = m
            mounts.append((Path(h).resolve(), c, mode))
        else:
            h, c = m
            mounts.append((Path(h).resolve(), c, "rw"))
    return run_docker(SANDBOX_IMAGE, args, mounts=mounts,
                      entrypoint=entrypoint, timeout=timeout, network="none")
