"""Step4 - 反编译/提取。

ELF → Ghidra Headless 提取程序信息(Docker 镜像)
文本/脚本/源码 → 标记可直接审计
证书 → 提取元信息(是否私钥/算法/长度)
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ..docker.docker_utils import docker_available, run_docker
from ..file_rules import is_downgrade_dir, logical_path
from ..models import FileInfo
from .triage import triage_opaque, sniff_firmware_kind

# Ghidra 镜像
GHIDRA_IMAGE = "ghidra"

# 容器内固定路径
_CONT_INPUT = "/work/input"
_CONT_OUTPUT = "/work/output"
_CONT_PROJECT = "/work/project"


def _decompile_success_count(decompiled_c: Path) -> int:
    """读 decompiled.c 头部真实反编译成功数。

    新格式头:  `// decompile_success: <N>`(machine-readable)
    旧格式头:  `// total functions: X, success: N, failed: Y`(兼容改动前产物)
    读取失败返回 0。为什么读头部而非只看文件大小: Ghidra 无条件写头部,
    全部函数反编译失败时 decompiled.c 也有字节,按大小判断恒真,会把空壳
    标成成功并永久跳过重试。
    """
    import re as _re
    try:
        with decompiled_c.open("r", encoding="utf-8", errors="ignore") as f:
            for _ in range(8):  # 头部前几行内即可
                line = f.readline()
                m = _re.search(r"decompile_success:\s*(\d+)", line)
                if m:
                    return int(m.group(1))
                m = _re.search(r"success:\s*(\d+)", line)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 0


def _extractinfo_version(decompiled_c: Path) -> int:
    """读 decompiled.c 头部 extractinfo_version 标记(产物格式版本)。

    缺失/解析失败返回 0。旧版 ExtractInfo.py 产物无此标记 → 0 ≠ _EXTRACTINFO_VERSION,
    使 _is_decompiled_ok 返回 False,自动失效重跑。
    """
    import re as _re
    try:
        with decompiled_c.open("r", encoding="utf-8", errors="ignore") as f:
            for _ in range(8):  # 头部前几行内即可
                line = f.readline()
                m = _re.search(r"extractinfo_version:\s*(\d+)", line)
                if m:
                    return int(m.group(1))
    except OSError:
        pass
    return 0


def _is_decompiled_ok(fi: FileInfo, analysis_dir: Path) -> bool:
    """判定 ELF 是否已真正反编译成功(可续传跳过)。

    需同时满足: 反编译成功数 > 0、functions.json 存在非空、且产物版本等于
    _EXTRACTINFO_VERSION(旧版产物自动失效重跑)。
    为什么还要查 functions.json: 续传只认 decompiled.c 会漏掉"反编译成功但
    functions.json 缺失/损坏"的旧产物,加此校验能发现并重跑(验收3)。

    .c 与 JSON 同处 analysis_dir(合并目录): .c 用 `<rel>.c`,JSON 用 `<rel>.functions.json`。
    """
    c_path = analysis_dir / f"{fi.rel_path}.c"
    if not c_path.exists():
        return False
    if _decompile_success_count(c_path) <= 0:
        return False
    if _extractinfo_version(c_path) != _EXTRACTINFO_VERSION:
        return False
    funcs_path = analysis_dir / f"{fi.rel_path}.functions.json"
    return not (not funcs_path.exists() or funcs_path.stat().st_size <= 0)


# analysis/ 下产物按"逻辑 rel_path 末尾后缀"反查归属。后缀互斥,一个文件只命中一种。
# (后缀, 分类标签) 用于分类统计删除数。
_ANALYSIS_PRODUCT_SUFFIXES = (
    (".functions.json", "elf"),  # ELF 产物
    (".imports.json", "elf"),    # ELF 产物
    (".symbols.json", "elf"),    # ELF 产物
    (".strings.json", "elf"),    # ELF 字符串表产物
    (".text.json", "text"),      # 文本扫描产物
    (".crypto.json", "crypto"),  # 证书解析产物
)


def _cleanup_orphans(
    fileinfos: list[FileInfo],
    analysis_dir: Path,
) -> int:
    """按本轮名单裁剪 analysis/(.c 与 JSON 同处),清除陈旧孤儿产物。

    背景: analysis/ 会积累"以前某轮反编译、但本轮过滤规则已排除的 ELF"的陈旧产物。
    例如本轮加了 BUILD_ARTIFACT_PATTERNS 的 "/build/" 规则后,路径含 /build/ 的 CMake
    探测程序、*.cc.o 等 ELF 被 Step2 过滤、不进本轮流水线,但更早某轮的
    analysis/xxx.c 与 analysis/xxx.functions.json 仍留盘,导致目录口径与 fileinfo
    不一致。每次调整过滤规则都会再堆积,须手动清;这里每次跑自动清理。

    规则:
      - 裁剪白名单 = 本轮 fileinfos 中全部记录的 rel_path(所有类型,不能只 ELF!
        否则会把文本扫描产物 *.text.json 和证书产物 *.crypto.json 误删)。
      - analysis/ 下 *.c 视为 ELF 反编译产物,去掉末尾 ".c" 得候选 rel。
      - analysis/ 下依次尝试剥离 _ANALYSIS_PRODUCT_SUFFIXES,命中者得候选 rel。
      - 候选 rel 不在白名单 → 删除该文件。
      - 白名单内的文件一律保留,即使上次反编译失败、产物不完整——保留让断点续传
        决定是否重跑,不在这里删。
      - 只删目录内的文件,用 Path.resolve() 校验仍在目录内,防路径穿越。

    Returns: 删除的文件数。
    """
    whitelist = {fi.rel_path for fi in fileinfos}
    # 分类删除计数:反编译(.c) / ELF 产物(functions/imports/symbols) /
    # 文本扫描(.text.json) / 证书解析(.crypto.json)
    deleted_by = {"decompiled": 0, "elf": 0, "text": 0, "crypto": 0}
    # 单一 analysis_dir,同时匹配 .c 与各 JSON 后缀
    suffixes = ((".c", "decompiled"),) + _ANALYSIS_PRODUCT_SUFFIXES
    base_dir = analysis_dir
    if not base_dir.is_dir():
        return 0
    base = base_dir.resolve()
    for f in base_dir.rglob("*"):
        if not f.is_file():
            continue
        rel = str(f.relative_to(base_dir)).replace("\\", "/")
        cand = None
        category = None
        for suf, cat in suffixes:
            if rel.endswith(suf):
                cand = rel[: -len(suf)]
                category = cat
                break
        if cand is None or cand in whitelist:
            continue
        # 安全性:确认仍在目标目录内,防路径穿越后误删
        try:
            f.resolve().relative_to(base)
        except ValueError:
            continue
        try:
            f.unlink()
            deleted_by[category] += 1
        except OSError:
            pass
    total = sum(deleted_by.values())
    print("[Step4] 清理孤儿产物: 删除 "
          f"{total} 个(反编译 {deleted_by['decompiled']}, ELF 产物 {deleted_by['elf']}, "
          f"文本 {deleted_by['text']}, 证书 {deleted_by['crypto']})")
    return total


def _mark_decompiled_ok(fi: FileInfo, analysis_dir: Path) -> bool:
    """ELF 已真正反编译成功(_is_decompiled_ok 为真)时,按续传成功填充字段。

    复用续传的填充逻辑,避免重复造轮子。供续传循环与 --max-elf 截断部分共用:
    截断的 ELF 虽不实际跑 Ghidra,但磁盘有完整产物时不得在 fileinfo 里被降级为
    pending(否则 save_fileinfos 写回会把已 ok 的覆盖成 pending、路径清空)。

    Returns: 是否命中(有完整产物)。
    """
    if _is_decompiled_ok(fi, analysis_dir):
        fi.ghidra_status = "ok"
        fi.decompiled_path = str(analysis_dir / f"{fi.rel_path}.c")
        fi.analysis_path = str(analysis_dir)
        return True
    return False


def decompile(
    fileinfos: list[FileInfo],
    workspace: Path,
    max_elf: int | None = None,
    max_workers: int = 4,
) -> list[FileInfo]:
    """对 FileInfo 列表做反编译/提取,原地填充字段。

    Args:
        fileinfos: Step3 产出的 FileInfo 列表
        workspace: 审计工作区根目录(target/<N>/)
        max_elf: 只处理前 N 个 ELF(None=全部)。固件含大量 ELF 时控制总时长。
        max_workers: Ghidra 并行容器数。每个 ELF 起独立容器 + 独立 project 目录,
                     天然线程安全;_run_ghidra 内部用临时目录,无共享状态。

    除文本/crypto/ELF 反编译外,还会对 ELF 的 Ghidra strings.json 做字符串表扫描
    (读硬编码 URL/密码/私钥并带出引用函数)。Ghidra 不可用时 strings.json 缺失,自然跳过。

    Returns:
        填充后的 fileinfos(同一列表,原地修改)
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    # 合并目录:analysis/ 同时存放 .c 与各 JSON(不再分 decompiled/)
    analysis_dir = workspace / "analysis"
    analysis_dir.mkdir(parents=True, exist_ok=True)

    # 按本轮名单裁剪产物目录,清除"以前某轮反编译、本轮已排除的 ELF"的陈旧孤儿
    # 产物(如加了 /build/ 规则后,路径含 /build/ 的 ELF 不进本轮)。白名单用完整
    # fileinfos(所有类型),这样 --max-elf 只影响实际反编译,不影响裁剪——后段 ELF
    # 的产物仍保留,下次全量可续传复用,不误删。
    _cleanup_orphans(fileinfos, analysis_dir)

    ghidra_ok = docker_available(GHIDRA_IMAGE)

    # 按类型分流
    elf_fis = [fi for fi in fileinfos if fi.type in ("elf_exec", "elf_lib")]
    crypto_fis = [fi for fi in fileinfos if fi.type.startswith("crypto_") or fi.type == "cert"]
    text_fis = [fi for fi in fileinfos if fi.type in ("script", "source", "config", "text")]

    # --- 文本类:扫描硬编码敏感串(串行,纯 Python,很快) ---
    text_scanned = 0
    text_with_findings = 0
    for fi in text_fis:
        _scan_text(fi, analysis_dir)
        text_scanned += 1
        if fi.findings:
            text_with_findings += 1

    # --- Crypto:dispatch(串行,纯解析,快) ---
    crypto_count = 0
    crypto_counts: dict[str, int] = {}
    for fi in crypto_fis:
        crypto_count += 1
        if fi.type == "cert":
            label = "cert(legacy)"
            _dispatch_crypto(fi, analysis_dir, legacy=True)
        else:
            label = fi.type
            _dispatch_crypto(fi, analysis_dir)
        crypto_counts[label] = crypto_counts.get(label, 0) + 1

    # --- ELF:可选上限 + 断点续传 + 并行 Ghidra ---
    elf_total = len(elf_fis)
    if max_elf is not None and max_elf >= 0:
        elf_todo_all = elf_fis[:max_elf]
        elf_capped = elf_total - len(elf_todo_all)
    else:
        elf_todo_all = list(elf_fis)
        elf_capped = 0

    # --max-elf 截断的 ELF 不实际跑 Ghidra(语义不变),但磁盘已有完整产物时,
    # 不得在 fileinfo 里被降级为 pending。复用续传填充逻辑,保持 ok + 路径非空,
    # 否则结尾 save_fileinfos 写回会把原本已 ok 的 ELF 覆盖回 pending、路径清空
    # (实测 --max-elf 0 后 29 个 ELF 全部变 pending)。
    if elf_capped:
        for fi in elf_fis[max_elf:]:
            _mark_decompiled_ok(fi, analysis_dir)

    # 断点续传:已真正反编译成功(decompile_success>0 且 functions.json 非空)的跳过。
    # 不能只看 decompiled.c 非空——Ghidra 无条件写头部,全部反编译失败的空壳也有字节。
    # analysis_path 必须在此填充:否则上次跑完 .c 但 JSON 没拷完(或 ExtractInfo 中途崩)
    # 时,续传既不重跑、analysis 也空着,Step5 拿不到 functions/imports/symbols.json。
    # _is_decompiled_ok 已同时校验 functions.json 存在非空,缺失即不放行、加入重跑队列。
    elf_ok = 0
    elf_failed = 0
    elf_skipped = 0
    elf_resumed = 0
    elf_todo: list[FileInfo] = []
    for fi in elf_todo_all:
        if _mark_decompiled_ok(fi, analysis_dir):
            elf_resumed += 1
        else:
            elf_todo.append(fi)

    if elf_todo and not ghidra_ok:
        for fi in elf_todo:
            fi.ghidra_status = "skipped"
        elf_skipped = len(elf_todo)
        print("[Step4] 提示: Ghidra 镜像未建,待处理 ELF 全部跳过,文本/crypto 审计仍可进行")
    elif elf_todo:
        workers = max(1, min(max_workers, len(elf_todo)))
        print(f"[Step4] Ghidra 并行: 待处理 {len(elf_todo)} ELF, workers={workers}")
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {
                ex.submit(_run_ghidra, fi, analysis_dir): fi
                for fi in elf_todo
            }
            for fut in as_completed(futures):
                fi = futures[fut]
                try:
                    success = fut.result()
                except Exception as e:
                    print(f"[Step4] Ghidra 异常: {fi.rel_path}: {e}")
                    success = False
                if success:
                    elf_ok += 1
                else:
                    elf_failed += 1

    # --- ELF 字符串表扫描 ---
    # 需在 Ghidra 并行块之后:刷新 Ghidra 刚产出的 strings.json,扫描硬编码敏感串
    # (读 URL/密码/私钥并带出引用函数)。续传跳过的 ELF 沿用磁盘旧 strings.json。
    # Ghidra 未跑/strings.json 缺失(如镜像未建)时自然跳过,不崩。
    elf_str_scanned = 0
    elf_str_findings = 0
    for fi in elf_fis:
        if _scan_elf_strings(fi, analysis_dir):
            elf_str_scanned += 1
            if fi.findings:
                elf_str_findings += 1

    # --- 不透明固件分诊(unknown + text 类嗅探命中) ---
    # unknown: file=data 的裸二进制(固件/模型/私有格式),旧代码无 handler 静默跳过
    # text 类嗅探命中: cn.hex 这类被 file 误判为 "ASCII text" 的固件(实测确认),
    #   4KB 嗅探命中 hex/srec 签名才转分诊,正常文本不受影响
    unknown_fis = [fi for fi in fileinfos if fi.type == "unknown"]
    text_hex = []
    for fi in text_fis:
        try:
            head = Path(fi.path).read_bytes()[:4096]
        except OSError:
            continue
        kind, _ = sniff_firmware_kind(head)
        if kind in ("firmware_hex", "firmware_srec"):
            text_hex.append(fi)
    triaged = 0
    for fi in unknown_fis + text_hex:
        if triage_opaque(fi, workspace):
            triaged += 1

    crypto_summary = ", ".join(f"{t}={n}" for t, n in sorted(crypto_counts.items()))
    print(
        f"[Step4] 处理完成: ELF={elf_total}(ok={elf_ok}, failed={elf_failed}, "
        f"跳过={elf_skipped}, 续传复用={elf_resumed}, cap跳过={elf_capped}), "
        f"crypto={crypto_count}({crypto_summary}), 文本扫描={text_scanned}(有发现={text_with_findings}), "
        f"ELF字符串扫描={elf_str_scanned}(有发现={elf_str_findings}), "
        f"不透明分诊={len(unknown_fis)}(hex/srec从text捞={len(text_hex)}, 已分诊={triaged})"
    )
    if elf_total > 0 and elf_skipped == elf_total:
        print("[Step4] 提示: 所有 ELF 被跳过(Ghidra 镜像未建),文本/crypto 审计仍可进行")

    return fileinfos


# --- 文本类扫描 ---
import re as _re
import contextlib

_TEXT_SCAN_MAX_FINDINGS = 50
_TEXT_SCAN_MAX_BYTES = 1024 * 1024  # 超过 1MB 当二进制,不扫

# 命中即记入 findings 供 Step5 复核。
# password_kw 刻意要求"关键字 + 分隔符(:/=) + 值"的赋值形式,而非裸词:
# 裸词会命中 API 参数名(set_password())、XML 字段名、系统配置项(PASS_MAX_DAYS),
# 造成海量误报(实测 etc/mono 模板、mqtt 库头文件)。赋值形式才像硬编码。
# 值字符类加 ["']? 允许引号内取值: 固件 JSON/YAML 配置几乎全是 password = "hunter2",
# 旧排除集把引号一并排除导致这类最高频信号漏检。键名 [_A-Z0-9]* 支持 SECRET_KEY=...
# / PASSWORD_HASH=... 这类下划线/大写键名(仍要求 : 或 =,不退回裸词)。
# wifi_psk: 嵌入式固件 WiFi 明文密码最常见位置: NetworkManager system-connections,
# 格式 psk=xxx / passphrase=xxx / wpa-passphrase=xxx / pre-shared-key=xxx,
# 同样允许引号内取值(psk="xxxxx")。独立类型便于 Step5 突出显示。
_TEXT_PATTERNS = [
    ("private_key",   _re.compile(rb"BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("shadow_hash",   _re.compile(rb"\$[156]\$[^\s:$]{8,}")),
    ("wifi_psk",      _re.compile(rb"(?i)(?:psk|passphrase|wpa-psk|wpa_passphrase|pre-shared[-_]?key)\s*[:=]\s*[\"']?[^\s\"'<>]+")),
    ("password_kw",   _re.compile(rb"(?i)(?:password|passwd|secret|api[_-]?key|apikey|token|credential)[_A-Z0-9]*\s*[:=]\s*[\"']?[^\s\"'<>]+")),
    ("url",           _re.compile(rb"https?://[^\s\"'<>]+")),
    ("ipv4",          _re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
]

# 系统标准配置目录(逻辑路径)。这些目录下的文件多为发行版样例/模板/默认配置,
# 含 password/secret/token/url/ip 等字样属正常(如 Debian /etc/adduser.conf 的
# "passwd" 提示、软件源 URL)。fi.is_system_trust 只覆盖证书信任库,Text 需独立名单。
# 对其中文件降低"低危信号"匹配,避免冲刷报告;高危信号(private_key/shadow_hash)
# 不受影响,始终保留。
# 2026-08-30(C3):降级名单收敛到 file_rules 的 SYSTEM_DOWNGRADE_DIRS(原硬编码
# _SYSTEM_STD_DIRS)。注意与 profile SYSTEM_STD_DIRS 区分:那套是"排除送审",
# 此目录是"活着走到 Step4、只降级不排除"。

# 低危信号:在降级目录下不再匹配(避免误报)
_LOW_RISK_KINDS = {"password_kw", "url", "ipv4"}

# ExtractInfo.py 产物格式版本;旧版产物(decompile.c 无此标记)自动失效重跑
_EXTRACTINFO_VERSION = 2

# ELF 字符串扫描(strings.json)的 findings 上限,防膨胀
_ELF_SCAN_MAX_FINDINGS = 200


def _in_downgrade_dir(logical: str) -> bool:
    """逻辑路径是否落在低危信号降级目录下(file_rules 收敛)。"""
    return is_downgrade_dir(logical)


def _scan_text(fi: FileInfo, analysis_dir: Path) -> None:
    """扫描文本类文件(script/source/config/text)中的可疑硬编码。

    搜索私钥标记、shadow 哈希、密码关键字、URL、IP。命中写入 fi.findings,
    并落盘 analysis_dir/<rel>.text.json 供 Step5 消费。
    audit_status: 无发现 -> passed,有发现 -> suspicious(与 models.py 文档化取值一致,
    不再用未文档化的 "ready")。每个 finding 关联 is_system_trust / in_system_std,
    供 Step5 区分"系统标准配置"与"厂商可疑硬编码";系统标准目录下的低危信号
    (password_kw/url/ipv4)直接跳过,避免海量误报(实测 private_key/shadow_hash 才是真信号)。
    """
    import json

    fi.audit_status = "passed"  # 默认无发现;下方有发现时覆写为 suspicious
    p = Path(fi.path)
    try:
        size = p.stat().st_size
    except OSError:
        return
    if size == 0 or size > _TEXT_SCAN_MAX_BYTES:
        return
    try:
        data = p.read_bytes()
    except OSError:
        return

    logical = logical_path(fi.rel_path)
    in_system_std = _in_downgrade_dir(logical)
    is_system_trust = fi.is_system_trust

    findings: list[dict] = []
    for kind, pat in _TEXT_PATTERNS:
        # 系统标准目录下的低危信号不匹配,避免误报
        if in_system_std and kind in _LOW_RISK_KINDS:
            continue
        for m in pat.finditer(data):
            match_str = m.group(0).decode("utf-8", errors="replace")[:120]
            line = data.count(b"\n", 0, m.start()) + 1
            findings.append({
                "type": kind,
                "match": match_str,
                "line": line,
                "is_system_trust": is_system_trust,
                "in_system_std": in_system_std,
            })
            if len(findings) >= _TEXT_SCAN_MAX_FINDINGS:
                break
        if len(findings) >= _TEXT_SCAN_MAX_FINDINGS:
            break

    fi.findings = findings
    if findings:
        fi.audit_status = "suspicious"  # 有可疑硬编码,交 Step5 复核
    out = analysis_dir / f"{fi.rel_path}.text.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {"path": fi.rel_path, "type": fi.type, "count": len(findings),
             "is_system_trust": is_system_trust, "in_system_std": in_system_std,
             "findings": findings},
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )


def _scan_elf_strings(fi: FileInfo, analysis_dir: Path) -> bool:
    """宿主侧扫描 ELF 的 strings.json(Ghidra 产物),替代原始字节扫描。

    读 analysis_dir/<rel_path>.strings.json,对每个字符串 value 跑 _TEXT_PATTERNS
    (与文本扫描相同的降级规则: in_system_std 时跳过 _LOW_RISK_KINDS)。命中记
    finding(schema 与文本扫描兼容,附加字符串上下文 address/refs)。strings.json
    缺失(Ghidra 不可用/未跑)→ 直接返回,不崩、不写产物,audit_status 保持默认。
    audit_status: 无发现 -> passed,有发现 -> suspicious。

    Returns: 是否实际扫描了 strings.json(缺失返回 False)。
    """
    import json

    sfile = analysis_dir / f"{fi.rel_path}.strings.json"
    if not sfile.is_file():
        return False
    try:
        data = json.loads(sfile.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    strings = data.get("strings", []) if isinstance(data, dict) else []

    logical = logical_path(fi.rel_path)
    in_system_std = _in_downgrade_dir(logical)
    is_system_trust = fi.is_system_trust

    findings: list[dict] = []
    for s in strings:
        value = s.get("value", "")
        if not isinstance(value, str):
            continue
        raw = value.encode("utf-8", errors="replace")
        for kind, pat in _TEXT_PATTERNS:
            if in_system_std and kind in _LOW_RISK_KINDS:
                continue
            m = pat.search(raw)
            if m:
                match_str = m.group(0).decode("utf-8", errors="replace")[:120]
                findings.append({
                    "type": kind,
                    "match": match_str,
                    "address": s.get("address", ""),
                    "refs": s.get("refs", []),
                    "line": 0,
                    "is_system_trust": is_system_trust,
                    "in_system_std": in_system_std,
                })
                if len(findings) >= _ELF_SCAN_MAX_FINDINGS:
                    break
        if len(findings) >= _ELF_SCAN_MAX_FINDINGS:
            break

    fi.findings = findings
    fi.audit_status = "suspicious" if findings else "passed"
    out = analysis_dir / f"{fi.rel_path}.text.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {"scan": "elf", "path": fi.rel_path, "type": fi.type,
             "count": len(findings), "is_system_trust": is_system_trust,
             "in_system_std": in_system_std, "findings": findings},
            ensure_ascii=False, indent=2,
        ),
        encoding="utf-8",
    )
    return True


def _run_ghidra(fi: FileInfo, analysis_dir: Path) -> bool:
    """Ghidra Headless 反编译 + 程序信息提取。

    流程:
    1. analyzeHeadless <project> audit -import <elf> -postScript ExtractInfo.py <output>
    2. ExtractInfo.py 产出: decompiled.c / functions.json / imports.json / symbols.json
    3. 整理到 analysis_dir/<rel_path>.c 和 analysis_dir/<rel_path>.*.json(合并目录)

    Returns:
        True 成功, False 失败
    """
    input_file = Path(fi.path)
    if not input_file.is_file():
        print(f"[Step4] ELF 文件不存在: {fi.path}")
        fi.ghidra_status = "failed"
        return False

    print(f"[Step4] Ghidra 反编译: {fi.rel_path}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        project_dir = tmpdir / "project"
        project_dir.mkdir()
        ghidra_output = tmpdir / "output"
        ghidra_output.mkdir()

        # analyzeHeadless 参数
        args = [
            _CONT_PROJECT, "audit",
            "-import", f"{_CONT_INPUT}/{input_file.name}",
            # 分析阶段超时: 大库/异常二进制分析可能失控(实测 libddsc.so 在
            # 并行竞争下 600s 超时)。-analysisTimeoutPerFile 是 Ghidra 原生
            # 分析阶段截断: 超时后中断分析、保留已完成 analyzer 结果、继续
            # postScript(ExtractInfo.py 仍产出,仅丢少量函数反编译,实测 60s
            # 超时 5146/5195, -0.9%)。300s 足够小库,大库"分析到哪算哪"。
            "-analysisTimeoutPerFile", "300",
            "-postScript", "ExtractInfo.py", _CONT_OUTPUT,
            "-deleteProject",
            "-overwrite",
            "-scriptPath", "/opt/ghidra/Ghidra/Features/Decompiler/ghidra_scripts",
        ]
        mounts = [
            (input_file.parent, _CONT_INPUT),
            (ghidra_output, _CONT_OUTPUT),
            (project_dir, _CONT_PROJECT),
        ]

        # Docker timeout 900: 分析 300s 截断后 + postScript 反编译仍需时间,
        # 600s 总限太紧(实测 60s 分析 + 反编译 = 248s;300s 分析 + 反编译
        # 大库可能 >600s,故提到 900 给足余量)。
        rc, stdout, stderr = run_docker(
            GHIDRA_IMAGE, args, mounts=mounts, timeout=900
        )

        if rc != 0:
            print(f"[Step4] Ghidra 失败(退出码 {rc}): {fi.rel_path}")
            if stderr:
                print(f"[Step4] stderr: {stderr[:500]}")
            fi.ghidra_status = "failed"
            return False

        # 整理产出(全部进 analysis_dir)
        success = False

        # decompiled.c -> analysis_dir/rel_path.c
        decompiled_src = ghidra_output / "decompiled.c"
        if decompiled_src.exists() and decompiled_src.stat().st_size > 0:
            dest = analysis_dir / f"{fi.rel_path}.c"
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(decompiled_src, dest)
            fi.decompiled_path = str(dest)
            # 只有真实反编译成功数>0 才算成功。全部函数反编译失败时头部
            # decompile_success=0(空壳),标 failed,下次可续传重跑。
            success = _decompile_success_count(dest) > 0

        # *.json -> analysis_dir/rel_path.*.json
        for json_file in ghidra_output.glob("*.json"):
            if json_file.stat().st_size > 0:
                dest = analysis_dir / f"{fi.rel_path}.{json_file.name}"
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(json_file, dest)
                if not fi.analysis_path:
                    fi.analysis_path = str(dest.parent)

        if success:
            fi.ghidra_status = "ok"
            print(f"[Step4] 反编译成功: {fi.rel_path}")
        else:
            fi.ghidra_status = "failed"
            print(f"[Step4] 反编译无有效产出(全部函数失败或空壳): {fi.rel_path}")

        return success


def _crypto_base_info(fi: FileInfo) -> dict:
    """所有 crypto parser 返回结构的公共字段。

    统一结构(各 parser 填充自己能识别的字段):
        {
            "crypto_type": "crypto_x509" / ...,
            "algorithm":   "rsa" / "ecdsa" / "ed25519" / ...,
            "is_private":  true / false,
            "format":      "PEM" / "DER" / "OpenSSH" / "OpenPGP-binary" / ...,
            "parse_status":"ok" / "unsupported" / "parse_error" / "no_lib",
            "message":     "可选的人类可读说明",
            "path":        rel_path,
            "size":        bytes
        }
    """
    return {
        "crypto_type": fi.type,
        "algorithm": "",
        "is_private": False,
        "format": "",
        "parse_status": "",
        "message": "",
        "path": fi.rel_path,
        "size": fi.size,
    }


def _key_algorithm(key) -> str:
    """把 cryptography 的密钥对象映射成标准算法名。

    旧实现 type(key).__name__.replace("_","").lower() 会产出 "rsapublickey"
    这类非标准串(实测 DigiCert 证书)。统一映射成 rsa/ecdsa/ed25519/dsa 等标准名,
    便于 Step5 按算法维度统计。未知类型回退到类名小写去下划线。
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import (
            rsa, ec, ed25519, ed448, dsa, x25519, x448,
        )
    except ImportError:
        return type(key).__name__.replace("_", "").lower()
    if isinstance(key, (rsa.RSAPublicKey, rsa.RSAPrivateKey)):
        return "rsa"
    if isinstance(key, (ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey)):
        return "ecdsa"
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "ed25519"
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "ed448"
    if isinstance(key, (dsa.DSAPublicKey, dsa.DSAPrivateKey)):
        return "dsa"
    if isinstance(key, (x25519.X25519PublicKey, x25519.X25519PrivateKey)):
        return "x25519"
    if isinstance(key, (x448.X448PublicKey, x448.X448PrivateKey)):
        return "x448"
    return type(key).__name__.replace("_", "").lower()


def _dispatch_crypto(fi: FileInfo, analysis_dir: Path, legacy: bool = False) -> None:
    """Crypto dispatcher: 按 fi.type 调用对应 parser。

    统一产出 analysis_dir/<rel_path>.crypto.json(不再用 .cert.json,
    因为不再只有证书)。

    Args:
        legacy: True 表示 fi.type 是旧的 "cert"(重跑前旧数据),
                无法精确 dispatch,走 fallback 全格式尝试。
    """
    import json

    ctype = fi.type if not legacy else "cert"

    if legacy:
        info = _parse_legacy_cert(fi)
    else:
        parser = _CRYPTO_PARSERS.get(ctype, _parse_unknown)
        info = parser(fi)

    # 透传系统信任库标记:Step5 据此把这类凭证排除出"可疑硬编码凭证"
    info["system_trust"] = bool(fi.is_system_trust)

    out = analysis_dir / f"{fi.rel_path}.crypto.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(info, ensure_ascii=False, indent=2), encoding="utf-8")
    fi.analysis_path = str(out)
    if fi.is_system_trust:
        fi.audit_status = "passed"   # 系统信任库,默认非可疑


# --- 各 crypto parser ---

def _parse_x509(fi: FileInfo) -> dict:
    """X.509 证书(PEM 或 DER)。

    file 输出 "PEM certificate" 或 "Certificate, Version=3"(DER)。
    """
    info = _crypto_base_info(fi)
    info["format"] = "PEM-or-DER"

    try:
        import warnings
        from cryptography import x509
    except ImportError:
        info["parse_status"] = "no_lib"
        info["message"] = "cryptography 库未安装"
        return info

    try:
        data = Path(fi.path).read_bytes()
        cert = None
        # 固件里有 RFC 5280 非法的负 serial 证书,cryptography 43 会打印
        # CryptographyDeprecationWarning 刷屏。该告警由 C 扩展在加载与读取 serial
        # 时触发,`module=` 过滤匹配不到(模块名非 "cryptography"),故用
        # simplefilter 忽略整个解析块内的所有警告,避免污染终端。
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for loader in (x509.load_pem_x509_certificate, x509.load_der_x509_certificate):
                try:
                    cert = loader(data)
                    info["format"] = "PEM" if loader is x509.load_pem_x509_certificate else "DER"
                    break
                except ValueError:
                    continue
            if cert is None:
                info["parse_status"] = "parse_error"
                info["message"] = "既非 PEM 也非 DER"
                return info

            info["parse_status"] = "ok"
            info["algorithm"] = _key_algorithm(cert.public_key())
            try:
                info["subject"] = cert.subject.rfc4514_string()
                info["issuer"] = cert.issuer.rfc4514_string()
                info["serial"] = str(cert.serial_number)
            except Exception:
                pass
            # 负 serial 是 RFC 5280 不允许的(serial 必须是非负整数),本身是审计价值点:
            # 厂商反向生成/自签名证书的常见特征,记录到 message 供 Step5 关注。
            if cert.serial_number < 0:
                info["message"] = "负 serial 证书(非标准,RFC 5280 不允许)"
    except Exception as e:
        info["parse_status"] = "parse_error"
        info["message"] = str(e)[:200]
    return info


def _parse_ssh(fi: FileInfo) -> dict:
    """OpenSSH 公钥/私钥。

    file 输出 "OpenSSH ... public key" 或 "OpenSSH private key"。
    """
    info = _crypto_base_info(fi)
    info["format"] = "OpenSSH"

    # 从 file 输出推断公/私
    subtype_lower = fi.subtype.lower()
    if "private" in subtype_lower:
        info["is_private"] = True
    elif "public" in subtype_lower:
        info["is_private"] = False

    # 从文件名二次确认(ssh_host_xxx_key 是私钥,_key.pub 是公钥)
    name = fi.rel_path.lower()
    if name.endswith(".pub"):
        info["is_private"] = False
    elif name.endswith("_key") or "/id_" in name:
        info["is_private"] = True

    # 推断算法(从 file 输出或文件名)
    for alg in ("ecdsa", "ed25519", "rsa", "dsa"):
        if alg in subtype_lower or alg in name:
            info["algorithm"] = alg
            break

    try:
        from cryptography.hazmat.primitives.serialization import (
            load_ssh_private_key, load_ssh_public_key,
        )
        data = Path(fi.path).read_bytes()
        try:
            if info["is_private"]:
                key = load_ssh_private_key(data, password=None)
                info["parse_status"] = "ok"
                info["algorithm"] = _key_algorithm(key)
                with contextlib.suppress(AttributeError):
                    info["key_size"] = key.key_size
            else:
                key = load_ssh_public_key(data)
                info["parse_status"] = "ok"
                info["algorithm"] = _key_algorithm(key)
                with contextlib.suppress(AttributeError):
                    info["key_size"] = key.key_size
        except Exception as e:
            info["parse_status"] = "parse_error"
            info["message"] = str(e)[:200]
    except ImportError:
        info["parse_status"] = "no_lib"
        info["message"] = "cryptography 库未安装(SSH 解析需要)"
    except Exception as e:
        info["parse_status"] = "parse_error"
        info["message"] = str(e)[:200]
    return info


def _parse_gpg(fi: FileInfo) -> dict:
    """OpenPGP/GPG 密钥(二进制 .gpg 或 ASCII .asc)。

    file 输出 "OpenPGP Public Key" 或 "PGP public key block"。
    cryptography 库不直接支持 OpenPGP,只记录元信息。
    """
    info = _crypto_base_info(fi)
    subtype_lower = fi.subtype.lower()

    if "ascii" in subtype_lower or fi.rel_path.lower().endswith(".asc"):
        info["format"] = "PGP-ASCII"
    else:
        info["format"] = "PGP-binary"

    if "public" in subtype_lower:
        info["is_private"] = False
    elif "private" in subtype_lower or "secret" in subtype_lower:
        info["is_private"] = True

    # 从 file 输出提取算法(RSA/DSA/ElGamal/ECC)
    for alg in ("rsa", "dsa", "elgamal", "ecc", "eddsa", "ecdh"):
        if alg in subtype_lower:
            info["algorithm"] = alg
            break

    # 从 file 输出提取创建时间(如 "Created Thu May 30 00:40:54 2019")
    import re
    m = re.search(r"created\s+\w+\s+\w+\s+\d+\s+\d+:\d+:\d+\s+\d+", subtype_lower)
    if m:
        info["created"] = m.group(0)

    info["parse_status"] = "ok"
    info["message"] = "PGP 元信息从 file 输出提取(未深入解析 keyring 结构)"
    return info


def _parse_pkcs12(fi: FileInfo) -> dict:
    """PKCS#12 证书包(.p12/.pfx)。

    通常包含证书 + 私钥 + CA 链,可能加密。
    """
    info = _crypto_base_info(fi)
    info["format"] = "PKCS12"

    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
    except ImportError:
        info["parse_status"] = "no_lib"
        info["message"] = "cryptography 库未安装"
        return info

    try:
        data = Path(fi.path).read_bytes()
        # 尝试无密码加载(固件里常见无密码或弱密码)
        try:
            key, cert, addl = pkcs12.load_key_and_certificates(data, None)
            info["parse_status"] = "ok"
            info["is_private"] = key is not None
            if cert:
                info["subject"] = cert.subject.rfc4514_string()
                info["issuer"] = cert.issuer.rfc4514_string()
            info["additional_certs"] = len(addl) if addl else 0
        except ValueError:
            info["parse_status"] = "unsupported"
            info["message"] = "PKCS12 加密,需密码(固件审计可标记为可疑)"
    except Exception as e:
        info["parse_status"] = "parse_error"
        info["message"] = str(e)[:200]
    return info


def _parse_private_key(fi: FileInfo) -> dict:
    """私钥(扩展名 .key,但 file 未识别为 PEM/SSH)。

    可能是厂商自定义格式或裸密钥。
    """
    info = _crypto_base_info(fi)
    info["is_private"] = True
    info["format"] = "unknown-private"

    # 尝试 PEM 私钥
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        data = Path(fi.path).read_bytes()
        try:
            key = load_pem_private_key(data, password=None)
            info["parse_status"] = "ok"
            info["format"] = "PEM"
            # 统一 _key_algorithm,避免 type().__name__ 产出 "rsaprivatekey" 非标准名
            info["algorithm"] = _key_algorithm(key)
            with contextlib.suppress(AttributeError):
                info["key_size"] = key.key_size
        except ValueError:
            # 可能是 DER 私钥或厂商格式
            info["parse_status"] = "unsupported"
            info["message"] = "非 PEM 私钥,可能是 DER 或厂商自定义格式"
    except ImportError:
        info["parse_status"] = "no_lib"
        info["message"] = "cryptography 库未安装"
    except Exception as e:
        info["parse_status"] = "parse_error"
        info["message"] = str(e)[:200]
    return info


def _parse_public_key(fi: FileInfo) -> dict:
    """公钥(扩展名 .pub,但 file 未识别为 SSH)。

    可能是 PEM 公钥或厂商格式。
    """
    info = _crypto_base_info(fi)
    info["is_private"] = False
    info["format"] = "unknown-public"

    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_public_key, load_ssh_public_key,
        )
        data = Path(fi.path).read_bytes()
        for loader, fmt in ((load_pem_public_key, "PEM"), (load_ssh_public_key, "OpenSSH")):
            try:
                key = loader(data)
                info["parse_status"] = "ok"
                info["format"] = fmt
                info["algorithm"] = _key_algorithm(key)
                with contextlib.suppress(AttributeError):
                    info["key_size"] = key.key_size
                break
            except ValueError:
                continue
        else:
            info["parse_status"] = "unsupported"
            info["message"] = "非 PEM/SSH 公钥,可能是厂商格式"
    except ImportError:
        info["parse_status"] = "no_lib"
        info["message"] = "cryptography 库未安装"
    except Exception as e:
        info["parse_status"] = "parse_error"
        info["message"] = str(e)[:200]
    return info


def _parse_unknown(fi: FileInfo) -> dict:
    """未识别的密码学材料(crypto_unknown)。

    记录基本信息,标记需人工或 Step5 进一步分析。
    """
    info = _crypto_base_info(fi)
    info["format"] = "unknown"
    info["parse_status"] = "unsupported"
    info["message"] = "未识别的密码学材料,建议人工检查内容"
    return info


def _parse_legacy_cert(fi: FileInfo) -> dict:
    """兼容旧 fileinfo.json 中 type=cert 的记录。

    不知道具体子类型,按顺序尝试 PEM 私钥 → PEM 公钥 → X.509 → SSH → 标记 unknown。
    """
    info = _crypto_base_info(fi)
    info["crypto_type"] = "cert(legacy)"
    info["format"] = "legacy-unknown"

    try:
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key, load_pem_public_key, load_ssh_public_key,
        )
        from cryptography import x509
        data = Path(fi.path).read_bytes()

        for loader, fmt, is_priv in (
            (lambda d: load_pem_private_key(d, password=None), "PEM", True),
            (load_pem_public_key, "PEM", False),
            (x509.load_pem_x509_certificate, "PEM-X509", False),
            (x509.load_der_x509_certificate, "DER-X509", False),
            (load_ssh_public_key, "OpenSSH", False),
        ):
            try:
                obj = loader(data)
                info["parse_status"] = "ok"
                info["format"] = fmt
                info["is_private"] = is_priv
                if hasattr(obj, "subject"):  # 证书
                    info["subject"] = obj.subject.rfc4514_string()
                    info["issuer"] = obj.issuer.rfc4514_string()
                else:  # 密钥
                    info["algorithm"] = _key_algorithm(obj)
                    with contextlib.suppress(AttributeError):
                        info["key_size"] = obj.key_size
                return info
            except ValueError:
                continue
        info["parse_status"] = "unsupported"
        info["message"] = "所有 parser 均失败,可能是厂商自定义格式"
    except ImportError:
        info["parse_status"] = "no_lib"
        info["message"] = "cryptography 库未安装"
    except Exception as e:
        info["parse_status"] = "parse_error"
        info["message"] = str(e)[:200]
    return info


# 类型 -> parser 映射(dispatch 表)
_CRYPTO_PARSERS = {
    "crypto_x509":         _parse_x509,
    "crypto_ssh":          _parse_ssh,
    "crypto_gpg":          _parse_gpg,
    "crypto_pkcs12":       _parse_pkcs12,
    "crypto_private_key":  _parse_private_key,
    "crypto_public_key":   _parse_public_key,
    "crypto_unknown":      _parse_unknown,
}
