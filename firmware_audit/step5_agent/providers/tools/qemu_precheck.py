"""qemu_precheck:QEMU 动态实验前的静态预检(票 05;spec 预检/会话两组能力的检查侧)。

边界(ADR-0013 + 票 04 纪律):
- 只做静态核查:ELF 头/程序头/动态段解析 + 固件根内文件存在性检查,
  **不执行目标、不运行固件或其加载器、不创建会话**。唯一容器调用是执行
  镜像内 qemu 二进制自报 --version(设施核查,不读不触固件字节)。
- 通过≠可运行:架构/解释器/依赖检查通过**不代表子进程链能力已验证**——
  票 04 实测 ARM(target/6 uClibc)链受阻且根因未定论、MIPS 链需
  QEMU_LD_PREFIX 适配;限制句固定写入每份报告。
- 结果分类只从 PRECHECK_RESULT_CLASSES 子集发出;解析原始信息全量进
  data,阻塞必有 detail,不静默丢弃。
- 模板适用性(票 02 移交口径):NEEDED 含 NVRAM 系库 → 需模板注入;模板
  支持表未定稿(票 11)按 ADR-0013 记运行阻塞;/dev/nvram 系与
  envram(MTD)系的家族归属需符号级核实,预检不判定。

ToolResult.ok 语义:预检报告成功产出即为 True(阻塞是发现,不是预检失败);
分类与阻塞项看 data.result_class / data.blockers。参数未过契约才 ok=False。
"""
from __future__ import annotations

import struct
from pathlib import Path

from ....docker.docker_utils import docker_available, run_docker
from .base import AgentTool, ToolResult, resolve_within
from .cli_base import extracted_root
from .qemu_base import (
    QEMU_EXEC_IMAGE,
    QEMU_ARCH_MATRIX,
    QemuArchProfile,
    QemuResultClass,
)

# 动态段遍历的条目标签(只用到这三个)
_DT_NULL, _DT_NEEDED, _DT_STRTAB = 0, 1, 5
_PT_LOAD, _PT_DYNAMIC, _PT_INTERP = 1, 2, 3

# 固件根内的标准库目录(先按布局查,再限界递归兜底)
_LIB_DIRS = ("lib", "usr/lib", "lib32", "usr/lib32", "lib64", "usr/lib64")
_LIB_SEARCH_CAP = 20000  # 递归兜底的条目上限(防病态树;超出记入 search_note)

# NVRAM 系库基名(票 02:三方 /dev/nvram 同协议库;envram 家族的库归属
# 需符号级核实,基名匹配只标"需要 NVRAM 模板",不判定家族)
_NVRAM_FAMILY_BASENAMES = ("libnvram.so", "libCfm.so", "libtpi.so")

# 固定限制句(每份报告必带;措辞是票 04 纪律的落点,不得改写为能力宣称)
_LIMIT_NO_EXEC = ("预检是静态核查:不执行目标、不运行固件或其加载器、"
                  "不创建会话;预检结果只是 Evidence,不构成漏洞成立或不存在的依据。")
_LIMIT_CHAIN = ("架构/解释器/依赖检查通过不代表子进程链能力已验证"
                "(票 04 实测:ARM32 LE uClibc 链当前受阻且根因未定论,"
                "MIPS32 BE 链需 QEMU_LD_PREFIX 环境适配);链能力以会话期实测为准。")
_LIMIT_MATRIX = ("矩阵内命名是档案不是能力承诺:不能据架构名称宣称所有程序可运行;"
                 "矩阵外架构仅表示不在首批范围,不表示永久不可行。")


class ElfParseError(ValueError):
    """ELF 解析失败(非 ELF/截断/结构不可读)——预检转为准备阻塞,不崩溃。"""


def _vaddr_to_offset(loads: list[tuple[int, int, int]], vaddr: int) -> int | None:
    """PT_LOAD 恒等/偏移映射:vaddr → 文件 offset;不在任何段内返回 None。"""
    for vaddr0, offset, filesz in loads:
        if vaddr0 <= vaddr < vaddr0 + filesz:
            return offset + (vaddr - vaddr0)
    return None


def parse_elf_runtime(blob: bytes) -> dict:
    """静态解析执行镜像关注的三类信息:架构三元组、PT_INTERP、DT_NEEDED。

    纯 struct 实现(零依赖铁律),32/64 位、大小端通吃;失败抛 ElfParseError。
    只读字节,不执行任何代码(预检红线,见模块 docstring)。
    返回 {bits, endianness, e_machine, interp, needed, has_dynamic,
    dynamic_note};static 形态 interp=None/needed=[]/has_dynamic=False;
    dynamic_note 记动态段不可解析的原因(非阻塞 note,原始信息保留)。
    """
    if len(blob) < 20 or blob[:4] != b"\x7fELF":
        raise ElfParseError("非 ELF 文件(魔数不符)")
    ei_class, ei_data = blob[4], blob[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ElfParseError(f"ELF class/data 非法: {ei_class}/{ei_data}")
    end = "<" if ei_data == 1 else ">"
    bits = 32 if ei_class == 1 else 64
    e_machine = struct.unpack_from(end + "H", blob, 18)[0]
    if bits == 32:
        phoff = struct.unpack_from(end + "I", blob, 28)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", blob, 42)
    else:
        phoff = struct.unpack_from(end + "Q", blob, 32)[0]
        phentsize, phnum = struct.unpack_from(end + "HH", blob, 54)

    info = {"bits": bits,
            "endianness": "little" if ei_data == 1 else "big",
            "e_machine": e_machine,
            "interp": None,
            "needed": [],
            "has_dynamic": False,
            "dynamic_note": None}
    if phnum == 0 or phentsize == 0:
        info["dynamic_note"] = "无程序头表"
        return info
    phdr_end = phoff + phnum * phentsize
    if phoff <= 0 or phdr_end > len(blob):
        raise ElfParseError("程序头表越界(文件截断或损坏)")

    loads: list[tuple[int, int, int]] = []
    interp_span: tuple[int, int] | None = None
    dynamic: tuple[int, int] | None = None
    for i in range(phnum):
        base = phoff + i * phentsize
        if bits == 32:
            p_type, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(
                end + "IIIII", blob, base)
        else:
            p_type, _flags = struct.unpack_from(end + "II", blob, base)
            p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(
                end + "QQQQ", blob, base + 8)
        if p_type == _PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == _PT_INTERP:
            interp_span = (p_offset, p_filesz)
        elif p_type == _PT_DYNAMIC:
            dynamic = (p_offset, p_filesz)

    if interp_span is not None:
        ioff, isz = interp_span
        if ioff + isz > len(blob):
            raise ElfParseError("PT_INTERP 越界(文件截断或损坏)")
        nul = blob.find(b"\x00", ioff, ioff + isz)
        raw = blob[ioff: nul if nul != -1 else ioff + isz]
        info["interp"] = raw.decode("utf-8", "replace")

    if dynamic is None:
        return info  # 静态形态(无动态段)
    info["has_dynamic"] = True
    doff, dsz = dynamic
    entsize = 8 if bits == 32 else 16
    fmt = end + ("iI" if bits == 32 else "qQ")
    if dsz % entsize or doff + dsz > len(blob):
        info["dynamic_note"] = "动态段越界或长度非法,依赖清单不可解析"
        return info
    strtab_vaddr: int | None = None
    needed_offsets: list[int] = []
    for off in range(doff, doff + dsz, entsize):
        tag, val = struct.unpack_from(fmt, blob, off)
        if tag == _DT_NULL:
            break
        if tag == _DT_NEEDED:
            needed_offsets.append(val)
        elif tag == _DT_STRTAB:
            strtab_vaddr = val
    if strtab_vaddr is None:
        info["dynamic_note"] = "动态段缺 DT_STRTAB,依赖清单不可解析"
        return info
    strtab_off = _vaddr_to_offset(loads, strtab_vaddr)
    if strtab_off is None:
        info["dynamic_note"] = "DT_STRTAB 不在任何 PT_LOAD 内,依赖清单不可解析"
        return info
    for v in needed_offsets:
        s = strtab_off + v
        if s >= len(blob):
            info["needed"].append(f"<dynstr 越界 offset {v}>")
            continue
        nul = blob.find(b"\x00", s)
        info["needed"].append(blob[s: nul if nul != -1 else len(blob)]
                              .decode("utf-8", "replace"))
    return info


class QemuPrecheckTool(AgentTool):
    name = "qemu_precheck"
    description = (
        "QEMU 动态实验前的静态预检:ELF 架构/解释器/依赖/模板适用性/路径边界。"
        "只读检查,不执行目标、不创建会话;通过不代表子进程链可用。"
        "适合在投入动态实验前确认准备条件与阻塞项。"
    )
    params = {
        "file_ref": {"type": "str", "required": True,
                     "desc": "目标 ELF 工具路径(相对 extracted 根,可带 extracted/ 前缀)"},
        "firmware_root": {"type": "str", "required": True,
                          "desc": "加载器/依赖解析根(-L 前缀;相对 extracted 根的固件根目录)"},
    }

    # ---- 设施核查(唯一容器调用;测试用 Docker 替身替换本方法) ----

    def _facility_check(self, qemu_binary: str) -> dict:
        """执行镜像内 qemu 二进制自报版本。只跑 qemu 自身(x86 静态二进制),
        不读不触固件字节(预检红线:不运行固件或其加载器)。

        命令按 AGENTS.md 踩坑纪律用纯字符串拼接(禁 .format/f-string)。
        """
        if not docker_available(QEMU_EXEC_IMAGE):
            return {"image": QEMU_EXEC_IMAGE, "qemu_binary": qemu_binary,
                    "available": False, "version": None,
                    "detail": f"镜像 {QEMU_EXEC_IMAGE} 不可用"
                              "(docker image inspect 失败;先运行 build_image.sh)"}
        cmd = qemu_binary + " --version 2>&1 | head -1"
        rc, out, err = run_docker(QEMU_EXEC_IMAGE, ["-c", cmd],
                                  entrypoint="bash", network="none", timeout=60)
        lines = (out or "").strip().splitlines()
        version = lines[0].strip() if lines else ""
        available = rc == 0 and "version" in version
        detail = version or (err or "").strip()[:200]
        return {"image": QEMU_EXEC_IMAGE, "qemu_binary": qemu_binary,
                "available": available,
                "version": version if available else None,
                "detail": detail or f"qemu --version 无有效输出(rc={rc})"}

    # ---- 路径解析 ----

    def _resolve_extracted(self, ref: str) -> Path | None:
        """工具路径(相对 extracted,可带 extracted/ 前缀,ADR-0008)→ 绝对路径。"""
        r = (ref or "").strip().replace("\\", "/").removeprefix("extracted/")
        if r.startswith("/"):
            return None
        return resolve_within(extracted_root(self.ctx), r)

    # ---- 固件根内检索 ----

    def _find_in_root(self, root: Path, basename: str) -> tuple[str | None, bool]:
        """在固件根内找库/加载器文件,返回 (相对 root 的 POSIX 路径|None, 检索是否截断)。

        先按标准库目录布局,再限界递归兜底;超过 _LIB_SEARCH_CAP 时返回
        (None, True)——"未找到"与"没找完"必须可区分,截断由调用方写入报告,
        不得静默当作缺失(原始信息保留红线)。
        """
        for d in _LIB_DIRS:
            cand = root / d / basename
            if cand.is_file():
                return cand.relative_to(root).as_posix(), False
        seen = 0
        for cand in root.rglob(basename):
            seen += 1
            if seen > _LIB_SEARCH_CAP:
                return None, True
            if cand.is_file():
                return cand.relative_to(root).as_posix(), False
        return None, False

    # ---- 主流程 ----

    def _run(self, file_ref: str, firmware_root: str) -> ToolResult:
        blockers: list[dict] = []

        def block(check: str, cls: QemuResultClass, detail: str) -> None:
            blockers.append({"check": check, "result_class": cls.value,
                             "detail": detail})

        def finish(report: dict) -> ToolResult:
            report["blockers"] = blockers
            report["limitations"] = [_LIMIT_NO_EXEC, _LIMIT_CHAIN, _LIMIT_MATRIX]
            rank = {QemuResultClass.FACILITY_FAILURE: 0,
                    QemuResultClass.PREP_BLOCKED: 1,
                    QemuResultClass.DEPENDENCY_BLOCKED: 2}
            classes = [QemuResultClass(b["result_class"]) for b in blockers]
            worst = min(classes, key=lambda c: rank[c]) if classes else QemuResultClass.OK
            report["result_class"] = worst.value
            report["result_class_label"] = worst.label
            text = _render_text(report)
            return ToolResult(ok=True, text=text, data=report)

        report: dict = {"schema_version": 1, "tool": self.name,
                        "mode": "precheck"}

        # 1) 路径边界:目标与固件根都必须在 extracted 只读树内
        target = self._resolve_extracted(file_ref)
        if target is None:
            block("path_boundary", QemuResultClass.PREP_BLOCKED,
                  f"目标路径越界或非法(须为 extracted/ 内相对路径): {file_ref}")
            return finish({**report,
                           "target": {"ref": file_ref, "resolved": None},
                           "firmware_root": {"ref": firmware_root}})
        root = self._resolve_extracted(firmware_root)
        if root is None:
            block("path_boundary", QemuResultClass.PREP_BLOCKED,
                  f"固件根路径越界或非法(须为 extracted/ 内相对路径): {firmware_root}")
            return finish({**report,
                           "target": {"ref": file_ref, "resolved": str(target)},
                           "firmware_root": {"ref": firmware_root, "resolved": None}})
        report["target"] = {"ref": file_ref, "resolved": str(target),
                            "within_extracted": True}
        report["firmware_root"] = {"ref": firmware_root, "resolved": str(root)}

        if not target.is_file():
            block("path_boundary", QemuResultClass.PREP_BLOCKED,
                  f"目标不存在或不是常规文件: {target}")
            return finish(report)
        if not root.is_dir():
            block("path_boundary", QemuResultClass.PREP_BLOCKED,
                  f"固件根不存在或不是目录: {root}")
            return finish(report)

        # 2) 静态解析 ELF(不执行)
        blob = target.read_bytes()
        try:
            elf = parse_elf_runtime(blob)
        except ElfParseError as exc:
            block("architecture", QemuResultClass.PREP_BLOCKED,
                  f"ELF 解析失败: {exc}")
            report["architecture"] = {"parse_error": str(exc)}
            return finish(report)
        report["architecture"] = {k: elf[k] for k in
                                  ("bits", "endianness", "e_machine")}

        # 3) 架构矩阵
        profile: QemuArchProfile | None = QEMU_ARCH_MATRIX.get(
            (elf["bits"], elf["endianness"], elf["e_machine"]))
        if profile is None:
            block("architecture", QemuResultClass.PREP_BLOCKED,
                  f"架构 ELF{elf['bits']} {elf['endianness']}-endian "
                  f"e_machine={elf['e_machine']} 不在首批矩阵"
                  "(ARM32 小端 / MIPS32 大端);矩阵扩充需另行核实,"
                  "预检不据此宣称该架构不可行")
            report["architecture"].update({"key": None, "name": None,
                                           "qemu_binary": None,
                                           "matrix": "unsupported"})
            return finish(report)
        report["architecture"].update({"key": profile.key, "name": profile.name,
                                       "qemu_binary": profile.qemu_binary,
                                       "matrix": "first_batch",
                                       "observed_notes": profile.observed_notes})

        # 4) 解释器(-L 按 PT_INTERP 原路径解析:精确路径是唯一判据;
        # basename 兜底命中只留痕,不当作解释器已就位)
        if elf["interp"]:
            rel = elf["interp"].lstrip("/")
            if (root / rel).is_file():
                report["interpreter"] = {"requested": elf["interp"],
                                         "resolved_under_root": rel,
                                         "present": True}
            else:
                alt, truncated = self._find_in_root(root, rel.split("/")[-1])
                note = (f"解释器 {elf['interp']} 在固件根内未找到"
                        "(-L 按原路径解析,运行期将无法加载;固件根可能不完整)")
                entry: dict = {"requested": elf["interp"],
                               "resolved_under_root": None, "present": False}
                if alt is not None:
                    entry["same_basename_found"] = alt
                    note += (f";固件根内另有同名文件 {alt},"
                             "但 PT_INTERP 原路径缺失,不视为解释器已就位")
                if truncated:
                    entry["search_truncated"] = True
                    note += ";检索在达上限后截断,结论可能不可靠"
                report["interpreter"] = entry
                block("interpreter", QemuResultClass.DEPENDENCY_BLOCKED, note)
        else:
            note = ("动态段存在但无 PT_INTERP,加载器解析路径未知"
                    if elf.get("has_dynamic")
                    else "静态链接:无 PT_INTERP,无需加载器解析")
            report["interpreter"] = {"requested": None, "present": None,
                                     "note": note}

        # 5) 依赖(NEEDED → 固件根内逐一解析;截断如实入报告)
        resolved: dict[str, str] = {}
        missing: list[str] = []
        search_notes: list[str] = []
        for lib in elf["needed"]:
            hit, truncated = self._find_in_root(root, lib.split("/")[-1])
            if hit is None:
                missing.append(lib)
                if truncated:
                    search_notes.append(
                        f"{lib}: 固件根检索达上限({_LIB_SEARCH_CAP} 条目)后截断,"
                        "未找到的结论可能不可靠")
            else:
                resolved[lib] = hit
        report["dependencies"] = {"needed": list(elf["needed"]),
                                  "resolved": resolved, "missing": missing}
        if elf.get("dynamic_note"):
            report["dependencies"]["dynamic_note"] = elf["dynamic_note"]
        if search_notes:
            report["dependencies"]["search_notes"] = search_notes
        for lib in missing:
            truncated_note = (";检索截断,结论可能不可靠"
                              if any(n.startswith(lib + ":") for n in search_notes)
                              else "")
            block("dependencies", QemuResultClass.DEPENDENCY_BLOCKED,
                  f"NEEDED 库 {lib} 在固件根内未找到{truncated_note}"
                  "(运行期加载将失败;确认固件根是否完整或需适配模板补齐)")

        # 6) 模板适用性(票 02 口径:NVRAM 系库 → 需模板;支持表未定稿 = 运行阻塞)
        nvram_needed = [lib for lib in elf["needed"]
                        if lib.split("/")[-1] in _NVRAM_FAMILY_BASENAMES]
        report["template_applicability"] = {
            "nvram_family_needed": nvram_needed,
            "base_templates": ("基础适配(目录/配置/argv/环境/CGI 输入)按会话声明提供,"
                               "预检不校验具体值"),
        } if nvram_needed else {"nvram_family_needed": []}
        if nvram_needed:
            report["template_applicability"]["template_status"] = \
                "not_in_support_table"
            report["template_applicability"]["detail"] = (
                f"NEEDED 含 NVRAM 系库 {', '.join(nvram_needed)}:运行期需要 NVRAM "
                "模板注入;模板支持表未定稿(票 11),且 /dev/nvram 系与 "
                "envram(MTD)系的家族归属需符号级核实,预检不判定——按 ADR-0013 "
                "记运行阻塞,不临时编造实现")
            block("template_applicability", QemuResultClass.DEPENDENCY_BLOCKED,
                  report["template_applicability"]["detail"])

        # 7) 执行设施(镜像内 qemu 自报版本;能走到这里说明架构已入选)
        facility = self._facility_check(profile.qemu_binary)
        if not facility.get("available"):
            block("execution_facility", QemuResultClass.FACILITY_FAILURE,
                  f"执行设施不可用:{facility.get('detail')}")
        report["execution_facility"] = facility
        return finish(report)


def _render_text(report: dict) -> str:
    """预检报告 → LLM 可读摘要(分类/架构/解释器/依赖/模板/设施/边界/限制)。"""
    lines = [f"[qemu_precheck] 结果分类: {report['result_class']}"
             f"({report['result_class_label']})"]
    arch = report.get("architecture") or {}
    if "parse_error" in arch:
        lines.append(f"- 架构: 解析失败({arch['parse_error']})")
    elif arch.get("key"):
        lines.append(f"- 架构: {arch['name']}(ELF{arch['bits']} "
                     f"{arch['endianness']} e_machine={arch['e_machine']})"
                     f" → {arch['qemu_binary']} [首批矩阵内]")
    else:
        lines.append(f"- 架构: ELF{arch.get('bits')} {arch.get('endianness')} "
                     f"e_machine={arch.get('e_machine')} [不在首批矩阵]")
    interp = report.get("interpreter") or {}
    if interp.get("requested"):
        state = "固件根内已找到" if interp.get("present") else "固件根内未找到"
        lines.append(f"- 解释器: {interp['requested']}({state}"
                     f"{': ' + interp['resolved_under_root'] if interp.get('resolved_under_root') else ''})")
    else:
        lines.append(f"- 解释器: {(interp or {}).get('note') or '无 PT_INTERP'}")
    deps = report.get("dependencies") or {}
    if deps.get("needed"):
        parts = [f"{lib}→{deps['resolved'][lib]} ✓" if lib in deps["resolved"]
                 else f"{lib}→未找到 ✗" for lib in deps["needed"]]
        lines.append(f"- 依赖: {'; '.join(parts)}")
    else:
        lines.append("- 依赖: 无 NEEDED(静态或不可解析)")
    tpl = report.get("template_applicability") or {}
    if tpl.get("nvram_family_needed"):
        lines.append(f"- 模板适用性: 需 NVRAM 模板({', '.join(tpl['nvram_family_needed'])});"
                     "支持表未定稿,当前为运行阻塞")
    facility = report.get("execution_facility") or {}
    if facility.get("available") is True:
        version = facility.get("version") or "版本可查"
        lines.append(f"- 执行设施: {facility['image']} "
                     f"{facility.get('qemu_binary')}({version})")
    elif facility.get("available") is False:
        lines.append(f"- 执行设施: 不可用({facility.get('detail')})")
    lines.append(f"- 路径边界: 目标与固件根均在 extracted/ 只读树内;"
                 f"预检未执行目标、未创建会话")
    for i, b in enumerate(report.get("blockers") or [], 1):
        lines.append(f"- 阻塞{i}[{b['check']}/{b['result_class']}]: {b['detail']}")
    lines.append("- 限制: " + " ".join(report.get("limitations") or []))
    return "\n".join(lines)
