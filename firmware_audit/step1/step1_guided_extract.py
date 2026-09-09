"""Step1 - 引导式解包(规则版,替代 binwalk -Me 盲解)。

为什么: binwalk -Me 无差别递归把 bootimg 内 fdt 分解成数十万
bus@0/aconnect@.../phandle 节点文件(实测 part05 61.6 万条目)。这里
改为分层: 嗅探魔数 → 预筛 → 规则决策 → 并行单层解包 → 递归。

关键设计(2026-08-13 评审定稿):
  - preclassify 二分(fdt→skip, elf/pe/text→product, 其余→rule_decision)
  - rule_decision 容器裁决(容器→continue, 无签名→finalize 留树;字符串审计由 Step5 兜底)
  - binwalk 并行默认 8(每文件独立容器,线程安全)
  - 产物布局 <file>.extracted/<HEX>/... 与 -Me 同构,Step2 正则兼容(M0 实证)
  - 断点续传 manifest: guided_extract.json
"""
from __future__ import annotations

import json
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ..docker.docker_utils import run_docker, docker_available
from ..gates import resolve_max_files_per_extraction, resolve_max_total_files
from .file_magic import sniff_magic, preclassify, rule_decision
import contextlib

BINWALK_IMAGE = "binwalk"
CONTAINER_WS = "/work/ws"

# 深度上限:正常 Android 固件链路 bootimg(0)→ramdisk.gz(1)→cpio(2)→
# init/ELF(3)= 3-4 层到底;6 = 正常链路 ≤4 + 2 层异常余量(压缩套压缩)。
# manifest 记录每容器 depth 供事后审计;第 6 层仍有 continue → warning 而非
# 静默强制 finalize(深度上限只是保险,不该吞掉"真的还有料"的信号)。
MAX_DEPTH = 6
# 单次产出/全树文件数两道闸门的默认值与 env 覆盖(STEP1_MAX_FILES_PER_
# EXTRACTION / STEP1_MAX_TOTAL_FILES)见 gates.py——消费点调 resolve_*,
# 默认值不在本模块重复定义
_MANIFEST_NAME = "guided_extract.json"


def _load_manifest(output_dir: Path) -> dict:
    """读断点续传 manifest;缺失/损坏返回空 dict(失败不崩)。"""
    p = output_dir / _MANIFEST_NAME
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_manifest(output_dir: Path, manifest: dict) -> None:
    """写 manifest;失败不崩。"""
    with contextlib.suppress(OSError):
        (output_dir / _MANIFEST_NAME).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=1), encoding="utf-8")


def _binwalk_extract_one(path: Path, seq: int, parent: Path) -> tuple[list[Path], str]:
    """真实解包: binwalk -e 单层 + 7z 兜底 + 单次产出上限守卫。

    流程:
      1. 硬改名 <parent>/<seq>_<原名>(防 binwalk 同名输出覆盖;首段
         .extracted 与 Step2 _EXTRACTED_PREFIX_RE 天然兼容)
      2. binwalk -e <f> -x dtb -d <parent>,env BINWALK_RM_EXTRACTION_SYMLINK=1
         (-x dtb: 恒排除设备树签名,源头拦截 fdt 分解)
      3. 空产出 → 7z 兜底(binwalk 镜像内置 7z;cpio/tar/7z/zip/squashfs
         等 binwalk 有签名但无 extractor 的场景)
      4. 产出 > 单次上限(env STEP1_MAX_FILES_PER_EXTRACTION,默认 5 万)
         → 删除该次产物,记 over_guard

    Returns:
        (产出文件列表, 状态): "ok" / "empty" / "over_guard" / "failed"
    """
    new = parent / f"{seq:06d}_{path.name}"
    try:
        path.rename(new)
    except OSError:
        return [], "failed"

    container_file = f"{CONTAINER_WS}/{new.name}"
    mounts = [(parent, CONTAINER_WS)]

    rc, _stdout, _stderr = run_docker(
        BINWALK_IMAGE,
        ["-e", container_file, "-x", "dtb", "-d", CONTAINER_WS],
        mounts=mounts,
        env={"BINWALK_RM_EXTRACTION_SYMLINK": "1"},
        timeout=600,
    )

    extracted_dir = parent / f"{new.name}.extracted"
    files = _collect_files(extracted_dir)

    if not files and rc == 0:
        # 空产出: 7z 兜底(binwalk 有签名但无 extractor 的容器)
        _rc7, _o7, _e7 = run_docker(
            BINWALK_IMAGE,
            ["x", container_file, f"-o{CONTAINER_WS}/{new.name}.extracted"],
            mounts=mounts,
            entrypoint="7z",
            timeout=300,
        )
        files = _collect_files(extracted_dir)

    if not files:
        return [], "empty"

    if len(files) > resolve_max_files_per_extraction():
        shutil.rmtree(extracted_dir, ignore_errors=True)
        return [], "over_guard"

    return files, "ok"


def _collect_files(directory: Path) -> list[Path]:
    """收集目录下所有文件(跳过损坏符号链接)。"""
    if not directory.is_dir():
        return []
    files = []
    for f in directory.rglob("*"):
        try:
            if f.is_file():
                files.append(f)
        except OSError:
            continue
    return files


def extract_guided(
    firmware_path: Path,
    output_dir: Path,
    max_depth: int = MAX_DEPTH,
    max_workers: int = 8,
    extractor=None,
    check_docker: bool = True,
    resume: bool = False,
    scan_tree: bool = False,
) -> Path | None:
    """引导式解包主循环。

    Args:
        firmware_path: 固件文件路径(resume/scan_tree 模式可传目录,不检查文件)
        output_dir: 解包输出目录(会创建),产物布局 <file>.extracted/<HEX>/...
        max_depth: 最大递归层数(默认 6)
        max_workers: binwalk 并行容器数(默认 8,用户拍板)
        extractor: 解包函数注入点(单测用 fake;None → _binwalk_extract_one)
        check_docker: 是否检查 Docker/镜像(单测传 False 跳过)
        resume: 断点续解模式。固件文件可能已被改名进解包树,不检查存在性;
                候选树从 manifest 重建(done continue 的 files)+ 树里未记录
                文件重新决策。
        scan_tree: 树扫描模式(归档路径)。firmware_path 是解压树根目录,
                候选队列 = 树内全部文件,嵌套容器继续解。与 resume 叠加:
                manifest 存在则复用续解,不存在从零扫描。

    Returns:
        output_dir(解包根),失败返回 None(调用方兜底旧 -Me)
    """
    firmware_path = Path(firmware_path).resolve()
    output_dir = Path(output_dir).resolve()

    if not resume and not scan_tree and not firmware_path.is_file():
        print(f"[Step1] 固件不存在: {firmware_path}")
        return None
    if scan_tree and not firmware_path.is_dir():
        print(f"[Step1] scan_tree 模式要求目录: {firmware_path}")
        return None
    if check_docker and not docker_available(BINWALK_IMAGE):
        print(f"[Step1] Docker未打开或镜像不可用: {BINWALK_IMAGE}")
        return None

    output_dir.mkdir(parents=True, exist_ok=True)
    if extractor is None:
        extractor = _binwalk_extract_one

    manifest = _load_manifest(output_dir)
    # 新 seq 从现有最大 seq+1 开始:断点续传时新产物绝不与旧同名冲突
    next_seq = max((r.get("seq", 0) for r in manifest.values()), default=-1) + 1
    # 全树守卫:已有文件数(近似,不精确但够守卫)
    total_files = sum(1 for _ in output_dir.rglob("*") if _.is_file())

    # 候选队列: (path, depth, rel_path)
    # 已被改名的容器本体(树根/<seq>_原名,manifest 的 renamed_to)在 resume/
    # scan_tree 的 rglob 里会再次出现,必须排除,否则重复决策/解包。
    renamed = {rec.get("renamed_to") for rec in manifest.values()
               if rec.get("renamed_to")}
    if resume:
        # 断点续解: 从 manifest 重建候选树
        #   - done continue 的容器,其 files 作为候选(深度 = 记录深度 + 1)
        #   - 树里未记录的(上次中断时未决策的)重新决策(深度从 0 计,保守)
        candidates: list[tuple[Path, int, str]] = []
        for rel, rec in manifest.items():
            if rec.get("action") == "continue" and rec.get("done"):
                depth = rec.get("depth", 0) + 1
                for frel in rec.get("files", []):
                    fp = output_dir / frel
                    if fp.is_file():
                        candidates.append((fp, depth, frel))
        for f in output_dir.rglob("*"):
            try:
                if not f.is_file():
                    continue
            except OSError:
                continue
            frel = str(f.relative_to(output_dir)).replace("\\", "/")
            if frel in (_MANIFEST_NAME, ".step1_done") or frel in renamed:
                continue
            if frel not in manifest:
                candidates.append((f, 0, frel))
        if not candidates:
            print("[Step1] resume: manifest 无候选,树为空,视为完成")
    elif scan_tree:
        # 树扫描模式(归档路径):候选 = 树内全部文件(rglob)
        #   排除: guided_extract.json / .step1_done(非固件内容)
        #         manifest 中 renamed_to 记录的文件(已被改名/解包的容器本体,
        #         避免 resume 时重复决策/解包)
        candidates = []
        for f in firmware_path.rglob("*"):
            try:
                if not f.is_file():
                    continue
            except OSError:
                continue
            rel = str(f.relative_to(firmware_path)).replace("\\", "/")
            if rel in (_MANIFEST_NAME, ".step1_done") or rel in renamed:
                continue
            candidates.append((f, 0, rel))
        if not candidates:
            print("[Step1] scan_tree: 树内无候选文件,视为完成")
    else:
        candidates = [(firmware_path, 0, firmware_path.name)]
    over_total = False
    over_guard_count = 0

    for depth in range(max_depth):
        if not candidates:
            break
        print(f"[Step1] 引导解包 层{depth}: {len(candidates)} 个候选")

        # --- 1. 决策(嗅探 + 预筛 + 规则裁决) ---
        to_extract: list[tuple[Path, str, list[str], str]] = []  # (path, rel, sigs, reason)
        # 断点续传: 已 done 的 continue 容器,其 files 作为下一层候选重建
        next_candidates: list[tuple[Path, int, str]] = []
        for path, d, rel in candidates:
            rec = manifest.get(rel)
            if rec and rec.get("done"):
                if rec.get("action") == "continue":
                    for frel in rec.get("files", []):
                        fp = output_dir / frel
                        if fp.is_file():
                            next_candidates.append((fp, d + 1, frel))
                continue  # 断点续传: 已 done 跳过

            try:
                head = path.read_bytes()[:4096]
            except OSError:
                head = b""
            sigs = sniff_magic(head, path.name)
            pc = preclassify(sigs, path.name)

            # Python SDK 容器跳过(所有模式): dist-packages/site-packages 下的
            # 压缩容器(如 botocore 的 endpoint-rule-set-1.json.gz,实测 target/1
            # 有 391 个)是 Python 包打包数据,零审计价值。不解包: 避免 391 次
            # binwalk + 解出的 JSON 污染 Step2-4(解开后不在黑名单,会被 Step4
            # 分诊误标 opaque_firmware——gzip 熵 7.8 ≥ 6.0)。
            # 最终防线是 Step2 黑名单 usr/local/lib(见 nano-ubuntu.yaml)。
            # 段级匹配(而非子串): 单文件模式 rel = 固件文件名,若固件恰叫
            # site-packages.tar.gz,子串匹配会把它误判为 SDK 容器直接吞掉。
            if "/dist-packages/" in f"/{rel}/" or "/site-packages/" in f"/{rel}/":
                manifest[rel] = {"seq": -1, "depth": d, "action": "finalize",
                                 "reason": "Python SDK 容器(dist-packages/site-packages),不解包",
                                 "sigs": sigs, "done": True}
                continue

            if pc == "skip":
                manifest[rel] = {"seq": -1, "depth": d, "action": "skip",
                                 "reason": "fdt 设备树", "done": True}
                continue
            if pc == "product":
                manifest[rel] = {"seq": -1, "depth": d, "action": "finalize",
                                 "reason": "ELF/PE/文本", "sigs": sigs, "done": True}
                continue

            # container → rule_decision 裁决
            action, reason = rule_decision(sigs, path.name, d)
            if action == "skip":
                manifest[rel] = {"seq": -1, "depth": d, "action": "skip",
                                 "reason": reason, "done": True}
            elif action == "finalize":
                manifest[rel] = {"seq": -1, "depth": d, "action": "finalize",
                                 "reason": reason, "sigs": sigs, "done": True}
            else:  # continue
                if over_total:
                    manifest[rel] = {"seq": -1, "depth": d, "action": "finalize",
                                     "reason": "全树文件数守卫", "sigs": sigs, "done": True}
                    continue
                to_extract.append((path, rel, sigs, reason))

        if not to_extract:
            # 本轮无新解包: 候选全部 finalize/skip/done。
            # 若无下一层候选生成(scan_tree 首次全 finalize 等),循环结束,
            # 否则推进到下一层候选(避免空转 max_depth 层)。
            if not next_candidates:
                break
            # 落盘: 本层新产生的 skip/finalize/SDK 记录在此提交,崩溃不丢
            # (resume 会重做,但幂等;落盘让"决策结果"持久可见)。
            _save_manifest(output_dir, manifest)
            candidates = next_candidates
            continue

        # --- 2. 并行解包(ThreadPoolExecutor) ---
        if depth + 1 >= max_depth:
            # 已达层底仍 continue: warning 而非静默强制 finalize
            print(f"[Step1] 警告: 层{depth} 仍有 {len(to_extract)} 个容器 continue,"
                  f"已达 max_depth={max_depth},记录 warning 不再解包")
            for path, rel, sigs, reason in to_extract:
                manifest[rel] = {"seq": -1, "depth": depth, "action": "finalize",
                                 "reason": f"max_depth 终局: {reason}",
                                 "sigs": sigs, "done": True}
            continue

        seqs = {id(p): next_seq + i for i, (p, *_rest) in enumerate(to_extract)}
        next_seq += len(to_extract)

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {
                ex.submit(extractor, path, seqs[id(path)], output_dir): (path, rel)
                for path, rel, _sigs, reason in to_extract
            }
            # path -> reason 映射,供 as_completed 回调写 manifest(continue 记录
            # 带决策理由,与 finalize/skip 记录字段一致)
            reasons = {id(path): reason for path, rel, _sigs, reason in to_extract}
            for fut in as_completed(futures):
                path, rel = futures[fut]
                try:
                    files, status = fut.result()
                except Exception as e:
                    print(f"[Step1] 解包异常 {rel}: {e}")
                    status, files = "failed", []
                if status == "ok":
                    # renamed_to: 容器被改名后的 rel(树根/<seq>_原名)。
                    # scan_tree resume 时, rglob 会再次找到改名文件,若不在
                    # manifest 会重复决策/解包;记录后候选初始化排除之。
                    renamed_to = f"{seqs[id(path)]:06d}_{path.name}"
                    manifest[rel] = {
                        "seq": seqs[id(path)], "depth": depth, "action": "continue",
                        "renamed_to": renamed_to,
                        "reason": reasons.get(id(path), ""),
                        "files": [str(f.relative_to(output_dir)).replace("\\", "/")
                                  for f in files],
                        "done": True,
                    }
                    total_files += len(files)
                    if total_files > resolve_max_total_files():
                        over_total = True
                        print(f"[Step1] 全树文件数守卫: 已 {total_files} 文件,停止新增解包")
                    for f in files:
                        try:
                            frel = str(f.relative_to(output_dir)).replace("\\", "/")
                        except ValueError:
                            frel = f.name
                        next_candidates.append((f, depth + 1, frel))
                elif status == "over_guard":
                    over_guard_count += 1
                    manifest[rel] = {"seq": seqs[id(path)], "depth": depth,
                                     "action": "finalize",
                                     "reason": f"单次产出>{resolve_max_files_per_extraction()} 删除",
                                     "done": True}
                    print(f"[Step1] over_guard: {rel} 产出超限,已删除")
                elif status == "empty":
                    manifest[rel] = {"seq": seqs[id(path)], "depth": depth,
                                     "action": "finalize",
                                     "reason": "binwalk/7z 均无产出(extractor 缺失或损坏)",
                                     "done": True}
                else:  # failed
                    manifest[rel] = {"seq": seqs[id(path)], "depth": depth,
                                     "action": "finalize", "reason": "解包失败",
                                     "done": True}
                    print(f"[Step1] 解包失败: {rel}")

        candidates = next_candidates
        _save_manifest(output_dir, manifest)

    _save_manifest(output_dir, manifest)

    if over_guard_count:
        print(f"[Step1] 完成: over_guard 删除 {over_guard_count} 次爆炸产物,"
              f"manifest: {output_dir / _MANIFEST_NAME}")
    else:
        print(f"[Step1] 引导解包完成 -> {output_dir}")
    return output_dir
