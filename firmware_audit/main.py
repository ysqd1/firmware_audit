"""宇树固件审计 - 主入口。

串联 Step1-5:Step1-4 解包/过滤/分类/反编译,Step5 三 Agent 串行审计
(recon→analysis→verification;无 API key 或 API 调用失败时立即终止,不降级)。

目录约定:
    target/<N>/                  <- 输入目录(数字文件夹,如 target/1)
    ├── <firmware>               <- 固件文件(用户放入)
    ├── extracted/               <- Step1 解包结果(自动创建)
    ├── analysis/                <- Step4 反编译 C + 程序信息 JSON(合并目录,自动创建)
    └── fileinfo.json            <- FileInfo 列表(自动创建)

用法:
    python -m firmware_audit.main <target_dir>
    python -m firmware_audit.main target/1
    python -m firmware_audit.main D:\\create\\important\\target\\1

如果 target_dir/extracted/ 已存在且非空,自动跳过 Step1 直接走 Step2-4。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import FileInfo, save_fileinfos
from .step1 import step1_extract
from .step2 import step2_filter
from .step3 import step3_classify
from .step4 import step4_decompile

# workspace 下的子目录名(也作为跳过 Step1 时识别"非固件"的依据)
_EXTRACTED_DIR = "extracted"
_ANALYSIS_DIR = "analysis"   # Step4 合并目录:反编译 .c 与各 JSON 同处
_FILEINFO_FILE = "fileinfo.json"
_STEP1_DONE_MARKER = ".step1_done"   # Step1 成功后写入 extracted/ 下,用于断点续跑校验


def _extraction_looks_complete(extracted_dir: Path) -> bool:
    """校验 extracted/ 是否是一次完整解包(而非中途失败的脏目录)。

    判据:非空 且 至少有一个 *.extracted 子目录(解包器产出的标志结构)。
    纯扁平解压树(无 .extracted)仅当有 .step1_done 标记才算完整——否则
    可能是 scan_tree 失败(Docker 不可用)留下的树,不应跳过重试。
    """
    if not extracted_dir.is_dir():
        return False
    entries = list(extracted_dir.rglob("*"))
    if not entries:
        return False
    if any(p.is_dir() and p.name.endswith(".extracted") for p in entries):
        return True
    # 纯扁平解压树:旧归档树有 .step1_done(向后兼容);无标记的树视为不完整,
    # 下次重跑会重新 scan_tree(修复:Docker 恢复后嵌套容器能重试解包)。
    return (extracted_dir / ".step1_done").is_file() and len(entries) >= 20

# 常见固件扩展名(用于自动识别 target_dir 下的固件文件)
_FIRMWARE_EXTENSIONS = {
    ".bin", ".img", ".fw", ".tar", ".tar.gz", ".tar.xz", ".tar.bz2",
    ".gz", ".xz", ".bz2", ".zip", ".7z", ".squashfs", ".cramfs", ".jffs2",
    ".ubi", ".ubifs", ".rom", ".dump",
}


def _find_firmware(target_dir: Path) -> Path | None:
    """在 target_dir 顶层找固件文件。

    规则:
        1. 只扫描顶层文件(不递归),排除 extracted/ analysis/ fileinfo.json
        2. 优先匹配已知固件扩展名
        3. 若无扩展名匹配,取最大文件(>=1MB,避免误选小文件)
        4. 唯一文件直接用
    """
    skip_names = {_EXTRACTED_DIR, _ANALYSIS_DIR, _FILEINFO_FILE, "process"}
    # (path, size)。size 在循环内一次取好缓存,后续 max 排序不再触发 stat,
    # 避免损坏符号链接在别处再次抛 OSError。
    candidates: list[tuple[Path, int]] = []
    for p in target_dir.iterdir():
        # Windows 下损坏的符号链接 is_file/stat 会抛 OSError(step2_filter 已同样处理)。
        try:
            if not p.is_file():
                continue
            size = p.stat().st_size
        except OSError:
            continue  # 跳过损坏符号链接,不崩
        if p.name in skip_names:
            continue
        candidates.append((p, size))

    if not candidates:
        return None

    # 1. 扩展名匹配(支持 .tar.xz 这种双扩展)
    size_of = dict(candidates)  # path -> size,已校验缓存
    ext_matches = []
    for p, _size in candidates:
        name_lower = p.name.lower()
        for ext in _FIRMWARE_EXTENSIONS:
            if name_lower.endswith(ext):
                ext_matches.append(p)
                break
    if len(ext_matches) == 1:
        return ext_matches[0]
    if len(ext_matches) > 1:
        # 多个匹配,取最大
        return max(ext_matches, key=lambda t: size_of[t])

    # 2. 唯一文件直接用
    if len(candidates) == 1:
        return candidates[0][0]

    # 3. 取最大文件(>=1MB)
    big_enough = [t for t in candidates if t[1] >= 1024 * 1024]
    if big_enough:
        return max(big_enough, key=lambda t: t[1])[0]

    return None


def empty_filter_action(is_partition: bool) -> tuple[str, str]:
    """空分区跳过判定(小决策点,票 02):Step2 过滤后为空时如何处置。

    - 分区批次内(is_partition=True):跳过该分区、继续其余分区——单分区
      空树(如 target/3 的 RECROOTFS)曾以 sys.exit(1) 杀死整批,其余分区
      全部不再处理;空分区本身无审计价值,记录(分区名+原因)后放行。
    - 顶层单固件(is_partition=False):过滤为空即终止——顶层固件过滤为空
      意味着解包/过滤环节有问题,静默产出空报告比响亮终止更危险(语义不变)。

    Returns:
        (action, reason):action ∈ {"skip", "terminate"},reason 供日志记录。
    """
    if is_partition:
        return "skip", "Step2 过滤后为 0 文件(空分区或纯被滤系统文件)"
    return "terminate", "Step2 过滤后无文件"


def run_pipeline(
    target_dir: Path,
    max_elf: int | None = None,
    max_workers: int = 4,
    profile: str = "nano-ubuntu",
    workspace: Path | None = None,
    run_step5: bool = True,
    is_partition: bool = False,
) -> list[FileInfo]:
    """运行 Step1-4 流水线。

    Args:
        target_dir: target/<N> 目录,内含固件文件
                    (若已有完整 extracted/ 子目录则跳过 Step1)
        max_elf: Step4 只反编译前 N 个 ELF(None=全部)
        max_workers: Step4 Ghidra 并行容器数
        profile: 固件型号 profile(见 firmware_audit/profiles/),默认 nano-ubuntu
        workspace: 工作区目录。None 默认 target_dir/process;
                    磁盘镜像分区分发时传分区子文件夹本身,
                    使分区子文件夹即工作区(不自带嵌套 process/)
        run_step5: Step1-4 完成后是否跑 Step5 Agent 审计(默认跑)
        is_partition: 本次运行是多分区批次的分区子工作区(分区递归内部传 True)。
                    Step2 过滤为空时跳过该分区返回 [](不 sys.exit 杀整批),
                    顶层固件仍终止——见 empty_filter_action

    Returns:
        填充完整的 FileInfo 列表
    """
    target_dir = Path(target_dir).resolve()
    if not target_dir.is_dir():
        print(f"错误: 目标目录不存在: {target_dir}")
        sys.exit(1)

    # workspace 默认 = target_dir/process(统一工作区,无论固件类型都强制创建):
    #   单一固件: process/extracted/ + process/analysis/ + process/fileinfo.json
    #   磁盘镜像: process/<分区名>/ 各自自包含(分区文件 + extracted/ + analysis/ + fileinfo.json)
    workspace = Path(workspace).resolve() if workspace else target_dir / "process"
    workspace.mkdir(parents=True, exist_ok=True)
    print(f"[main] 工作区: {workspace}")

    extracted_dir = workspace / _EXTRACTED_DIR
    step1_marker = extracted_dir / _STEP1_DONE_MARKER
    guided_manifest = extracted_dir / "guided_extract.json"

    # Step1 解包(若已完成则跳过)
    #   优先认 .step1_done 标志;引导解包 manifest 存在 → 续解(resume);
    #   无标志但结构看起来完整(向后兼容旧解包)也跳过;
    #   结构不完整(脏目录)则清空重跑。
    skip_step1 = False
    resume_guided = False
    if step1_marker.exists():
        skip_step1 = True
    elif guided_manifest.exists():
        # 引导解包中途中断: 续解,不清空目录(旧产物是续解基础)
        resume_guided = True
        print("[main] 发现引导解包 manifest,续解 Step1(resume)")
    elif extracted_dir.is_dir() and _extraction_looks_complete(extracted_dir):
        skip_step1 = True
        print("[main] 提示: 无 .step1_done 标志但解包结构完整,跳过 Step1(向后兼容)")

    if skip_step1:
        print(f"[main] 跳过 Step1,使用已有解包: {extracted_dir}")
        extracted_root = extracted_dir
    else:
        # 旧/脏目录清理后重跑,避免半解包文件混入。
        # resume 模式不清空: 引导解包续解需要旧产物。
        if (extracted_dir.is_dir() and any(extracted_dir.iterdir())
                and not resume_guided):
            print(f"[main] extracted/ 不完整,清理后重跑 Step1: {extracted_dir}")
            import shutil as _shutil
            _shutil.rmtree(extracted_dir, ignore_errors=True)

        from .step1 import step1_guided_extract

        if resume_guided:
            # 引导解包续解: 固件文件可能已被改名进解包树,不找固件、不再 preprocess。
            # resume 模式: extract_guided 从 manifest 重建候选树续解。
            print("[main] resume: 引导解包续解(固件文件可能已改名,跳过识别/preprocess)")
            extracted_root = step1_guided_extract.extract_guided(
                Path("resume"), extracted_dir, max_workers=8, resume=True)
            if extracted_root is None:
                print("[main] 引导解包 resume 失败,终止")
                sys.exit(1)
            if not step1_extract.verify(extracted_root):
                print("[main] Step1 验证失败: 解包目录为空")
                sys.exit(1)
            step1_marker.write_text("ok", encoding="utf-8")
        else:
            firmware_path = _find_firmware(target_dir)
            if firmware_path is None:
                print(f"[main] 在 {target_dir} 下未找到固件文件")
                sys.exit(1)
            print(f"[main] 识别固件: {firmware_path.name}")

            # Step0 预解压:宿主 Python 解常见压缩,避开 binwalk 解压层 bug。
            # 归档类(zip/tar*)解出文件系统 → skip_binwalk=True,引导解包器树扫描;
            # 磁盘镜像(几百 GB .img)→ 分区提取 → 每个分区独立子工作区跑 Step1-4;
            # 单文件压缩(gz/bz2/xz)/其他 → 交引导解包器(单文件模式)。
            from .step0 import step0_preprocess
            pre_inputs, skip_binwalk = step0_preprocess.preprocess(
                firmware_path, extracted_dir
            )

            if skip_binwalk:
                # 归档已解出文件系统,但树内仍可能有嵌套容器(子目录
                # .gz/.img/bootimg 等)。引导解包器树扫描继续解(自动跳过
                # Python SDK 容器,如 botocore 的 endpoint-rule-set gz);
                # 失败回退直接用树,不阻塞。
                tree_root = pre_inputs[0]
                extracted_root = step1_guided_extract.extract_guided(
                    tree_root, tree_root, max_workers=8, scan_tree=True)
                if extracted_root is None:
                    # scan_tree 失败(Docker 不可用等): 回退用树继续,但
                    # 不写 .step1_done——否则下次重跑 skip_step1,树内嵌套
                    # 容器永久不解(修复:恢复 Docker 后重跑会重新 scan_tree)。
                    # 注意: 必须赋值 extracted_root = tree_root,否则后续
                    # Step2 拿到 None 崩溃(实测 bug)。
                    extracted_root = tree_root
                    print("[main] 警告: 引导解包树扫描失败(Docker 不可用?),"
                          "本次用解压树直接继续,嵌套容器未解;"
                          "恢复 Docker 后重跑本命令会重新扫描")
                else:
                    step1_marker.write_text("ok", encoding="utf-8")
                    print(f"[main] Step0 预解压完成 + 引导解包树扫描,使用: {extracted_root}")
            elif not pre_inputs:
                # 磁盘镜像有分区表但所有分区均未产出(如 ext4 直读失败且无其他
                # 分区):Step0 特意不回退整盘 binwalk(几百 GB 会爆炸),响亮终止
                print("[main] Step0 有分区表但所有分区均未产出(直读失败/被筛),终止")
                print("[main] 提示: 安装 debugfs(e2fsprogs)或配置免密 sudo 用 "
                      "STEP0_EXT4_BACKEND=mount 后重跑")
                sys.exit(1)
            elif len(pre_inputs) > 1 or any(p.is_dir() for p in pre_inputs):
                # 磁盘镜像:每个分区独立工作区(process/<分区名>/,自包含),
                # 递归跑完整流水线。为什么独立: 多个分区的解包产物(如 etc/passwd)
                # 若合并进同一 extracted/ 会 rel_path 冲突、去重互相误删;
                # 分区各自 fileinfo.json/analysis/ 也便于审计报告分块。
                # 条件含 is_dir: Step0 ext4 直读产物是子工作区目录(extracted/ +
                # .step1_done 已就位),单目录(单 ext4 分区镜像)也必须走递归。
                print(f"[main] 磁盘镜像识别出 {len(pre_inputs)} 个分区,逐个审计:")
                all_infos: list[FileInfo] = []
                skipped_parts: list[str] = []
                for pf in pre_inputs:
                    stem = Path(pf).stem
                    sub_target = workspace / stem
                    sub_target.mkdir(parents=True, exist_ok=True)
                    if pf.is_dir():
                        # ext4 直读子工作区:Step1 已由直读完成(树+标记),
                        # 无分区文件可 move,直接复用该工作区跑 Step2-5
                        print(f"[main] === 分区工作区(ext4 直读): {sub_target} ===")
                    else:
                        dst = sub_target / pf.name
                        if not dst.exists():
                            # 同盘 rename 零拷贝;已存在说明上次跑过,直接复用续传
                            import shutil as _shutil
                            _shutil.move(str(pf), str(dst))
                        print(f"[main] === 分区工作区: {sub_target} ===")
                    infos = run_pipeline(
                        sub_target,
                        max_elf=max_elf,
                        max_workers=max_workers,
                        profile=profile,
                        workspace=sub_target,  # 分区子文件夹即工作区,不自带嵌套 process/
                        run_step5=run_step5,
                        is_partition=True,
                    )
                    if not infos:
                        # 票 02:空分区返回 [](Step2 过滤为 0,成因已当场记录),
                        # 名单批次末汇总
                        skipped_parts.append(stem)
                    all_infos.extend(infos)
                if skipped_parts:
                    # 汇总口径取"未产出可审计文件"而非具体成因:递归返回 [] 的
                    # 路径今后可能不止 Step2 过滤为空(如嵌套磁盘镜像整批跳过),
                    # 各分区自己的成因在跳过当场已按分区名记录
                    print(f"[main] 批次汇总: 跳过 {len(skipped_parts)}/{len(pre_inputs)} "
                          f"个分区(未产出可审计文件): {', '.join(skipped_parts)}")
                print(f"[main] 所有分区审计完成,共 {len(all_infos)} 个文件")
                return all_infos
            else:
                # 引导解包(规则版)为主;失败回退旧 binwalk -Me(内部兜底)
                extracted_root = step1_guided_extract.extract_guided(
                    pre_inputs[0], extracted_dir, max_workers=8)
                if extracted_root is None:
                    print("[main] 引导解包失败,回退旧 binwalk -Me")
                    extracted_root = step1_extract.extract(pre_inputs[0], extracted_dir)
                if extracted_root is None:
                    print("[main] Step1 解包失败,终止")
                    sys.exit(1)
                if not step1_extract.verify(extracted_root):
                    print("[main] Step1 验证失败: 解包目录为空")
                    sys.exit(1)
                # 写完成标志,供下次断点续跑校验
                step1_marker.write_text("ok", encoding="utf-8")

    # Step2 过滤(profile 指定名单,默认 nano-ubuntu)
    files = step2_filter.filter_files(extracted_root, profile=profile)
    if not files:
        # 票 02:分区批次内空分区跳过续批(记录分区名+原因),顶层固件仍终止
        action, reason = empty_filter_action(is_partition)
        if action == "skip":
            print(f"[main] 分区 {target_dir.name}: {reason},记录跳过,其余分区继续")
            return []
        print(f"[main] {reason},终止")
        sys.exit(1)

    # 认证无标记解包树:兼容路径(无 .step1_done 但结构完整)已通过 Step2,
    # 补写标记——否则每次重跑都重新遍历/确认(实测 part05 61.6 万条目树
    # 反复触发"向后兼容"分支,且无标记可能误触发 binwalk 重解)。
    if not step1_marker.exists():
        step1_marker.write_text("ok", encoding="utf-8")
        print(f"[main] 认证解包树(无标记但结构完整),补写 {step1_marker.name}")

    # Step3 分类
    fileinfos = step3_classify.classify(files, extracted_root)

    # Step4 反编译/提取
    fileinfos = step4_decompile.decompile(
        fileinfos, workspace, max_elf=max_elf, max_workers=max_workers
    )

    # Save FileInfo
    fileinfo_path = workspace / _FILEINFO_FILE
    save_fileinfos(fileinfos, fileinfo_path)
    print(f"[main] FileInfo 已保存: {fileinfo_path}")

    # Step5 Agent 审计(recon→analysis→verification 串行;无 API key 或
    # API 调用失败立即终止不降级;工件齐备时断点跳过)。workspace 即 process 等价目录,
    # 分区子工作区同样适用(递归调用里各自跑各自的 Step5)。
    if run_step5:
        from .step5_agent import step5_run
        from .step5_agent.providers.llm_client import LLMError
        try:
            s5 = step5_run(workspace)
            print(f"[main] Step5 完成({s5['mode']}): {s5['report']}")
        except LLMError as e:
            print(f"[main] Step5 终止(无 API key 或 API 调用失败): {e}")
        except (FileNotFoundError, ValueError) as e:
            print(f"[main] Step5 未执行: {e}")
    else:
        print("[main] 跳过 Step5(--no-step5);可随时用 "
              "python -m firmware_audit.step5_agent.run_step5 <target> 补跑")

    return fileinfos


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="宇树固件审计 - Step1-4 流水线",
    )
    parser.add_argument(
        "target_dir",
        help="target/<N> 目录(如 target/1),内含固件文件",
    )
    parser.add_argument(
        "--max-elf", type=int, default=None,
        help="Step4 只反编译前 N 个 ELF(默认全部)。控制固件含大量 ELF 时的总时长",
    )
    parser.add_argument(
        "--max-workers", type=int, default=4,
        help="Step4 Ghidra 并行容器数(默认 4)",
    )
    parser.add_argument(
        "--profile", type=str, default="nano-ubuntu",
        help="固件型号 profile(默认 nano-ubuntu,位于 firmware_audit/profiles/)",
    )
    parser.add_argument(
        "--no-step5", action="store_true",
        help="跳过 Step5 Agent 审计(可稍后用 step5_agent.run_step5 补跑)",
    )
    args = parser.parse_args(argv)

    target_dir = Path(args.target_dir).resolve()
    run_pipeline(
        target_dir,
        max_elf=args.max_elf,
        max_workers=args.max_workers,
        profile=args.profile,
        run_step5=not args.no_step5,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
