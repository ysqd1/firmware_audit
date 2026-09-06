"""APP 分区流水线驱动(不改 firmware_audit,只调用其公共函数,流程与 main.py 一致)。

背景: Step0 的 _PARTITION_MAX_SIZE_GB=50 会跳过 237.71GiB 的 APP 分区,
本驱动把 WSL 导出的 rootfs 树(process/APP/extracted/,带 .step1_done)直接
接入 Step2-4。用法:
    python app_pipeline_driver.py s23           # Step2+3,存 fileinfo.json,打印直方图
    python app_pipeline_driver.py s4 <max_elf>  # Step4(断点续传),max_elf=-1=全部
"""
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent
WS = REPO / "target" / "3" / "process" / "APP"


def s23() -> None:
    from firmware_audit.step2 import step2_filter
    from firmware_audit.step3 import step3_classify
    from firmware_audit.models import save_fileinfos

    extracted = WS / "extracted"
    files = step2_filter.filter_files(extracted, profile="nano-ubuntu")
    print(f"[driver] Step2 保留 {len(files)} 文件")
    c = Counter(p.relative_to(extracted).parts[0] for p in files)
    print("[driver] Step2 顶层目录分布:")
    for k, v in c.most_common(30):
        print(f"    {k:25s} {v}")
    fileinfos = step3_classify.classify(files, extracted)
    t = Counter(fi.type for fi in fileinfos)
    print("[driver] Step3 类型分布:")
    for k, v in t.most_common():
        print(f"    {k:20s} {v}")
    save_fileinfos(fileinfos, WS / "fileinfo.json")
    print(f"[driver] fileinfo.json -> {WS / 'fileinfo.json'}")


def s4(max_elf: int) -> None:
    from firmware_audit.step4 import step4_decompile
    from firmware_audit.models import load_fileinfos, save_fileinfos

    fileinfos = load_fileinfos(WS / "fileinfo.json")
    n = None if max_elf < 0 else max_elf
    fileinfos = step4_decompile.decompile(fileinfos, WS, max_elf=n, max_workers=4)
    save_fileinfos(fileinfos, WS / "fileinfo.json")
    print("[driver] Step4 完成,fileinfo.json 已回写")


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "s23":
        s23()
    elif cmd == "s4":
        s4(int(sys.argv[2]))
    else:
        raise SystemExit(f"未知子命令: {cmd}")
