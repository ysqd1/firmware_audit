"""解 APP_rootfs.tar -> process/APP/extracted/,写 .step1_done(跳过 Step1 的约定标记)。

36 万条目 NTFS 落盘预计 10-20 分钟;members 已在 tar 里(无压缩,流式读)。
"""
import tarfile
import time
from pathlib import Path

TAR = Path(r"E:\固件\create\important\target\3\process\APP_rootfs.tar")
OUT = Path(r"E:\固件\create\important\target\3\process\APP\extracted")

OUT.mkdir(parents=True, exist_ok=True)
t0 = time.monotonic()
n = 0
with tarfile.open(TAR, "r") as tf:
    for m in tf:
        n += 1
        if n % 20000 == 0:
            print(f"  {n} members, {time.monotonic()-t0:.0f}s", flush=True)
        try:
            tf.extract(m, OUT, filter="data")
        except Exception as e:
            print(f"  skip {m.name}: {e}")
marker = OUT / ".step1_done"
marker.write_text("ok", encoding="utf-8")
print(f"DONE: {n} members in {time.monotonic()-t0:.0f}s; marker -> {marker}")
