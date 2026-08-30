"""Step2 过滤单元测试:hex 偏移前缀剥离 / DTB 节点过滤 / 过滤集成。

覆盖 2026-08-12 修的 part05 卡死根因:
  1. binwalk 3.1.1 偏移目录是 hex(2919000/13DE7F0),旧正则只剥数字 → 白名单全 miss
  2. 设备树(fdt)分解节点(bus@0/aconnect@2a41000/.../phandle)数十万级纯噪声,
     必须在过滤最前排除
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from ..file_rules import logical_path
from ..step2.step2_filter import (
    _is_dtb_node,
    _is_elf_dup_candidate,
    _is_base_name,
    _dedup_by_content,
    filter_files,
)


def test_logical_path_hex_prefix() -> list[str]:
    """binwalk hex 偏移目录(2919000)应剥掉,数字目录(0)与 squashfs-root 兼容。"""
    fails: list[str] = []
    cases = [
        # binwalk 3.1.1 hex 偏移目录 + 深解 rootfs
        ("part05_B_kernel.img.extracted/2919000/decompressed.bin.extracted/0/etc/passwd",
         "etc/passwd"),
        # 浅解包(kernel 分区):hex 目录 + 单个文件
        ("part02_A_kernel.img.extracted/13DE7F0/decompressed.bin", "decompressed.bin"),
        # 旧 binwalk 数字目录(兼容)
        ("nano14-backup-SANITIZED.tar.xz.extracted/0/decompressed.bin.extracted/0/etc/passwd",
         "etc/passwd"),
        # squashfs-root 剥前缀
        ("root.squashfs.extracted/0/squashfs-root/etc/passwd", "etc/passwd"),
        # 7z 兜底扁平解包(引导解包器 binwalk 无 extractor 的容器走 7z):
        # 无偏移段,<seq>_x.cpio.extracted/ 直接接逻辑路径(2026-08-14 评审修复)
        ("000005_x.cpio.extracted/etc/passwd", "etc/passwd"),
        # 非解包路径原样返回
        ("etc/passwd", "etc/passwd"),
    ]
    for rel, want in cases:
        got = logical_path(rel)
        if got != want:
            fails.append(f"{rel} -> {got},期望 {want}")
    return fails


def test_is_dtb_node() -> list[str]:
    """DTB 节点路径(bus@0/...)应识别;rootfs/模块路径不应误判。"""
    fails: list[str] = []
    dtb_paths = [
        # 实测 part05 树的真实节点路径
        "0/bus@0/aconnect@2900000/ahub@2900800/ports/port@0/endpoint/phandle",
        "bus@0/aconnect@2a41000/ahub/ports/port@0/endpoint/remote-endpoint",
        "rail@vdd_soc/bin@1599/value",
        "i2c@0/imx185_a@1a/power",
        "aconnect@2a41000/ahub",
    ]
    keep_paths = [
        # rootfs/模块/普通文件
        "0/usr/lib/modules/5.15.148-tegra/updates/drivers/net/ethernet/nvidia/nvethernet/nvethernet.ko",
        "0/etc/passwd",
        "0/usr/bin/system_ipconfig",
        "decompressed.bin",
        "0/etc/network/interfaces",
    ]
    for p in dtb_paths:
        if not _is_dtb_node(p):
            fails.append(f"DTB 节点未识别: {p}")
    for p in keep_paths:
        if _is_dtb_node(p):
            fails.append(f"正常路径被误判 DTB: {p}")
    return fails


def test_filter_excludes_dtb(tmp_path: Path) -> list[str]:
    """集成:构造含 DTB 节点 + rootfs 的树,filter_files 应排除 DTB 保留 rootfs。"""
    fails: list[str] = []
    root = tmp_path / "extracted"
    base = root / "part05_B_kernel.img.extracted" / "2919000" / "decompressed.bin.extracted" / "0"
    (base / "etc").mkdir(parents=True)
    (base / "usr" / "lib" / "modules").mkdir(parents=True)
    dtb = base / "bus@0" / "aconnect@2a41000" / "ports" / "port@0" / "endpoint"
    dtb.mkdir(parents=True)
    (base / "etc" / "passwd").write_text("root:x:0:0\n", encoding="utf-8")
    (base / "usr" / "lib" / "modules" / "nvethernet.ko").write_bytes(
        b"\x7fELF" + b"\x00" * 60)
    (dtb / "phandle").write_bytes(b"\x00\x01\x02\x03")
    (base / "usr" / "lib" / "modules" / "nvethernet.ko.md5").write_text("abc\n",
                                                                       encoding="utf-8")

    kept = filter_files(root)
    kept_names = [p.name for p in kept]
    if "passwd" not in kept_names:
        fails.append("etc/passwd 应保留(白名单)")
    if "nvethernet.ko" not in kept_names:
        fails.append("nvethernet.ko 应保留(默认放行)")
    if any("phandle" in p.name for p in kept):
        fails.append("DTB 节点 phandle 应被排除")
    return fails


def test_is_elf_dup_candidate() -> list[str]:
    """ELF 去重候选判定: .so/.so.N/.ko/.elf 是;.bin/.out/文本不是。"""
    fails: list[str] = []
    yes = ["libddsc.so", "libddsc.so.0", "libglog.so.0.5.0",
           "module.ko", "app.elf", "liblcm.so.1"]
    no = ["app.bin", "config.json", "data.out", "passwd", "libddsc.so.bak"]
    for n in yes:
        if not _is_elf_dup_candidate(n):
            fails.append(f"{n} 应判为 ELF 去重候选")
    for n in no:
        if _is_elf_dup_candidate(n):
            fails.append(f"{n} 不应判为 ELF 去重候选")
    return fails


def test_is_base_name() -> list[str]:
    """基础名择优: .so > .so.N > .so.N.M。"""
    fails: list[str] = []
    cases = [
        ("libddsc.so", "libddsc.so.0", True),      # .so 优先
        ("libddsc.so.0", "libddsc.so", False),
        ("libglog.so.0", "libglog.so.0.5.0", True),  # 版本段短优先
        ("libglog.so.0.5.0", "libglog.so.0", False),
        ("libddsc.so", "libddsc.so", False),         # 同名
        ("liblcm.so.1", "liblcm.so.2", False),       # 同长度版本,保留先到
    ]
    for a, b, want in cases:
        got = _is_base_name(a, b)
        if got != want:
            fails.append(f"_is_base_name({a},{b}) -> {got},期望 {want}")
    return fails


def test_dedup_by_content(tmp_path: Path) -> list[str]:
    """集成: md5 相同的库副本去重,基础名保留;非库不去重。"""
    fails: list[str] = []
    d = tmp_path / "t"
    d.mkdir()
    # 三份相同内容的不同库名
    content = b"\x7fELF" + b"\x00" * 100 + b"same-payload"
    libs = ["libddsc.so", "libddsc.so.0", "libddsc.so.0.5.0"]
    paths = []
    for n in libs:
        p = d / n
        p.write_bytes(content)
        paths.append(p)
    # 非库文件(同内容但应保留)
    cfg1 = d / "a.json"
    cfg2 = d / "b.json"
    cfg1.write_bytes(b'{"x":1}')
    cfg2.write_bytes(b'{"x":1}')

    kept = _dedup_by_content(paths + [cfg1, cfg2])
    names = [p.name for p in kept]

    # 库只留基础名 libddsc.so
    if names.count("libddsc.so") != 1:
        fails.append(f"libddsc.so 应保留 1 份,实得 {names.count('libddsc.so')}")
    if "libddsc.so.0" in names or "libddsc.so.0.5.0" in names:
        fails.append(f"版本副本应被去重,实得 {names}")
    # 非库同内容文件不去重
    if "a.json" not in names or "b.json" not in names:
        fails.append(f"非库文件不应去重: {names}")
    return fails


def test_main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="test_step2_") as tmp:
        tmp_path = Path(tmp)
        groups = [
            ("hex偏移前缀剥离", test_logical_path_hex_prefix()),
            ("DTB节点识别", test_is_dtb_node()),
            ("DTB集成过滤", test_filter_excludes_dtb(tmp_path)),
            ("ELF去重候选判定", test_is_elf_dup_candidate()),
            ("基础名择优", test_is_base_name()),
            ("ELF内容去重集成", test_dedup_by_content(tmp_path)),
        ]
        for name, fl in groups:
            if fl:
                failures += len(fl)
                for msg in fl:
                    print(f"[FAIL] {name}: {msg}")
            else:
                print(f"[PASS] {name}")

    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())
