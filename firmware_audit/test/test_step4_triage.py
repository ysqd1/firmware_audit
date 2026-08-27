"""Step4 不透明固件分诊单测(不依赖 Docker/网络)。

覆盖 2026-08-13 实测校准的分诊判定:
  - Intel HEX / S-record → firmware_hex / firmware_srec
  - IFLY/LJU → voice_resource
  - eGON(dd cc bb aa)→ allwinner_boot0
  - RITE → opaque_privformat
  - 高熵 >= 6.0 → opaque_firmware
  - text 类入口: Intel HEX 被 Step3 归 text 后,分诊仍能通过嗅探接入
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from ..models import FileInfo
from ..step4.triage import (
    sniff_firmware_kind,
    triage_opaque,
    _hex_to_bin,
    _srec_to_bin,
)


def _hex_line(rectype: int, addr: int, data: bytes) -> bytes:
    """构造一条 Intel HEX 记录(带校验和)。"""
    body = bytes([len(data)]) + addr.to_bytes(2, "big") + bytes([rectype]) + data
    checksum = (-sum(body)) & 0xFF
    return b":" + body.hex().encode() + f"{checksum:02X}".encode()


def _intel_hex_sample() -> bytes:
    """真实 Intel HEX 样例: 16 字节 data + EOF。"""
    return _hex_line(0x00, 0x0000, bytes(range(16))) + b"\n" + _hex_line(0x01, 0, b"") + b"\n"


def _srec_line(rectype: int, addr_hex: str, data: bytes) -> bytes:
    """构造合法 S-record 行: count = 地址字节数 + 数据 + 校验和(1)。"""
    count = len(addr_hex) // 2 + len(data) + 1
    body = addr_hex + data.hex()
    # 校验和: 使 count+addr+data+checksum 低字节和为 0xFF(标准)
    checksum = (0xFF - (count + sum(bytes.fromhex(body))) & 0xFF) & 0xFF
    return (f"S{rectype}".encode() + f"{count:02X}".encode()
            + body.encode() + f"{checksum:02X}".encode())


def test_sniff_firmware_kind() -> list[str]:
    fails: list[str] = []
    cases = [
        (_intel_hex_sample(), "firmware_hex"),
        (_srec_line(0, "0000", b"\x00" * 18) + b"\n", "firmware_srec"),
        (b"IFLY\x1cLJU" + b"\x00" * 60, "voice_resource"),
        (b"\xdd\xcc\xbb\xaa" + b"\x00" * 60, "allwinner_boot0"),
        (b"RITE0006" + b"\x00" * 60, "opaque_privformat"),
        # 高熵随机字节(>6.0)
        (bytes(range(256)) * 16, "opaque_firmware"),
        # 低熵文本(<6.0)
        (b"hello world plain text\n" * 20, "opaque_unknown"),
        (b"", "opaque_unknown"),
    ]
    for data, want in cases:
        kind, reason = sniff_firmware_kind(data)
        if kind != want:
            fails.append(f"sniff_firmware_kind({data[:16]!r}) -> {kind},期望 {want} ({reason})")
    return fails


def test_text_entry_via_sniff(tmp_path: Path) -> list[str]:
    """Intel HEX 被 Step3 归 text 后,分诊仍能通过嗅探接入(评审批评 1 回归)。"""
    fails: list[str] = []
    workspace = tmp_path / "ws"
    workspace.mkdir()
    fw = workspace / "cn.hex"
    fw.write_bytes(_intel_hex_sample())
    fi = FileInfo(path=str(fw), rel_path="cn.hex", type="text")  # Step3 归 text

    # 模拟 step4 的 text 嗅探入口: 4KB 嗅探命中 hex → triage
    from ..step4.triage import sniff_firmware_kind as sniff
    kind, _ = sniff(fw.read_bytes()[:4096])
    if kind != "firmware_hex":
        fails.append(f"text 类 cn.hex 嗅探 -> {kind},期望 firmware_hex")

    ok = triage_opaque(fi, workspace)
    if not ok:
        fails.append("triage_opaque 返回 False")
    triage_file = workspace / "analysis" / "cn.hex.triage.json"
    if not triage_file.exists():
        fails.append("triage.json 未生成")
    else:
        d = json.loads(triage_file.read_text(encoding="utf-8"))
        if d["triage_type"] != "firmware_hex":
            fails.append(f"triage.json type={d['triage_type']},期望 firmware_hex")
        if d["converted_path"]:
            conv = Path(d["converted_path"])
            if not conv.exists():
                fails.append(f"转换产物不存在: {conv}")
    if fi.audit_status != "suspicious":
        fails.append(f"audit_status={fi.audit_status},期望 suspicious")
    return fails


def test_hex_srec_to_bin(tmp_path: Path) -> list[str]:
    """Intel HEX / S-record → 二进制转换。"""
    fails: list[str] = []
    ws = tmp_path / "conv"
    ws.mkdir()
    # HEX: 0x0000 处 16 字节
    binp = _hex_to_bin(_intel_hex_sample(), ws, "cn.hex")
    if binp is None or not binp.exists():
        fails.append("_hex_to_bin 失败")
    else:
        if binp.read_bytes() != bytes(range(16)):
            fails.append("_hex_to_bin 内容错误")
    # S-record: S1 记录 0x1000 处 4 字节
    data = bytes([0x11, 0x22, 0x33, 0x44])
    srec_line = _srec_line(1, "1000", data)
    binp2 = _srec_to_bin(srec_line + b"\n", ws, "fw.srec")
    if binp2 is None or not binp2.exists():
        fails.append("_srec_to_bin 失败")
    else:
        if binp2.read_bytes()[0x1000:0x1004] != data:
            fails.append("_srec_to_bin 内容/地址错误")
    return fails


def test_triage_not_crash(tmp_path: Path) -> list[str]:
    """读失败/空文件不崩。"""
    fails: list[str] = []
    ws = tmp_path / "ws2"
    ws.mkdir()
    fi = FileInfo(path=str(ws / "missing.bin"), rel_path="missing.bin", type="unknown")
    if triage_opaque(fi, ws):
        fails.append("文件不存在不应返回 True")
    empty = ws / "empty.bin"
    empty.write_bytes(b"")
    fi2 = FileInfo(path=str(empty), rel_path="empty.bin", type="unknown")
    if triage_opaque(fi2, ws):
        fails.append("空文件不应返回 True")
    return fails


def test_main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="test_step4_triage_") as tmp:
        tmp_path = Path(tmp)
        groups = [
            ("分诊类型嗅探", test_sniff_firmware_kind()),
            ("text 类入口接入", test_text_entry_via_sniff(tmp_path)),
            ("hex/srec 转二进制", test_hex_srec_to_bin(tmp_path)),
            ("读失败/空文件不崩", test_triage_not_crash(tmp_path)),
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
