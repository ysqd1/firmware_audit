"""Step4 - 不透明固件分诊(unknown/可疑 text 文件的处置)。

背景(2026-08-13 实测校准): target/1 的固件 .bin(flashboot/master/respak/
script/E_Go2_DRV)经 file 识别为 data → Step3 归 unknown → 旧代码无 handler
静默跳过,审计员完全看不到。另有 cn.hex(Intel HEX 固件)被 file 识别为
"ASCII text" → Step3 归 text,同样掩盖固件身份。

本模块对这两类文件做纯规则分诊,绝不再静默消失:
  - 入口: fi.type == "unknown",或 fi.type 是 text 但 4KB 嗅探命中 hex/srec 签名
  - 判定(实测校准,勿拍脑袋改):
      Intel HEX 首行 ":" + 行校验   → firmware_hex(hex→bin 落盘)
      Motorola S-record "S0/S1/..." → firmware_srec(同上转换)
      "IFLY"/"LJU" 段               → voice_resource(讯飞语音包)
      eGON 头 "dd cc bb aa" + CRC  → allwinner_boot0
      "RITE" 前缀                   → opaque_privformat
      Shannon 熵 >= 6.0            → opaque_firmware(疑似 MCU 固件)
      其他                          → opaque_unknown
  全部 audit_status="suspicious",写 analysis/<rel>.triage.json。
"""
from __future__ import annotations

from pathlib import Path

from ..models import FileInfo
from ..step1.file_magic import shannon_entropy

# --- 签名表(实测校准) ---
# respak.bin: 头 "IFLY\x1cLJU"(0x49464C59 1C4C4A55),段名 KEY1/KEY2/WAKE/CAEM/ESRM/INFO
_IFLY_MAGIC = b"IFLY"
_LJU_MAGIC = b"LJU"
# flashboot.bin: eGON boot0 头(Allwinner)
_EGON_MAGIC = b"\xdd\xcc\xbb\xaa"
# script.bin: RITE0006 + MATZ/IREP 段(私有脚本字节码)
_RITE_MAGIC = b"RITE"

# 熵阈值(实测: master 6.78 / flashboot 6.58 / respak 6.06 / E_Go2_DRV 7.98;
# ELF 对照 5.8,文本对照 4.8。7.5 会漏 master/flashboot/respak,故定 6.0)
_ENTROPY_THRESHOLD = 6.0
# 熵采样字节数
_ENTROPY_SAMPLE = 65536
# 文件头采样(签名嗅探 + triage.json 记录)
_HEAD_SAMPLE = 4096
# S-record 转换二进制最大地址上限(MCU 固件通常 <= 16MB;防恶意/损坏记录
# 的 0xFFFFFFFF 地址触发 4GB 内存扩展,见 _srec_to_bin)
_MAX_SREC_BIN_SIZE = 16 * 1024 * 1024


def sniff_firmware_kind(data: bytes, fname: str = "") -> tuple[str, str]:
    """嗅探不透明文件的分诊类型。

    Returns:
        (type, reason):
            firmware_hex / firmware_srec / voice_resource / allwinner_boot0 /
            opaque_privformat / opaque_firmware / opaque_unknown
    """
    if not data:
        return "opaque_unknown", "空文件"

    # Intel HEX: 首行以 ":" 开头,长度+校验和
    if _looks_like_intel_hex(data):
        return "firmware_hex", "Intel HEX 固件(ASCII 文本伪装)"
    # Motorola S-record
    if _looks_like_srec(data):
        return "firmware_srec", "Motorola S-record 固件"

    # 私有/已知签名
    if data.startswith(_IFLY_MAGIC) and _LJU_MAGIC in data[:64]:
        return "voice_resource", "讯飞语音资源包(IFLY/LJU 段)"
    if data.startswith(_EGON_MAGIC):
        return "allwinner_boot0", "Allwinner eGON boot0(带签名头)"
    if data.startswith(_RITE_MAGIC):
        return "opaque_privformat", "RITE 私有脚本字节码"

    # 熵判定
    e = shannon_entropy(data[:_ENTROPY_SAMPLE])
    if e >= _ENTROPY_THRESHOLD:
        return "opaque_firmware", f"疑似 MCU 固件/加密内容(熵 {e:.2f} >= {_ENTROPY_THRESHOLD})"
    return "opaque_unknown", f"低熵未识别二进制(熵 {e:.2f})"


def _looks_like_intel_hex(data: bytes) -> bool:
    """Intel HEX: 首行以 ':' 开头,且行长度字段与字节数吻合。

    行格式 :LLAAAATT<2*LL hex>CC,总长 = 1 + 2 + 4 + 2 + 2*LL + 2 = 11 + 2*LL。
    """
    if not data.startswith(b":"):
        return False
    # 第一行(到 \n): :LLAAAATT... 校验和
    line = data.split(b"\n", 1)[0].strip(b"\r")
    if len(line) < 11:
        return False
    try:
        length = int(line[1:3], 16)
        if 11 + length * 2 != len(line):
            return False
        # 校验和: 解析为二进制后,所有字节和 & 0xFF == 0
        raw = bytes.fromhex(line[1:].decode())
        if sum(raw) & 0xFF != 0:
            return False
    except ValueError:
        return False
    return True


def _looks_like_srec(data: bytes) -> bool:
    """Motorola S-record: 首行以 S0/S1/S2/S3... 开头,行长度吻合。"""
    if len(data) < 4:
        return False
    if data[:1] != b"S" or data[1:2] not in (b"0", b"1", b"2", b"3", b"5", b"7", b"8", b"9"):
        return False
    try:
        length = int(data[2:4], 16)
        line = data.split(b"\n", 1)[0].strip(b"\r")
        if length * 2 + 4 != len(line):
            return False
    except ValueError:
        return False
    return True


def triage_opaque(fi: FileInfo, workspace: Path) -> bool:
    """对不透明文件分诊,写 analysis/<rel>.triage.json。

    Returns:
        True 已分诊(含 unknown),False 文件不可读/为空(不崩)。
    """
    import json

    p = Path(fi.path)
    try:
        head = p.read_bytes()[:_HEAD_SAMPLE]
    except OSError:
        return False
    if not head:
        return False

    kind, reason = sniff_firmware_kind(head, p.name)

    # hex/srec → 转二进制落盘(供 Ghidra ARM 加载)
    converted_path = ""
    if kind in ("firmware_hex", "firmware_srec"):
        try:
            full = p.read_bytes()
        except OSError:
            full = b""
        if kind == "firmware_hex":
            bin_path = _hex_to_bin(full, workspace, p.name)
        else:
            bin_path = _srec_to_bin(full, workspace, p.name)
        if bin_path:
            converted_path = str(bin_path)
            reason += f",已转二进制: {bin_path.name}"

    fi.audit_status = "suspicious"
    # 追加而非覆写: text_hex 类文件(cn.hex)先进过 _scan_text 填了文本发现,
    # 覆写会丢失文本扫描结果(fileinfo 里只剩分诊条目;盘上 .text.json 虽在,
    # 但 fileinfo 是 Step5 消费的索引)。分诊条目放最后,与文本发现共存。
    fi.findings = list(fi.findings) + [{
        "type": kind,
        "match": reason,
        "line": 0,
    }]

    out = workspace / "analysis" / f"{fi.rel_path}.triage.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({
            "path": fi.rel_path,
            "triage_type": kind,
            "reason": reason,
            "entropy": round(shannon_entropy(head[:_ENTROPY_SAMPLE]), 3),
            "head_hex": head[:64].hex(),
            "converted_path": converted_path,
            "size": fi.size,
        }, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError as e:
        # 写盘失败(磁盘满/权限): 失败不崩,与读文件路径一致。
        # 注意: findings/audit_status 已在上面填充,fileinfo 仍会记录分诊结果。
        print(f"[Step4] 分诊产物写盘失败({fi.rel_path}): {e}")
        return False
    return True


def _hex_to_bin(data: bytes, workspace: Path, name: str) -> Path | None:
    """Intel HEX → 二进制。解析 :LLAAAATT<data>CC 记录,失败返回 None(不崩)。"""
    out = workspace / "analysis" / "converted" / f"{name}.bin"
    try:
        buf = bytearray()
        for line in data.splitlines():
            line = line.strip()
            if not line or not line.startswith(b":"):
                continue
            try:
                length = int(line[1:3], 16)
                addr = int(line[3:7], 16)
                rectype = int(line[7:9], 16)
                payload = bytes.fromhex(line[9:9 + length * 2].decode())
            except (ValueError, IndexError):
                continue
            if rectype == 0x00:  # data
                if addr + len(payload) > len(buf):
                    buf.extend(b"\xff" * (addr + len(payload) - len(buf)))
                buf[addr:addr + len(payload)] = payload
            elif rectype == 0x01:  # EOF
                break
        if not buf:
            return None
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(bytes(buf))
        return out
    except OSError:
        return None


def _srec_to_bin(data: bytes, workspace: Path, name: str) -> Path | None:
    """Motorola S-record → 二进制。解析 S1/S2/S3 数据记录,失败返回 None。

    S-record 格式: count 字节 = 地址字节数 + 数据字节数 + 校验和(1)。
    S1 地址 2 字节, S2 地址 3 字节, S3 地址 4 字节。
    """
    out = workspace / "analysis" / "converted" / f"{name}.bin"
    _ADDR_BYTES = {b"1": 2, b"2": 3, b"3": 4}
    try:
        buf = bytearray()
        for line in data.splitlines():
            line = line.strip()
            if len(line) < 4 or not line.startswith(b"S"):
                continue
            rectype = line[1:2]
            addr_bytes = _ADDR_BYTES.get(rectype)
            if addr_bytes is None:
                continue
            try:
                count = int(line[2:4], 16)
                # payload = 地址 + 数据(去校验和)
                payload = bytes.fromhex(line[4:4 + (count - 1) * 2].decode())
                if len(payload) < addr_bytes:
                    continue
                addr = int(payload[:addr_bytes].hex(), 16)
                data_part = payload[addr_bytes:]
            except (ValueError, IndexError):
                continue
            # 地址上限: 恶意/损坏 S-record(S3 地址 4 字节)可伪造
            # addr=0xFFFFFFFF, 直接扩展会尝试分配 ~4GB → MemoryError。
            # 固件是审计工具的不可信输入,必须限制(超限跳过该记录)。
            if addr > _MAX_SREC_BIN_SIZE:
                continue
            if addr + len(data_part) > len(buf):
                buf.extend(b"\xff" * (addr + len(data_part) - len(buf)))
            buf[addr:addr + len(data_part)] = data_part
        if not buf:
            return None
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(bytes(buf))
        return out
    except (OSError, MemoryError):
        # MemoryError 也捕获: 极端输入下 buf 扩展失败不崩(失败不崩原则)。
        return None
