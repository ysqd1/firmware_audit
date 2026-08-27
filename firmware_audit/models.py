"""文件信息数据结构。

所有通过过滤的文件都建 FileInfo(不只 ELF),在 Step3 创建后逐步填充。
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
import json


@dataclass
class FileInfo:
    """单个被审计文件的元信息与状态。"""

    # --- 基础信息(Step3 填充) ---
    path: str              # 原始绝对路径
    rel_path: str          # 相对解包根目录(报告引用,即"原本位置")
    type: str = ""         # elf_exec / elf_lib / script / source / config / text /
                           # crypto_x509 / crypto_ssh / crypto_gpg / crypto_pkcs12 /
                           # crypto_private_key / crypto_public_key / crypto_unknown / unknown
    size: int = 0
    subtype: str = ""      # file 命令原始输出
    is_system_trust: bool = False   # Step3 标记:位于系统信任库目录(etc/ssl/certs 等),
                                    # 非厂商硬编码凭证,Step5 不应作可疑点上报

    # --- ELF 专属(Step4 填充,其他类型留空) ---
    arch: str = ""                       # arm64 / x86_64
    decompiled_path: str = ""            # 反编译 .c 路径(analysis/<rel_path>.c)
    analysis_path: str = ""              # analysis/ 目录(.c 与 JSON 同处)
    ghidra_status: str = "pending"       # pending / ok / failed / skipped

    # --- 审计状态(Step5 填充,待定) ---
    audit_status: str = "pending"        # pending / passed / suspicious / failed
    findings: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FileInfo":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


def save_fileinfos(fileinfos: list[FileInfo], out_path: Path) -> None:
    """序列化所有 FileInfo 到 JSON。"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps([f.to_dict() for f in fileinfos], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def load_fileinfos(in_path: Path) -> list[FileInfo]:
    """从 JSON 反序列化 FileInfo 列表。"""
    return [FileInfo.from_dict(d) for d in json.loads(in_path.read_text(encoding="utf-8"))]
