"""Step3 _classify_crypto 单元测试。

验证 PEM RSA 私钥不再被误分类为 x509(修复:私钥/公钥独立成类,
优先级 private key > public key > x509)。

用法:
    python firmware_audit/test_step3.py
    python -m firmware_audit.test_step3
"""
from __future__ import annotations

from ..step3.step3_classify import _classify_crypto


def _check(name: str, file_output: str, suffix: str, expected: str) -> None:
    got = _classify_crypto(file_output, suffix)
    status = "PASS" if got == expected else "FAIL"
    print(f"[{status}] {name}: got={got!r}, expected={expected!r}")
    return got == expected


def main() -> int:
    cases = [
        # 验收1: PEM RSA 私钥 -> crypto_private_key(修复前是 crypto_x509)
        ("PEM RSA private key", ".key", "crypto_private_key"),
        # 附:PEM EC/DSA 私钥同样归 private_key
        ("PEM EC private key", ".key", "crypto_private_key"),
        ("PEM DSA private key", ".key", "crypto_private_key"),
        # 验收2: PEM 证书仍是 x509
        ("PEM certificate", ".pem", "crypto_x509"),
        # DER 证书仍 x509
        ("Certificate, Version=3", ".crt", "crypto_x509"),
        # 验收3: OpenSSH private key 不被私钥规则抢走,仍归 ssh
        # (依赖 openssh 元组在 private key 元组之前)
        ("OpenSSH private key", ".key", "crypto_ssh"),
        ("OpenSSH RSA public key", ".pub", "crypto_ssh"),
        # 回归:PKCS12 / OpenPGP 不受影响
        ("PKCS12 certificate", ".p12", "crypto_pkcs12"),
        ("OpenPGP Public Key", ".gpg", "crypto_gpg"),
    ]
    failures = 0
    for file_output, suffix, expected in cases:
        if not _check(f"file={file_output!r}", file_output, suffix, expected):
            failures += 1
    print(f"\n结果: {len(cases) - failures}/{len(cases)} 通过")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())