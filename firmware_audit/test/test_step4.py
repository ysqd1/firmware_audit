"""Step4 _TEXT_PATTERNS 文本扫描 + ELF 字符串表扫描/版本校验单元测试。

验证:
  - 引号/下划线赋值的密码能被命中,同时保持"赋值形式才匹配"约束(不退回裸词)。
  - ExtractInfo v2 产物版本校验(_is_decompiled_ok):旧版产物自动失效重跑。
  - _scan_elf_strings 对 strings.json 的命中/无命中/缺失三种场景。

用法:
    python firmware_audit/test_step4.py
    python -m firmware_audit.test_step4
"""
from __future__ import annotations

from ..models import FileInfo
from ..step4.step4_decompile import (
    _TEXT_PATTERNS,
    _is_decompiled_ok,
    _scan_elf_strings,
    _EXTRACTINFO_VERSION,
)


def _hits(kind: str, text: str) -> bool:
    """指定类型正则是否命中文本(文本按字节匹配)。"""
    for k, rx in _TEXT_PATTERNS:
        if k == kind and rx.search(text.encode("utf-8")):
            return True
    return False


def _hits_any(text: str) -> bool:
    return any(rx.search(text.encode("utf-8")) for _, rx in _TEXT_PATTERNS)


def _write_decompiled_c(decompiled_dir, rel_path, version, success):
    """写一个假 decompiled.c,头部含 extractinfo_version 与 decompile_success。"""
    p = decompiled_dir / f"{rel_path}.c"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        f"// decompiled output - fake\n"
        f"// extractinfo_version: {version}\n"
        f"// decompile_success: {success}\n"
        f"// total functions: 5, success: {success}, failed: 0\n"
        f"\nint main(void) {{ return 0; }}\n",
        encoding="utf-8",
    )
    return p


def _write_functions_json(analysis_dir, rel_path):
    import json
    p = analysis_dir / f"{rel_path}.functions.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps([{"name": "main", "address": "0x1000"}]), encoding="utf-8")
    return p


def _write_strings_json(analysis_dir, rel_path, strings):
    import json
    p = analysis_dir / f"{rel_path}.strings.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"version": 2, "program": "fake", "strings": strings}),
                 encoding="utf-8")
    return p


def test_version_check(tmp_path) -> list[str]:
    """验收1: 产物版本校验。version=1 失效重跑,version=_EXTRACTINFO_VERSION 放行。"""
    fails: list[str] = []
    # 合并目录:.c 与 JSON 同处 analysis_dir
    analysis_dir = tmp_path / "analysis"
    rel = "opt/unitree/robot"
    _write_functions_json(analysis_dir, rel)

    fi = FileInfo(path=str(tmp_path / rel), rel_path=rel)

    # 旧版产物(version=1)即使反编译成功也必须失效重跑
    _write_decompiled_c(analysis_dir, rel, version=1, success=5)
    if _is_decompiled_ok(fi, analysis_dir):
        fails.append("版本校验: extractinfo_version:1 应视为失效(返回 False),实际 True")

    # 当前版本产物放行
    _write_decompiled_c(analysis_dir, rel, version=_EXTRACTINFO_VERSION, success=5)
    if not _is_decompiled_ok(fi, analysis_dir):
        fails.append("版本校验: extractinfo_version 匹配应放行(返回 True),实际 False")

    # 无版本标记(旧 ExtractInfo 产物)→ 失效
    p = analysis_dir / f"{rel}.c"
    p.write_text("// decompile_success: 5\nint f(){return 0;}\n", encoding="utf-8")
    if _is_decompiled_ok(fi, analysis_dir):
        fails.append("版本校验: 无 extractinfo_version 应失效(返回 False),实际 True")

    return fails


def test_elf_strings_hits(tmp_path) -> list[str]:
    """验收2: strings.json 扫描命中 url / password_kw / private_key,字段含 address/refs。"""
    fails: list[str] = []
    analysis_dir = tmp_path / "analysis"
    rel = "opt/unitree/robot"
    strings = [
        {"address": "0x1234", "value": "`https://api.unitree.com/robot`",
         "length": 30, "refs": [{"from": "0x1000", "function": "func_1"}]},
        {"address": "0x1235", "value": 'password = "hunter2"',
         "length": 20, "refs": [{"from": "0x1001", "function": "func_2"}]},
        {"address": "0x1236", "value": "-----BEGIN RSA PRIVATE KEY-----",
         "length": 34, "refs": []},
    ]
    _write_strings_json(analysis_dir, rel, strings)

    fi = FileInfo(path=str(tmp_path / rel), rel_path=rel, type="elf_exec")
    ok = _scan_elf_strings(fi, analysis_dir)
    if not ok:
        fails.append("string 命中: _scan_elf_strings 应返回 True(已扫描),实际 False")

    kinds = {f["type"] for f in fi.findings}
    for want in ("url", "password_kw", "private_key"):
        if want not in kinds:
            fails.append(f"string 命中: 缺少 finding 类型 {want},实际 {sorted(kinds)}")

    # url finding 应带 address 与 refs 上下文
    url_f = next((f for f in fi.findings if f["type"] == "url"), None)
    if url_f is None:
        fails.append("string 命中: url finding 不存在")
    else:
        if url_f.get("address") != "0x1234":
            fails.append(f"string 命中: url finding.address 应为 0x1234,实际 {url_f.get('address')}")
        if url_f.get("refs") != [{"from": "0x1000", "function": "func_1"}]:
            fails.append(f"string 命中: url finding.refs 不符:{url_f.get('refs')}")

    if fi.audit_status != "suspicious":
        fails.append(f"string 命中: audit_status 应为 suspicious,实际 {fi.audit_status}")

    # .text.json 已写入且 scan=="elf"
    import json
    out = analysis_dir / f"{rel}.text.json"
    if not out.is_file():
        fails.append("string 命中: 未写入 .text.json")
    else:
        data = json.loads(out.read_text(encoding="utf-8"))
        if data.get("scan") != "elf":
            fails.append(f"string 命中: .text.json 顶层 scan 应为 'elf',实际 {data.get('scan')}")
        if data.get("count") != len(fi.findings):
            fails.append("string 命中: .text.json count 与 findings 数不一致")

    return fails


def test_elf_strings_no_hit(tmp_path) -> list[str]:
    """验收3: 无命中 → 无 findings,audit_status=="passed",.text.json 写入且 count==0。"""
    fails: list[str] = []
    analysis_dir = tmp_path / "analysis"
    rel = "opt/unitree/robot"
    strings = [
        {"address": "0x2000", "value": "hello world", "length": 11, "refs": []},
        {"address": "0x2001", "value": "unitree robotics", "length": 16, "refs": []},
    ]
    _write_strings_json(analysis_dir, rel, strings)

    fi = FileInfo(path=str(tmp_path / rel), rel_path=rel, type="elf_exec")
    ok = _scan_elf_strings(fi, analysis_dir)
    if not ok:
        fails.append("无命中: _scan_elf_strings 应返回 True(已扫描),实际 False")
    if fi.findings:
        fails.append(f"无命中: 不应有 findings,实际 {len(fi.findings)} 条")
    if fi.audit_status != "passed":
        fails.append(f"无命中: audit_status 应为 passed,实际 {fi.audit_status}")

    import json
    out = analysis_dir / f"{rel}.text.json"
    if not out.is_file():
        fails.append("无命中: 应写入 count==0 的 .text.json")
    else:
        data = json.loads(out.read_text(encoding="utf-8"))
        if data.get("count") != 0:
            fails.append(f"无命中: .text.json count 应为 0,实际 {data.get('count')}")

    return fails


def test_elf_strings_missing(tmp_path) -> list[str]:
    """验收4: strings.json 缺失 → 不崩,audit_status 保持默认(pending)。"""
    fails: list[str] = []
    analysis_dir = tmp_path / "analysis"
    rel = "opt/unitree/missing"  # 与其它用例不同,确保该 rel 无 strings.json
    fi = FileInfo(path=str(tmp_path / rel), rel_path=rel, type="elf_exec")
    ok = _scan_elf_strings(fi, analysis_dir)
    if ok:
        fails.append("缺失: strings.json 不存在时 _scan_elf_strings 应返回 False,实际 True")
    if fi.findings:
        fails.append("缺失: 不应有 findings")
    if fi.audit_status != "pending":
        fails.append(f"缺失: audit_status 应保持默认 pending,实际 {fi.audit_status}")
    if (analysis_dir / f"{rel}.text.json").exists():
        fails.append("缺失: 不应写入 .text.json")
    return fails


def main() -> int:
    import tempfile
    from pathlib import Path

    failures = 0

    # ---- 原有文本模式用例 ----
    cases = [
        # 验收1: 带引号密码命中 password_kw
        ("quoted password", 'password = "hunter2"', "password_kw", True),
        # 验收2: 下划线键名命中 password_kw
        ("SECRET_KEY underscore", "SECRET_KEY=abc123", "password_kw", True),
        ("PASSWORD_HASH", "PASSWORD_HASH=$6$randomsalt$hash", "password_kw", True),
        # 验收3: 函数调用无赋值形式,不命中
        ("set_password call", 'set_password("x")', "password_kw", False),
        ("password function arg", 'connect(password, host)', "password_kw", False),
        # 验收4: 系统配置项不误报(无 : 或 = 的裸词)
        ("PASS_MAX_DAYS", "PASS_MAX_DAYS 90", "password_kw", False),
        ("PASSWORD_MAX_LEN", "PASSWORD_MAX_LEN 64", "password_kw", False),
        # 验收5: 引号内 wifi psk 命中
        ('quoted psk', 'psk="xxxxx"', "wifi_psk", True),
        ("unquoted passphrase", "passphrase=Unitree#9035", "wifi_psk", True),
    ]
    for name, text, kind, expected in cases:
        got = _hits(kind, text)
        status = "PASS" if got == expected else "FAIL"
        print(f"[{status}] {name} ({kind}): text={text!r}, expected={expected}, got={got}")
        if got != expected:
            failures += 1

    # ---- ExtractInfo v2 相关新增用例 ----
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        groups = [
            ("版本校验", test_version_check(tmp)),
            ("string命中", test_elf_strings_hits(tmp)),
            ("string无命中", test_elf_strings_no_hit(tmp)),
            ("string缺失", test_elf_strings_missing(tmp)),
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
    raise SystemExit(main())