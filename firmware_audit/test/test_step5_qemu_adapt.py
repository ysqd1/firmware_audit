"""票 18(qemu-user-mode-experiments):环境适配模板(qemu_adapt)。

离线纯函数测试(零容器、零 Docker):夹具/bind/NVRAM 声明解析与校验、
模板映像构建、适配桩钉值、未决键消费、执行期 bind/挂载换算。
声明校验的失败路径是 TDD 主 seam:无来源的 NVRAM 值、保留路径 bind、
桩钉值漂移都必须在会话开启前拒绝——不伪造空值或成功。

纪律:不调用真实 LLM、不读取 GT;真实后端验证在门控测试单独覆盖。
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.providers.tools import qemu_adapt

SHIM_SHA = qemu_adapt.NVRAM_SHIM_SHA256


# ---------- 夹具声明 ----------

def test_fixtures_parse_roundtrip() -> None:
    content = b"tcp 6 ESTABLISHED src=192.168.0.10\n"
    items = qemu_adapt.parse_fixtures(
        "conntrack=" + base64.b64encode(content).decode())
    assert items == {"conntrack": content}


def test_fixtures_reject_dup_bad_name_bad_base64_oversize() -> None:
    ok = base64.b64encode(b"x").decode()
    with pytest.raises(qemu_adapt.AdaptationError, match="重复"):
        qemu_adapt.parse_fixtures(f"a={ok}\na={ok}")
    with pytest.raises(qemu_adapt.AdaptationError, match="名非法"):
        qemu_adapt.parse_fixtures(f"-bad={ok}")
    with pytest.raises(qemu_adapt.AdaptationError, match="base64"):
        qemu_adapt.parse_fixtures("a=!!!not-base64!!!")
    big = base64.b64encode(b"\0" * (qemu_adapt.MAX_FIXTURE_BYTES + 1)).decode()
    with pytest.raises(qemu_adapt.AdaptationError, match="上限"):
        qemu_adapt.parse_fixtures(f"a={big}")
    many = "\n".join(f"n{i}={ok}" for i in range(qemu_adapt.MAX_FIXTURES + 1))
    with pytest.raises(qemu_adapt.AdaptationError, match="数量"):
        qemu_adapt.parse_fixtures(many)


# ---------- bind 声明 ----------

@pytest.fixture
def fw_root(tmp_path: Path) -> Path:
    root = tmp_path / "extracted" / "fw"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "conntrack.conf").write_bytes(b"fixture-conf")
    return tmp_path / "extracted" / "fw"


def test_binds_parse_all_forms(fw_root: Path) -> None:
    fixture = {"conntrack": b"data"}
    binds = qemu_adapt.parse_binds(
        "rw:/var=base/varstate\n"
        "ro:/proc/net/ip_conntrack=fixture/conntrack\n"
        "ro:/etc/conntrack.conf=extracted/etc/conntrack.conf\n",
        fw_root, fixture)
    assert [(b["mode"], b["guest_path"], b["kind"]) for b in binds] == [
        ("rw", "/var", "base"),
        ("ro", "/proc/net/ip_conntrack", "fixture"),
        ("ro", "/etc/conntrack.conf", "extracted"),
    ]
    assert binds[1]["sha256"] == qemu_adapt.sha256_bytes(b"data")
    assert binds[2]["sha256"] == qemu_adapt.sha256_bytes(b"fixture-conf")


def test_binds_reject_reserved_and_bad_paths(fw_root: Path) -> None:
    fixture: dict[str, bytes] = {"a": b"d", "b": b"d"}
    for line, why in [
        ("ro:/tmp/x=fixture/a", "保留前缀"),
        ("ro:/dev/null=fixture/a", "保留前缀"),
        ("ro:/session/adapt/x=fixture/a", "保留前缀"),
        ("ro:/host-rootfs/etc/passwd=fixture/a", "保留前缀"),
        ("ro:relative=fixture/a", "绝对路径"),
        ("rw:/var=etc/not-base", "base/<名>"),
        ("ro:/x=fixture/missing", "未声明夹具"),
        ("ro:/x=extracted/no/such/file", "不存在或越出固件根"),
        ("xx:/x=base/y", "ro:<guest>"),
        ("ro:/a=fixture/b\nro:/a=fixture/b", "重复"),
    ]:
        with pytest.raises(qemu_adapt.AdaptationError, match=why):
            qemu_adapt.parse_binds(line, fw_root, fixture)


def test_binds_normalize_dot_segments(fw_root: Path) -> None:
    """词形等价的 .. 段折叠为规范路径(折叠后无穿越),不按原样接受。"""
    binds = qemu_adapt.parse_binds("ro:/a/../etc/ct.conf=fixture/a",
                                   fw_root, {"a": b"d"})
    assert binds[0]["guest_path"] == "/etc/ct.conf"


def test_binds_extracted_source_must_stay_in_root(tmp_path: Path) -> None:
    root = tmp_path / "fw"
    root.mkdir()
    with pytest.raises(qemu_adapt.AdaptationError, match="不存在或越出固件根"):
        qemu_adapt.parse_binds("ro:/x=extracted/../../etc/passwd",
                               root, {})


# ---------- NVRAM 声明与映像 ----------

def test_nvram_declaration_requires_sources() -> None:
    with pytest.raises(qemu_adapt.AdaptationError, match="缺来源引用"):
        qemu_adapt.parse_nvram_declaration("wan_wifi_ssid=mywlan", "")
    with pytest.raises(qemu_adapt.AdaptationError,
                       match="没有对应值"):
        qemu_adapt.parse_nvram_declaration("", "wan_wifi_ssid=cfg:L1")
    decl = qemu_adapt.parse_nvram_declaration(
        "wan_wifi_ssid=mywlan\nrouter_mode=ap\n",
        "wan_wifi_ssid=declared_test_input\n"
        "router_mode=target/7 webroot_ro/nvram_default.cfg:L120\n")
    assert decl["wan_wifi_ssid"] == {"value": "mywlan",
                                     "source": "declared_test_input"}
    assert decl["router_mode"]["source"].startswith("target/7 ")


def test_nvram_declaration_rejects_bad_keys_and_caps() -> None:
    with pytest.raises(qemu_adapt.AdaptationError, match="键名非法"):
        qemu_adapt.parse_nvram_declaration("bad key=v", "bad key=s")
    with pytest.raises(qemu_adapt.AdaptationError, match="键名非法"):
        qemu_adapt.parse_nvram_declaration("=v", "=s")
    with pytest.raises(qemu_adapt.AdaptationError, match="键重复"):
        qemu_adapt.parse_nvram_declaration("k=v\nk=v2", "k=s")
    empty_value = "k="
    with pytest.raises(qemu_adapt.AdaptationError, match="值缺失"):
        qemu_adapt.parse_nvram_declaration(empty_value, "k=s")
    oversized = "k=" + "v" * (qemu_adapt.MAX_NVRAM_VALUE_BYTES + 1)
    with pytest.raises(qemu_adapt.AdaptationError, match="超过"):
        qemu_adapt.parse_nvram_declaration(oversized, "k=s")
    many = "\n".join(f"k{i:03d}=v" for i in range(qemu_adapt.MAX_NVRAM_ENTRIES + 1))
    sources = "\n".join(f"k{i:03d}=s" for i in range(qemu_adapt.MAX_NVRAM_ENTRIES + 1))
    with pytest.raises(qemu_adapt.AdaptationError, match="桩上限"):
        qemu_adapt.parse_nvram_declaration(many, sources)


def test_nvram_image_is_deterministic_sorted_kv_table() -> None:
    decl = qemu_adapt.parse_nvram_declaration(
        "b_key=beta\na_key=alpha\n", "b_key=s\na_key=s")
    image = qemu_adapt.build_nvram_image(decl)
    assert image == b"a_key=alpha\x00b_key=beta\x00"
    assert qemu_adapt.sha256_bytes(image) == qemu_adapt.sha256_bytes(
        qemu_adapt.build_nvram_image(qemu_adapt.parse_nvram_declaration(
            "a_key=alpha\nb_key=beta\n", "a_key=s\nb_key=s")))


# ---------- 适配桩钉值 ----------

def test_shim_artifact_matches_pin() -> None:
    path = qemu_adapt.shim_artifact()
    assert path.is_file()
    assert qemu_adapt.sha256_bytes(path.read_bytes()) == SHIM_SHA


def test_shim_artifact_drift_refuses(monkeypatch) -> None:
    monkeypatch.setattr(qemu_adapt, "NVRAM_SHIM_SHA256", "0" * 64)
    with pytest.raises(qemu_adapt.AdaptationError, match="漂移"):
        qemu_adapt.shim_artifact()


def test_shim_artifact_missing_refuses(monkeypatch) -> None:
    monkeypatch.setattr(qemu_adapt, "_SHIM_SOURCE",
                        Path("/nonexistent/libnvram_shim.so"))
    with pytest.raises(qemu_adapt.AdaptationError, match="缺失"):
        qemu_adapt.shim_artifact()


# ---------- 固化与执行期换算 ----------

def test_materialize_writes_fixtures_bases_and_nvram(tmp_path: Path) -> None:
    session_dir = tmp_path / "session"
    root = tmp_path / "fw"
    root.mkdir()
    (root / "orig").write_bytes(b"original")
    fixtures = {"ct": b"line1\n"}
    binds = qemu_adapt.parse_binds(
        "rw:/var=base/var\nro:/x/ct=fixture/ct\nro:/orig=extracted/orig\n",
        root, fixtures)
    nvram = qemu_adapt.parse_nvram_declaration("k=v", "k=s")
    decl = qemu_adapt.materialize(session_dir, root, fixtures=fixtures,
                                  binds=binds, nvram=nvram)
    assert (session_dir / "fixtures" / "ct").read_bytes() == b"line1\n"
    assert (session_dir / "runtime" / "base" / "var").is_dir()
    assert (session_dir / "adapt" / qemu_adapt.NVRAM_SHIM_BASENAME).is_file()
    assert (session_dir / "adapt" / qemu_adapt.NVRAM_IMAGE_BASENAME) \
        .read_bytes() == b"k=v\x00"
    assert decl["nvram"]["values_count"] == 1
    assert decl["nvram"]["values"] == {"k": "s"}
    assert decl["nvram"]["image_sha256"] == qemu_adapt.sha256_bytes(b"k=v\x00")
    assert decl["fixtures"][0]["source"] == "declared_test_input"
    shadowed = [b for b in decl["binds"] if b.get("shadowed_original")]
    assert len(shadowed) == 1 and shadowed[0]["guest_path"] == "/orig"
    assert shadowed[0]["shadowed_original"]["sha256"] == \
        qemu_adapt.sha256_bytes(b"original")


def test_proot_binds_and_container_mounts(tmp_path: Path) -> None:
    binds = [{"mode": "rw", "guest_path": "/var", "kind": "base", "ref": "var",
              "sha256": None},
             {"mode": "ro", "guest_path": "/proc/net/ip_conntrack",
              "kind": "fixture", "ref": "ct", "sha256": "x"},
             {"mode": "ro", "guest_path": "/etc/conf", "kind": "extracted",
              "ref": "etc/conf", "sha256": "y"}]
    argv = qemu_adapt.proot_binds(binds, with_nvram=True)
    assert argv == [
        "-b", "/session/runtime/base/var:/var",
        "-b", "/session/fixtures/ct:/proc/net/ip_conntrack",
        "-b", "/session/firmware/etc/conf:/etc/conf",
        "-b", "/session/adapt/libnvram_shim.so:/session/adapt/libnvram_shim.so",
        "-b", "/session/adapt/nvram.img:/session/adapt/nvram.img",
    ]
    session_dir = tmp_path
    (session_dir / "fixtures").mkdir()
    (session_dir / "adapt").mkdir()
    mounts = qemu_adapt.container_mounts(session_dir, with_fixtures=True,
                                         with_nvram=True)
    assert mounts == [
        (session_dir / "fixtures", "/session/fixtures", "ro"),
        (session_dir / "adapt", "/session/adapt", "ro"),
    ]
    assert qemu_adapt.container_mounts(session_dir, with_fixtures=False,
                                       with_nvram=False) == []


def test_consume_unresolved_keys_reads_and_clears(tmp_path: Path) -> None:
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    assert qemu_adapt.consume_unresolved_keys(runtime) == []
    log = runtime / qemu_adapt.NVRAM_UNRESOLVED_BASENAME
    log.write_text("wl0_ssid\nwan_ip\nwl0_ssid\n", encoding="utf-8")
    assert qemu_adapt.consume_unresolved_keys(runtime) == ["wl0_ssid", "wan_ip"]
    assert not log.exists()


def test_nvram_image_over_shim_capacity_refused() -> None:
    """映像总字节超过桩装载上限(IMAGE_CAP 配对值)必须声明期拒绝:
    超限条目会被桩静默截断为"未声明",不能靠运行期 gap 兜底。"""
    # 单键合法但总量逼近/超过上限:值长 250 × 200 条 ≈ 50 KB;再翻倍即超限
    many = "\n".join(f"k{i:03d}=" + "v" * 250 for i in range(200))
    sources = "\n".join(f"k{i:03d}=s" for i in range(200))
    decl = qemu_adapt.parse_nvram_declaration(many, sources)
    image = qemu_adapt.build_nvram_image(decl)
    assert len(image) <= qemu_adapt.NVRAM_IMAGE_MAX_BYTES
    over = "\n".join(f"k{i:03d}=" + "v" * 250 for i in range(500))
    over_sources = "\n".join(f"k{i:03d}=s" for i in range(500))
    decl = qemu_adapt.parse_nvram_declaration(over, over_sources)
    with pytest.raises(qemu_adapt.AdaptationError, match="装载上限"):
        qemu_adapt.build_nvram_image(decl)
