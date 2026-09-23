#!/usr/bin/env bash
# nvram_shim 构建(票 18):构建器镜像 → ARM32 共享桩 → 宿主侧校验入库。
# 产物 sha256 钉在 firmware_audit/step5_agent/providers/tools/qemu_adapt.py
# 的 NVRAM_SHIM_SHA256;漂移由离线测试拒绝,不静默换桩。
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/libnvram_shim.so"
TAG="fw-nvram-shim-build:2026-09-23"

docker build -f "$HERE/Dockerfile" -t "$TAG" "$HERE"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
docker run --rm --user "$(id -u):$(id -g)" -v "$TMP:/out" "$TAG"
mv "$TMP/libnvram_shim.so" "$OUT"
chmod 0644 "$OUT"

echo "== 产物身份 =="
sha256sum "$OUT"
wc -c < "$OUT"
if command -v readelf >/dev/null 2>&1; then
  readelf -h "$OUT" | sed -n '1,12p'
  echo "== 未决符号(必须为空) =="
  if readelf -s "$OUT" | awk '$7=="UND" && $8!="" {print $8}' | grep -v '^$'; then
    echo "存在未决符号,拒绝入库" >&2
    exit 1
  else
    echo "(无未决符号)"
  fi
else
  echo "readelf 不可用;保留 sha256/尺寸证据"
fi
