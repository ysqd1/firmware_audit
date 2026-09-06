"""APP rootfs 全量 cve-bin-tool 扫描(独立于 Step5 工具层,参数与其一致,仅去掉 900s 超时限制)。

输出: target/3/app_inventory/cve_scan_full.json
"""
import json
import subprocess
import time
from pathlib import Path

WS = Path(r"E:\固件\create\important\target\3\process\APP")
OUT = Path(r"E:\固件\create\important\target\3\app_inventory\cve_scan_full.json")

cmd = [
    "docker", "run", "--rm",
    "--entrypoint", "cve-bin-tool",
    "-v", str(WS / ".cve_cache") + ":/home/sandbox/.cache",
    "-v", str(WS / "extracted") + ":/work/extracted:ro",
    "firm_audit/sandbox:latest",
    "--quiet", "--format", "json", "-o", "-",
    "--offline", "--disable-version-check", "--disable-data-source", "PURL2CPE",
    "/work/extracted",
]
t0 = time.monotonic()
print("running cve-bin-tool on full APP tree...", flush=True)
proc = subprocess.run(cmd, capture_output=True, text=True,
                      encoding="utf-8", errors="replace")
elapsed = time.monotonic() - t0
print(f"rc={proc.returncode} elapsed={elapsed:.0f}s stdout={len(proc.stdout)} chars")
if proc.returncode >= 2:
    print("STDERR tail:", proc.stderr[-2000:])
    raise SystemExit(2)
OUT.write_text(proc.stdout, encoding="utf-8")
print(f"saved -> {OUT}")
try:
    data = json.loads(proc.stdout)
    cv = data.get("cve_entries", [])
    print(f"parsed: {len(cv)} CVE entries; metadata keys: {list(data.keys())}")
except Exception as e:
    print("JSON parse failed (rc=1 空输出=无命中?):", e, "| stdout head:", proc.stdout[:200])
