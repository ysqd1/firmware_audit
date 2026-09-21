#!/bin/bash
# QEMU 执行镜像冒烟(票 03)——在 firm_audit/qemu-exec 容器内运行,可重复执行。
#
# 宿主侧调用(或直接用同目录 run_smoke.sh):
#   docker run --rm --network none --entrypoint bash \
#     -v <本脚本>:/smoke.sh:ro \
#     -v <target/6 squashfs-root>:/work/tgt6:ro \
#     -v <target/8 squashfs-root>:/work/tgt8:ro \
#     firm_audit/qemu-exec /smoke.sh
#
# 断网 + 只读挂载 + --rm:无状态落盘,与 Step5 CLI 工具运行基线一致。
# 对照组依据票 01 调查(investigation/01/04-arm-runs.txt、05-mips-runs.txt):
# 裸跑 rc=126 证明显式调用不依赖 binfmt;错架构 rc=255 证明架构选择真实生效。
fail=0

echo "== 基线与 QEMU 版本查询(票 03 AC1)=="
cat /usr/local/share/fw-qemu-exec/BUILD-INFO.txt || fail=1
qemu-arm-static --version | head -1 || fail=1
qemu-mips-static --version | head -1 || fail=1
dpkg-query -W -f='dpkg: ${Version}\n' qemu-user-static || fail=1

echo "== binfmt 独立性对照:裸跑 ARM32 应 rc=126 =="
/work/tgt6/usr/sbin/nvram >/dev/null 2>&1
rc=$?
[ "$rc" = "126" ] && echo "PASS (rc=126)" || { echo "FAIL (rc=$rc,宿主 binfmt 漂移?)"; fail=1; }

echo "== ARM32 小端(target/6 nvram,-L 固件根)=="
out=$(qemu-arm-static -L /work/tgt6 /work/tgt6/usr/sbin/nvram 2>&1); rc=$?
echo "$out" | head -1
if [ "$rc" = "0" ] && echo "$out" | grep -q "usage: nvram"; then
    echo "PASS (rc=0)"
else
    echo "FAIL (rc=$rc)"; fail=1
fi

echo "== MIPS32 大端(target/8 busybox,-L 固件根)=="
out=$(qemu-mips-static -L /work/tgt8 /work/tgt8/bin/busybox echo hello-from-qemu-exec 2>&1); rc=$?
echo "$out" | head -1
if [ "$rc" = "0" ] && [ "$out" = "hello-from-qemu-exec" ]; then
    echo "PASS (rc=0)"
else
    echo "FAIL (rc=$rc)"; fail=1
fi

echo "== 错架构对照:qemu-arm-static 跑 MIPS32 应 rc=255 =="
qemu-arm-static -L /work/tgt8 /work/tgt8/bin/busybox echo x >/dev/null 2>&1
rc=$?
[ "$rc" = "255" ] && echo "PASS (rc=255)" || { echo "FAIL (rc=$rc)"; fail=1; }

echo "== RESULT: $([ $fail -eq 0 ] && echo ALL-PASS || echo HAS-FAIL) =="
exit $fail
