# nvram_shim 构建器(票 18):ARM32 小端(armel 软浮点,对齐 uClibc EABI
# 固件)共享桩。基础镜像 digest 与 qemu-exec-v2/ investigation 构建器同源钉定;
# 产物经 build_shim.sh 校验后入库,运行期由会话工具按 SHA-256 钉值装配,
# 不进 qemu-exec-v2 执行镜像(执行镜像保持剥离,deny-by-absence 不放宽)。
FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
      --no-install-recommends gcc-arm-linux-gnueabi && \
    rm -rf /var/lib/apt/lists/*
COPY nvram_shim.c /src/nvram_shim.c
# -fno-builtin/-fno-tree-loop-distribute-patterns:防 gcc 把扫描循环改写为
# strlen 等 libc 调用;-fno-stack-protector:防 __stack_chk_fail 未决符号。
# uClibc 预加载环境解析不了这些符号,整个桩会被 ldso 静默忽略(票 18 实测)。
RUN arm-linux-gnueabi-gcc -shared -nostdlib -fPIC -O2 -Wall -Wextra \
      -march=armv7-a -fno-builtin -fno-stack-protector \
      -fno-tree-loop-distribute-patterns \
      -Wl,--hash-style=sysv \
      -o /tmp/libnvram_shim.so /src/nvram_shim.c \
    && arm-linux-gnueabi-readelf -s /tmp/libnvram_shim.so | \
      awk '$7=="UND" && $8!="" {print "UND symbol: " $8; fail=1} END { exit fail }'
CMD ["/bin/sh", "-c", "cp /tmp/libnvram_shim.so /out/libnvram_shim.so"]
