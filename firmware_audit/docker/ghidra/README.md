# ghidra 镜像

基于 deepaudit/sandbox,内置 Ghidra 11.3.2 + JDK 21。

构建:

```bash
bash build_docker.sh
```

打 tag:`ghidra`。

本目录必须已有以下文件(已提供,请保留):
- `ghidra_11.3.2_PUBLIC.zip`(官方下载)
- `jdk21.tar.gz`(Oracle OpenJDK 21 源码+二进制 tar包)

> ExtractInfo.py 是 Ghidra 反编译/程序信息提取脚本,已内置。