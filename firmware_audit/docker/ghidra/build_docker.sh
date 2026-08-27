#!/usr/bin/env bash
# 构建 ghidra Docker 镜像
# 用法: bash build_docker.sh
# 先 cd 到 Dockerfile 所在目录再 build,否则 COPY 相对路径失效
cd "$(dirname "$0")" && docker build -t ghidra .
