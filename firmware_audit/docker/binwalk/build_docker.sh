#!/usr/bin/env bash
# 构建 binwalk Docker 镜像
# 注意: 必须打 tag `binwalk`,代码里 BINWALK_IMAGE="binwalk"(step1/step3)依赖它。
# 第三方源码自带的脚本打的是 binwalkv3,与代码不匹配,这里用官方 tag 统一。
cd "$(dirname "$0")/binwalk" && docker build -t binwalk .