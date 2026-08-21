# 压扁镜像的 ENTRYPOINT 修正层(docker import 的 --change 在 PowerShell 下引号被剥,
# ENTRYPOINT 解析成了 shell 形式;exec 形式必须由 Dockerfile JSON 语法声明)
# 压扁源:firm_audit/sandbox:slim 全量回归 ALL-PASS 后 docker export/import 而来
FROM firm_audit/sandbox:flat
ENTRYPOINT ["analyzeHeadless"]
