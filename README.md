# Firmware Audit

固件安全审计项目。当前流水线为 **Step0 预处理 → Step1 引导解包 → Step5 Host 控制的逐 Candidate 调查**。

## 项目内容

- `firmware_audit/`：源码、测试、配置示例与 Docker 构建文件。
- `docs/`：架构决策、工程约定与研究文档。
- `.scratch/`：版本化设计文档、工单与本机审计工作台视觉原型；实验运行数据保留在本地。
- `benchmark/`：案例说明和评测运行配置。固件、参考答案、参考资料及评审结果保留在本地；发现阶段不提供参考答案。

## 使用入口

需要 Python 和 Docker，建议在 Linux 或 WSL2 中运行。

```bash
pip install -r firmware_audit/requirements.txt
cp firmware_audit/.env.example firmware_audit/.env
# 在本地 .env 中填写模型接口配置。
python -m firmware_audit.main <target_dir>
```

已有解包工作区可单独运行 Step5：

```bash
python -m firmware_audit.step5_agent.run_step5 <target_or_workspace>
```

环境和镜像构建说明见 [部署文档](firmware_audit/README.md)；其中部分历史阶段描述以 [当前架构说明](AGENTS.md) 和 [架构决策](docs/adr/) 为准。

## 本地材料与 GitHub 上传范围

仓库保存代码、文档、工单、视觉原型和评测配置。以下材料留在本地：

- `.env`、账号配置和会话状态。
- `dataset/`、`target/`、`benchmark/cases/*/firmware/` 中的固件与审计运行结果。
- `.scratch/**/investigation/` 中的实验执行材料、工具缓存和构建下载缓存。
- `可参考的开源项目/` 中下载的第三方参考项目。
- `benchmark/ground_truth/`、`benchmark/reference/`、`benchmark/reviews/` 和案例筛选研究中的答案及参考材料。

评测所需固件的版本、文件名和来源见各案例的 README；克隆后需要自行准备对应固件。部分 Docker 构建依赖本地 Ghidra、JDK 和其他发布包，克隆仓库不会包含这些大型包。
