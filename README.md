# firmware_audit

固件安全审计流水线（Firmware Security Audit Pipeline）：

**解包 → 过滤 → 分类 → 反编译/提取 → 三 Agent 智能审计**

## 流水线

| 阶段 | 职责 |
|---|---|
| Step0 | 预解压 + 磁盘镜像分区提取（GPT/MBR） |
| Step1 | 引导式解包（魔数决策逐层解，兜底 binwalk -Me） |
| Step2 | 白/黑名单过滤 + 去重 |
| Step3 | 文件分类（ELF/脚本/源码/证书/密钥） |
| Step4 | Ghidra 反编译 + 文本/密钥扫描 + 不透明固件分诊 |
| Step5 | 三 Agent（recon→analysis→verification）ReAct 审计 |

## 快速开始

环境要求：Python 3.10+、Docker（binwalk/ghidra 容器）。

```bash
pip install -r firmware_audit/requirements.txt
python -m firmware_audit.main target/1
```

## 目录结构

```
firmware_audit/
├── step0~step5_agent/   # 各阶段（见 README.md 详述）
├── docker/              # Docker 封装 + 容器构建资源
├── profiles/            # 固件机型名单
└── test/                # 单元/集成测试
```

详见 [firmware_audit/README.md](firmware_audit/README.md)。

## 说明

- 大磁盘镜像按分区独立工作区审计，已提取分区自动复用。
- 敏感文件（`.env`）、固件样本与 `target/` 分析数据**不入库**。
