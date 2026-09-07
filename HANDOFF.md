# HANDOFF — 固件审计项目会话交接

> 写于 2026-09-07(上版 09-02)。这是给**下一个对话/接手者**的交接文档。
> 本版最大变化:**项目已整体迁入 Kali WSL**(`wsl: kali-linux`,用户 `dr`),Windows 侧原目录成为冻结的旧拷贝。

---

## 0. 项目一句话

`/home/dr/fw`(Kali WSL)—— 宇树固件安全审计流水线(Step1-5)。Step1-4 规则化处理(解包→过滤→分类→反编译),Step5 LLM Agent 审计(recon→analysis→verification,orchestrator 编排,每疑点一独立复核实例)。

**Windows 旧拷贝** `E:\固件\create\important`(junction `E:\fw`)是迁移前快照,**已冻结勿写入**;其去留(约 300GB)由用户定。

## 1. 环境与工作模式(2026-09-07 迁移定稿)

- **权威仓库**:`/home/dr/fw`(Kali WSL2 原生 ext4;301.6GB / 59 万文件,含 `target/` 固件数据、`firmware_audit/.cve_cache`、`.env`、`.scratch` 工单)。迁移全程 robocopy 0 失败,属主已全部修为 `dr`。
- **两种驱动方式**:
  1. Windows 侧 ZCode 会话经 `wsl.exe -d kali-linux` 执行——整个迁移即以此完成。坑与规矩:**wsl.exe 传参会搅坏中文路径和多行脚本**,一律 ASCII 路径 + 单行命令,复杂逻辑写脚本文件再执行。
  2. 桌面版"WSL 入口"(2026-09-07 已连通):文件读写/终端/Git/Agent 全在 Kali 内执行,模型登录与计费留 Windows 侧(国内版 bigmodel 凭据 / Lite 套餐 / GLM-5.3-Flash)。引擎由桌面端自动部署到 `~/.zcode/server/`——**勿手删**。
- **`/etc/wsl.conf` 已补 `[user] default=dr`**:此修复前,P9 通道(`\\wsl.localhost`)写入落盘为 root 属主(robocopy 301GB 全 root、桌面端部署 chmod EPERM 两个事故同根因);修复后写入即 dr 属主,新拷文件无需再 chown。
- **Kali 环境**:python3.13 + pyyaml/cryptography/pytest(系统级);Docker 走 Docker Desktop WSL 集成(firm_audit/sandbox、ghidra、binwalk 三镜像直接可用,集成开关改动备份在 `settings-store.json.bak-migration`);`~/bin/xdg-open` 转发 http(s) 到 Windows 默认浏览器(经 explorer.exe——**勿改回 cmd start**,cmd 会把 URL 第一个 `&` 后全部截断)。
- **已清理**:Kali 侧独立 zcode 三件套(官方 deb `/opt/ZCode`、`~/node22`、`~/bin/zcode` wrapper)——WSL 入口自带引擎后三者无用,已于 09-07 卸除(`dpkg --purge zcode`)。若见 TUI 报缺 `@zcode/tui`,那是该 deb 的打包缺口,与本项目无关。

## 2. 当前 git / 测试基线

- 工作区干净。2026-09-07 的文档更新(README / requirements / .env.example / 本文件)是 **Windows 侧最后一次提交**,此后项目在 Kali 侧(`/home/dr/fw`)演进。
- 自上版交接(eb0211d)以来的提交见 `git log`:Step5 Observation 预算两票(01/02)+ 文档口径票 03、CVE 缓存共享 gitignore、target/3 Go2 NX 审计报告归档。
- **Linux 下测试基线:274 passed / 2 skipped / 5 failed**(上版"176+2"是 Windows 时代数字;Linux 上 Docker 门控测试已激活并全过)。
- **5 个失败已定位、等用户拍板后修**(勿擅自动手):
  - 真 bug:`firmware_audit/step0/step0_preprocess.py:61` 用 `info.create_system == 3` 判"zip 符号链接",实际只说明 zip 创建于 Unix——Linux 制作的正常 zip 会被整包跳过。修法一行:改查文件类型位 `(external_attr >> 16) & 0o170000 == 0o120000`。
  - 测试平台假设:`test_resolve_within` 用 `C:\evil` 做 Windows 盘符越界用例,Linux 上只是合法文件名——用例需按平台分支。
  - 连带失败共 5 个:zip 用例 ×4 + `test_main` ×1,同一根因。

## 3. 关键背景(接手者必读)

- **CONTEXT.md** 是术语表;**rules.md** 是代码铁律("失败不崩"、零第三方依赖、配置集中);**docs/adr/** 现有 0001-0009。
- **"未来改进方向"类文档内容由用户亲自把关,agent 不得修改**。
- agent 持久记忆(自动加载)已存:迁移全部细节(`kali-wsl-migration`)、WSL/Docker 踩坑(`wsl-docker-env-quirks`)、target/3 审计结论(`go2-nx-target3-audit`)、Step0-fs-extract 改进票 grill 进展(`step0-fs-extract-grill`)、CVE 缓存共享(`firm-audit-cve-cache-shared`)。
- 用户对国内外账号站点敏感:Lite 套餐在**国内版 bigmodel.cn**,国际站(z.ai)是另一套账号体系,勿混。

## 4. 架构体检遗留候选(下一个可做)

来自 `improve-codebase-architecture` 报告(已做 C3、C4,Step5 重构是独立线)。剩余:

| 候选 | 强度 | 内容 |
|---|---|---|
| **C1** | Strong | Step4 `decompile()` 一个入口塞 4 个 pass,1046 行仅 12.9% 覆盖。**用户明确想提升 Step4 覆盖** |
| **C0(新)** | High | §2 的 5 个测试失败(1 真 bug + 1 平台用例),量小、独立,适合先行 |
| C2 | Worth | crypto parser 8 个浅克隆(`_parse_x509` 等) |
| C5 | Worth | Step1 manifest schema 散落 ~10 处 |
| C6 | Speculative | Step0 partition dict 隐式契约 |

## 5. 用户已表达的倾向

- 认可"该深化就深化"(不是一次性工具);想提升测试覆盖(尤其 Step4)
- 架构方向认可,主要问题是"大模块该拆未拆"
- 调 skill 前先征得同意;代码改动先说明意图(见 §8)
- 对环境迁移类操作接受度高,但**删除数据(如 E: 旧拷贝)必须用户亲自决定**

## 6. 历史 e2e 验证(2026-09-01,已过时记录,留档参考)

对 `target/1` 的 C4 验证见 `docs/c4-path-escape.md §六`。**当时验证的 agents 行为问题已被 01–06 重构解决**,此节不再作为下一步依据,仅留档。target/3 Go2 NX 完整审计已于 09-06 完成(1 critical 实证、6 幻觉全拦),结论存 agent 记忆与 `go2nx_audit_report.md`。

## 7. 下一会话焦点(候选)

1. **修 5 个测试失败**(§2,等用户点头)——一行 bug 修 + 平台分支用例,跑全套件回归
2. **C1:拆 Step4 `decompile()`**——用户明确想做。走全流程 skill:`grill-with-docs` → `to-spec` → `to-tickets` → 逐票 `implement`,提交前 `code-review`
3. C2 crypto parser 去重
4. Step0-fs-extract 改进票:grill 已定大半(Q8/Q10/Q14 待答),下一步 spec + 拆票(见 agent 记忆)

## 8. 工作规则(用户明确要求,接手者必须遵守)

- **调用任何 skill 前,必须先提示用户,得到许可后再调**。
- **不许擅自修改代码**。任何代码改动(哪怕小)先向用户说明意图、经同意再做。
- 复杂功能/重构优先走全流程 skill(grill → spec → tickets → implement → code-review)。
- 环境迁移/配置类操作可以放手做,但删除类操作(数据、目录、账号态)先问。

---

## 下一步选项(接手者从这里选)

0. **修 5 个测试失败**(最小、独立,建议先做)
1. **做 C1**(拆 Step4 decompile + 提覆盖)
2. **做 C2**(crypto parser 去重)/ Step0-fs-extract 继续 spec
3. **停一轮**(无紧急技术债时可停)

> 用户沟通偏好:中文;喜欢具体代码例子;会追问细节("这一步在干嘛")。
