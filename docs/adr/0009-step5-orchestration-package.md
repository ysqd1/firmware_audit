# 0009-Step5 编排层独立成 orchestration/ 包 + 依赖分层机器化

日期:2026-09-05(step5-orchestration-split T1;spec 见 `.scratch/step5-orchestration-split/spec.md`)

## 问题

编排器模块 `step5_agent/orchestrator.py` 长到 1675 行——全库第二大文件的 2.4 倍,一个模块戴五顶职责帽子(调度守卫、调度日志、verification 每疑点一实例引擎、报告对账、预算状态),30+ 成员摊在类表面。顶层平级文件还混了三个层次(编排决策/单实例执行/纯逻辑/CLI 入口/演示脚本),而依赖规则("engine/data/providers 互不 import、依赖只准向下")只写在 AGENTS.md 里靠自觉,违规靠 code review 肉眼抓。

## 决策

**编排层收进独立包 `step5_agent/orchestration/`**,分 6 张严格线性票零行为迁移(本 ADR 随 T1 落地):

1. **T1 = 整体纯搬家**:原编排器模块原样迁为 `orchestration/orchestrator.py`(1675 行,只改相对导入层级 `.` → `..`),旧顶层模块删除、**不留兼容 shim**——单一 import 路径,杜绝两套并存;后续票(T2-T5)按单一职责解体为 state/orchestrator/actions/handoff/dispatch_log/verify_phase/reconciliation,T6 小刀群收尾 + demo 迁 `demos/`。
2. **依赖分层(守护测试的规则来源)**:
   - 入口(`run_step5` / 包根 `__init__` / `demo_display`)→ orchestration → runner / aggregator → engine / data / providers;
   - 跨单元边只准向下(目标层级序严格大于源),包内边不受限,入口在顶可引任意单元;
   - runner 永不 import orchestration(单实例执行不知道编排的存在);
   - engine、data、providers 两两互不依赖,也不向上 import(既有规则,不变);
   - 新顶层模块必须先在守护测试的 TIER 表登记层级,否则直接红——层级图变更必须是显式决策。
3. **守护机器化**:`test/test_step5_layer_guard.py` AST 扫描 step5_agent 全部 .py 的 import 边(含函数级延迟导入),断言上图;守护范围是全依赖图,不限于新包。跨子系统引用(`firmware_audit.docker`/`file_rules` 等共享工具)不在图内。先例:tool_permissions_and_threshold(权限矩阵机器化)。
4. **顶层其余文件不动**:CLI 入口 `run_step5.py`、单实例执行 `runner.py`、聚合器 `aggregator.py` 保持原位原名;`python -m firmware_audit.step5_agent.run_step5` 与 `step5_run` 签名不变。

被否的方案:

- **顶层平铺不加包**(只把 1675 行拆成几个平级文件)——顶层继续混三个层次,"编排层"没有单一去处,目录读不出分工;且与 engine/data/providers 三包的既有组织方式不一致。
- **按层次全量改名/重组**(engine/data/providers 也跟着动)——大手术换零清晰度:三包名字与位置已是稳定词汇(AGENTS.md、CONTEXT.md、全部测试引用),动它们把"纯搬家"变成全库重写,违背零行为迁移纪律。
- **runner 并入编排包**(编排与执行同包)——runner 是被编排调度的执行层,与 engine/data/providers 同向消费;并进去后"runner 不知道编排存在"这条最重要的单向边反而被包内导入合法化,分层规则退化。

## 代价与兼容

- 生产/测试全部 import 更新到新路径(1 处生产 + 11 处测试 import + 1 处 patch 字符串),机械替换;工件、CLI、`step5_run` 行为零变化。
- 旧路径 `firmware_audit.step5_agent.orchestrator` 不再可 import(有意为之);守护测试防顶层 shim 复活。
- T2-T5 期间 `orchestration/orchestrator.py` 仍是单一大模块,包内解体按票推进,每票全套件绿才合入。

## 回归锁定

- `test_step5_layer_guard.py::dependency_layering`:分层规则 + 未知单元拒绝 + run_step5→orchestration 接线存在性;变异验证过三种违规(叶子互引/runner 引编排/未登记顶层模块)均被抓,git-stash 对照意外复现迁移前布局时同样全红(第四种真实场景);
- `test_step5_layer_guard.py::no_legacy_top_level_orchestrator`:旧顶层模块不复活;
- 全套件绿:迁移前对照实测 246 passed + 11 skipped,迁移后 249 passed + 11 skipped(增量恰为守护测试 3 个收集项;skip 均为环境门控 Docker/STEP5_SMOKE)。
