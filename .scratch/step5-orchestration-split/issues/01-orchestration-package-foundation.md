# 01: orchestration 包地基(建包 + 整体迁移 + ADR-0009 + 依赖守护测试)

Parent: ../spec.md

**What to build:** 编排层成为独立包:现编排器模块(1675 行)整体迁入 orchestration/ 包,逻辑零改动;同时把 AGENTS.md 里"靠自觉"的依赖分层规则升级为 AST 守护测试,从此越层/互 import 直接红;结构决策落成 ADR-0009。对外 CLI 入口与 step5_run 行为完全不变。

**Blocked by:** None(可立即开始)

**Status:** ready-for-agent

- [x] orchestration/ 包建立,原编排器模块整体迁入为包内首模块(纯搬家:除 import 路径与相对导入层级外,diff 无逻辑改动)
- [x] 旧顶层编排器模块文件删除,不留兼容 shim;生产代码与全部测试 import(约 24 处 + 1 处 patch 字符串路径)更新到新路径
- [x] 依赖守护测试落地:AST 扫描 step5_agent 全部 import 边,断言——入口→orchestration→runner/aggregator/engine/data/providers 单向;runner 不 import orchestration;engine/data/providers 互不 import 且不向上 import;守护的是全依赖图而非仅新包
- [x] ADR-0009 落地:包结构 + 依赖分层规则 + 被否备选(顶层平铺不加包/按层次全量改名/runner 并入编排包)及否因
- [x] CONTEXT.md 中指向旧模块文件的既有词条同步更正
- [x] 全套件绿(现基线 176 passed + 2 skipped);python -m firmware_audit.step5_agent.run_step5 路径仍可用

## Comments

- 2026-09-05 T1 落地:git mv 保历史,搬入模块与原文件逐行 diff 仅 10 行(9 个顶层相对导入 + 1 个 strip_fence 延迟导入,`.` → `..`),纯搬家成立。import 更新点实测 13 处 = 生产 1(run_step5.py)+ 测试 11(test_orchestrator.py ×10 + test_step5_pipeline.py ×1)+ patch 字符串 1(make_display),票面"约 24 处"为勘察高估。守护测试 `test/test_step5_layer_guard.py`(2 测试函数 + test_main),变异验证四种违规全被抓:叶子互引/runner 引编排/未登记顶层模块/stash 对照意外复现的"旧布局"(`orchestrator.py` 顶层存在 + run_step5 未接 orchestration)。ADR-0009 见 `docs/adr/0009-step5-orchestration-package.md`。全套件 249 passed + 11 skipped(增量恰为守护测试 3 收集项;票面基线 176+2 是 spec 勘察时旧数,stash 对照实测改动前基线 246 passed + 11 skipped 同为全绿);`python -m firmware_audit.step5_agent.run_step5` usage 正常。AGENTS.md 目录树按 spec 归 T6 定稿,未动。code-review(Standards/Spec 双轴):无硬违规;两件跟进已处理——ADR-0009 回归锁定段过期基线数字(176+2)已改为实测(246+11→249+11),`firmware_audit/docs/tools_summary.md` 三处旧路径漂移按纪律记票不顺手修(issue 07,建议并入 T6)。


## Comments
