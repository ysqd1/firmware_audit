# 06: 小刀群 + demo 迁移 + 文档定稿

Parent: ../spec.md

**What to build:** 把迁移途中已知散落的同源知识收编到单一出处(六把小刀,每把独立可测可回滚);demo 脚本挪入包内 demos/ 子目录;AGENTS.md 目录树与 CONTEXT.md 按终态定稿,纸面与代码一致。全部是等价替换,行为零变更。

**Blocked by:** 05

**Status:** ready-for-agent

- [x] 宽容 JSON 解析:编排层手写"剥围栏+找大括号+loads"翻版删除,复用 data 层既有提取函数(顺删函数内无效 lazy import)
- [x] 工件落盘走 data 层:裸写 schema 落盘(verified_findings 聚合工件)与 instance_seq 回写收编为 data 层的保存/回写函数;verified_findings 文件名走子 Agent 配置的 output_name,不再硬编码
- [x] severity 排序表单一出处:data 层派生 rank 表,编排层与 data 层共用
- [x] 执行后状态三岔判定(成功/降级/失败)去重:收敛到 runner 层,两处消费点改走它
- [x] transcript 跑前清空去重:engine 层提供统一入口,编排层与 runner 两处消费
- [x] demo 脚本位于 step5_agent/demos/ 子包,python -m firmware_audit.step5_agent.demos.demo_display 可运行,AGENTS.md 演示命令同步
- [x] AGENTS.md 目录树/模块清单更新为终态(orchestration 包七模块 + demos);CONTEXT.md 词条与新结构一致
- [x] 迁移途中记录的"记票不修"问题清单随票归档:已收编的注明,未处理的保留为独立 issue
- [x] 全套件绿

## Comments

- 2026-09-05 T6 落地(收尾票):六把小刀全部等价替换、行为零变更,全套件
  267 passed + 11 skipped(T5 基线 259+11 + 新增聚焦测试 7 收集项 + 守护测试
  demos 登记调整)。
  1. **宽容 JSON 解析**:data 层 `_extract_json_object` 转正公开名
     `extract_json_object`(survey 解析与编排层共用),orchestrator
     `_write_report` 手写"剥围栏+找大括号+loads"翻版删除,函数内无效 lazy
     import(Strip_fence)顺删;report.json 副产品路径由既有
     test_report_json_byproduct 端到端守护。
  2. **工件落盘走 data 层**:新增 `save_aggregate`(schema v2 容器,原
     verify_phase 裸写收编,无 .md 降级路径)、`stamp_provenance`(溯源回写,
     双策略分档:默认无条件覆盖=verification 复核语义,only_missing=True=
     编排调度回填语义,instance_seq 仅缺省补、source_agent 不动)、
     `rewrite_artifact`(工件整包回写,OSError 吞掉返回 False,原 actions
     try/except-pass 收编);`_reconcile_report` 的 verified_findings 路径改走
     `sub_cfgs["verification"].output_name`,硬编码删除。
  3. **severity 排序表单一出处**:data 层由 SEVERITIES/新增 CONFIDENCES 派生
     `SEVERITY_RANK`/`CONFIDENCE_RANK`,verify_phase 的 VERIFY_* 手写表删除,
     rank_findings 与 SummarizeTool 清单排序改用 data 层(表内容逐键一致,
     排序行为零变更)。
  4. **执行后状态三岔判定**:新增 `runner.post_run_status`(success/degraded/
     failed,字符串契约——runner 不 import orchestration 是 ADR-0009 分层
     红线),actions 调度回填与 verify_phase 单实例两处内联 if/elif 删除。
     注意 DispatchStatus 是类属性字符串非 Enum,消费点直接用字符串值,不包装。
  5. **transcript 跑前清空**:新增 `engine/transcript.reset_transcript`
     (清空+父目录自动建),runner 与 orchestrator.run 两处 write_text("")
     消费同一入口。
  6. **demo 迁移**:demo_display.py git mv 入 `demos/` 子包(新增
     `demos/__init__.py`),`python -m firmware_audit.step5_agent.demos.demo_display`
     实测可运行;sys.path 锚点 parents[2]→[3];DISPLAY.md ×3、AGENTS.md ×1
     命令同步;layer guard TIER 登记 `demos: 0`(入口层)。
  7. **文档定稿**:AGENTS.md 目录树更新为终态(orchestration 七模块 + demos,
     含各模块一行职责)与"实现与分层"段重写、过期 `_verify_k` 引用更正为
     `verify_phase.verify_k`;CONTEXT.md `_latest_upstream` 旧私有名更正为
     actions 公开名 `latest_upstream`、severity 词条补 SEVERITY_RANK 出处;
     orchestration/__init__.py docstring 补 T6 定稿段。
  8. **记票清单归档**(全部已收编,无遗留独立票):
     - spec"已知待收编清单"6 项 → 小刀 1-5 全覆盖(宽容 JSON 解析、裸写
       schema 落盘 ×2、硬编码 verified_findings.json、severity 排序表两处、
       状态三岔两处、transcript 清空两处);
     - T1 记票 issue 07(tools_summary 路径漂移)→ 已随本票处理,票已标 done;
     - T2 记票 issue 08(docstring rationale 过期)→ 已随本票处理,票已标 done;
     - T5 记档(`_run_verify_one` 死参数 task)→ 本票顺手清(签名与调用点
       各一处,零行为变更)。
  测试:新增 `test_step5_data_store.py`(extract_json_object / save_aggregate
  往返 / stamp_provenance 双策略 / rewrite_artifact 含 OSError / rank 表派生
  单一出处,5 项)+ `test_step5_verify_phase.py::test_post_run_status_three_way`
  + `test_step5_react.py::test_reset_transcript_unified_entry`;既有编排级/
  流水线级测试(report.json 副产品/每疑点一实例/溯源回写/对账)照绿即回归锁定。
