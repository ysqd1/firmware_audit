"""Step5 data 层工件存取小接口直测(T6 收编,tempfile 自清理,零 API 零 Docker)。

六把小刀落在 data/artifacts.py 的部分:
  - extract_json_object:宽容 JSON 提取单一出处(编排层手写"找大括号+loads"
    翻版已删,report.json 副产品与 survey 解析共用)
  - save_aggregate:编排聚合工件的 schema v2 落盘(原 verify_phase 裸写收编,
    无 .md 降级路径——输入是编排侧已聚合好的 findings,非 LLM Final Answer)
  - stamp_provenance / rewrite_artifact:schema v2 溯源回写与工件回写
    (原 actions/verify_phase 各自的回写循环收编,两种策略语义分档)
  - SEVERITY_RANK/CONFIDENCE_RANK:排序权重表由 SEVERITIES 派生的单一出处
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firmware_audit.step5_agent.data.artifacts import (
    CONFIDENCE_RANK,
    SCHEMA_VERSION,
    SEVERITIES,
    SEVERITY_RANK,
    extract_json_object,
    load_artifact,
    rewrite_artifact,
    save_aggregate,
    stamp_provenance,
)


def test_extract_json_object() -> list[str]:
    fails: list[str] = []
    # 前后散文容忍(首个 { 到最后一个 }),与收编前编排层手写行为一致
    obj = extract_json_object('结论如下 {"a": 1, "b": [2]} 以上')
    if obj != {"a": 1, "b": [2]}:
        fails.append(f"前后散文应容忍: {obj}")
    obj = extract_json_object('{"schema": 1, "conclusion": "ok"}')
    if obj is None or obj.get("conclusion") != "ok":
        fails.append(f"裸 dict 应可解析: {obj}")
    if extract_json_object("没有任何大括号") is not None:
        fails.append("无大括号应返回 None")
    if extract_json_object("{ 坏 JSON") is not None:
        fails.append("解析失败应返回 None(不抛)")
    if extract_json_object("[1, 2]") is not None:
        fails.append("非 dict(数组)应返回 None")
    if extract_json_object("") is not None:
        fails.append("空串应返回 None")
    return fails


# 票02(target/5 e2e 实测缩样):recon Final Answer 在字符串值里过度转义。
# 真实字节:role_evidence 中 \" 是合法转义(10 处),唯一非法转义是 \$(\$SERVER);
# json.loads 报 Invalid \escape → extract_json_object 返回 None → survey 降级
# .md → 编排层按弹性机制全额补跑 recon(白烧约 50 万 token)。
# 源码字串里 \\$ 产生原文的 \$,\\" 产生原文的 \"(与降级 survey.md 字节一致)。
T5_OVERESCAPE_RAW = (
    '侦察结论 {\n'
    '  "schema_version": 3,\n'
    '  "arch_snapshot": {\n'
    '    "top_level_dirs": ["bin", "etc_ro", "www"],\n'
    '    "components_grouped": [\n'
    '      {"name": "bin/lighttpd", "size": null, "role": "主 web 服务器",\n'
    '       "role_evidence": ["etc_ro/lighttpd/lighttpd.conf: server.port = 80, '
    '\\$SERVER[\\"socket\\"] == \\"0.0.0.0:443\\" ssl.engine enable"]}\n'
    '    ]\n'
    '  },\n'
    '  "summary": "攻击面概览"\n'
    '} 全文完'
)


def test_extract_json_object_overescape_repair() -> list[str]:
    """票02:过度转义修复保守档——原文解析失败且错误类型为 Invalid \\escape 时,
    剥掉非法转义的反斜杠后重试;接受条件三合一(原文确属该错误类型/归一化后
    能完整解析/通过工件形状校验),缺一维持 None 降级,不产"修出来的错数据"。

    fixture = target/5 实测缩样(降级 survey.md components_grouped 片段)。
    验收:
    1. 先红:现状返回 None;后绿:返回 dict 且 schema 形状正确,
       role_evidence 解码后含 $SERVER["socket"] == "0.0.0.0:443"
    2. 反向:真损坏(修复触发但仍解析失败)→ 照旧 None
    3. 反向:修复能解析但形状不符(无 survey/finding 结构键)→ None
    4. \\uXXXX 类转义错误行为不变(保持降级;门槛语义见实现结构)
    """
    fails: list[str] = []
    obj = extract_json_object(T5_OVERESCAPE_RAW)
    if obj is None:
        fails.append("缩样应经修复档解析为 dict(先红:现状为 None)")
        return fails
    if obj.get("schema_version") != 3 or not isinstance(obj.get("arch_snapshot"), dict):
        fails.append(f"schema 形状应正确(survey v3): {obj}")
    grouped = (obj.get("arch_snapshot") or {}).get("components_grouped") or []
    if len(grouped) != 1 or grouped[0].get("name") != "bin/lighttpd":
        fails.append(f"components_grouped 应完整解析: {grouped}")
    ev = " ".join(grouped[0].get("role_evidence") or [])
    if '$SERVER["socket"] == "0.0.0.0:443"' not in ev:
        fails.append(f"role_evidence 应解码过度转义为原文语义: {ev!r}")
    # 反向 1:修复档触发但归一化后仍解析失败 → 照旧 None(降级路径不变)
    if extract_json_object('{"schema_version": 3, "summary": "截断 \\$x') is not None:
        fails.append("真损坏 JSON(修复后仍失败)应照旧 None")
    # 反向 2:修复能解析但形状不符(无任何 survey/finding 结构键)→ None
    if extract_json_object('{"note": "cost \\$5"}') is not None:
        fails.append("修复后形状不符应 None(保守,不产修复数据)")
    # 反向 3:其他转义错误类型(\uXXXX)行为不变——保持降级 None。
    # 注:\u 是合法转义对、不会被剥,故本例对"类型门槛"不敏感(删门也过),
    # 它锁的是 \uXXXX 类错误整体不被修复档触碰的行为;门槛由实现结构保证。
    if extract_json_object(
            '{"arch_snapshot": {"dirs": ["x"]}, "summary": "bad \\uZZZZ escape"}') is not None:
        fails.append("Invalid \\uXXXX escape 类错误应保持降级 None(不进修复档)")
    return fails


def test_save_aggregate_and_roundtrip() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "agent" / "verified_findings.json"
        findings = [{"title": "t", "severity": "high", "verified": True,
                     "source_agent": "verification", "instance_seq": 3}]
        out = save_aggregate(path, "verification", "已复核 1/2 条", findings)
        if out != path or not path.is_file():
            fails.append("应原路径落盘")
        loaded = load_artifact(path)
        if loaded is None:
            fails.append("落盘工件应可经 load_artifact 读回")
            return fails
        if loaded.get("schema") != SCHEMA_VERSION or loaded.get("agent") != "verification":
            fails.append(f"schema v2 容器字段不符: "
                         f"{loaded.get('schema')}/{loaded.get('agent')}")
        if loaded.get("summary") != "已复核 1/2 条" or loaded.get("findings") != findings:
            fails.append(f"summary/findings 应原样保留: {loaded}")
    return fails


def test_stamp_provenance_policies() -> list[str]:
    fails: list[str] = []
    # 默认(verification 复核语义):无条件覆盖两字段,非 dict 条目跳过
    fs = [{"title": "a", "source_agent": "llm", "instance_seq": 99},
          "非dict条目跳过", {"title": "b"}]
    stamp_provenance(fs, "verification", 7)
    if fs[0].get("source_agent") != "verification" or fs[0].get("instance_seq") != 7:
        fails.append(f"默认应无条件覆盖两字段: {fs[0]}")
    if fs[1] != "非dict条目跳过":
        fails.append("非 dict 条目应原样跳过")
    if fs[2].get("instance_seq") != 7:
        fails.append(f"缺省字段应补齐: {fs[2]}")
    # only_missing(编排调度回填语义):seq 仅缺省时补,source_agent 不动
    fs2 = [{"source_agent": "analysis", "instance_seq": 4}, {"title": "x"}]
    stamp_provenance(fs2, "analysis", 9, only_missing=True)
    if fs2[0].get("instance_seq") != 4:
        fails.append(f"已有 seq 应保留(断点续跑工件的原始实例号): {fs2[0]}")
    if fs2[0].get("source_agent") != "analysis":
        fails.append(f"only_missing 下 source_agent 不应被改写: {fs2[0]}")
    if fs2[1].get("instance_seq") != 9:
        fails.append(f"缺省 seq 应补: {fs2[1]}")
    return fails


def test_rewrite_artifact() -> list[str]:
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "a.json"
        path.write_text("{}", encoding="utf-8")
        if rewrite_artifact(path, {"findings": [{"instance_seq": 1}]}) is not True:
            fails.append("正常回写应返回 True")
        if json.loads(path.read_text(encoding="utf-8")) != {"findings": [{"instance_seq": 1}]}:
            fails.append("回写内容应落盘")
        # OSError 吞掉返回 False(回填失败不阻塞调度,聚合层 ingest 仍会补)
        unwritable = Path(td) / "no-such-dir" / "sub" / "a.json"  # 父目录缺失
        if rewrite_artifact(unwritable, {"a": 1}) is not False:
            fails.append("父目录缺失(OSError)应吞掉返回 False")
    return fails


def test_rank_tables_derived_single_source() -> list[str]:
    """severity 排序表单一出处(T6):data 层由 SEVERITIES 派生,表内容与
    收编前 verify_phase 手写表逐键一致(取前 K 排序/汇总呈现行为零变更)。"""
    fails: list[str] = []
    if SEVERITY_RANK != {s: i for i, s in enumerate(SEVERITIES)}:
        fails.append(f"SEVERITY_RANK 应由 SEVERITIES 派生: {SEVERITY_RANK}")
    if SEVERITY_RANK != {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}:
        fails.append(f"severity 表内容与收编前不一致: {SEVERITY_RANK}")
    if CONFIDENCE_RANK != {"high": 0, "medium": 1, "low": 2}:
        fails.append(f"confidence 表内容与收编前不一致: {CONFIDENCE_RANK}")
    return fails


def test_main() -> int:
    failures = 0
    for name, fn in [
        ("extract_json_object", test_extract_json_object),
        ("extract_json_object_overescape_repair", test_extract_json_object_overescape_repair),
        ("save_aggregate_and_roundtrip", test_save_aggregate_and_roundtrip),
        ("stamp_provenance_policies", test_stamp_provenance_policies),
        ("rewrite_artifact", test_rewrite_artifact),
        ("rank_tables_derived_single_source", test_rank_tables_derived_single_source),
    ]:
        fl = fn()
        if fl:
            failures += len(fl)
            for msg in fl:
                print(f"[FAIL] {name}: {msg}")
        else:
            print(f"[PASS] {name}")
    print(f"\n结果: {'全部通过' if failures == 0 else f'{failures} 个断言失败'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(test_main())
