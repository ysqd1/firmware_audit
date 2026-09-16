"""Related Candidate 测试载荷的单一出处(照抄 intake 契约的必填字段)。

分析侧与复核侧的测试各自只覆盖自己要钉的规则,载荷本身不该出现第三份拷贝;
需要不同缺省的测试文件用薄包装设置本文件的默认值即可。
"""
from __future__ import annotations


def related_entry(**overrides) -> dict:
    """一条完整合法的 signal 线索 proposal(intake 必填字段齐全)。"""
    entry = {
        "proposal_id": "rel-cand-0001-1",
        "kind": "signal",
        "target": "extracted/bin/updater",
        "signal": "升级处理器解析未校验长度字段",
        "evidence_id": "ev-000001",
        "next_action": "反编译解析函数确认边界检查",
        "anchor": "parse_header+0x42",
        "mechanism": "integer overflow",
    }
    entry.update(overrides)
    return entry
