# 0005-Step5 LLM token 预算与截断续写

§7#3 的根因:推理模型(deepseek-v4-flash/mimo)的思考在 `reasoning_content`、正文在 `content`,两者**共享 max_tokens**(默认 16384)。当思考过程太长烧满预算,`content` 没位置写 → 返回空,`finish_reason=stop`。08-30 已把正文/思考拆分(只把 content 当回复,空→重试),但根因未解:思考烧满预算时靠重试兜底,重试 3 次仍空则抛 LLMError 终止整个 Step5。

改为**两措施**:

1. **max_tokens 16384 → 32768**:给 reasoning 翻倍空间,保证正文必然有位置写。上下文窗口 1M,32k 只占 3.2%,无压力;max_tokens 是输出上限(cap)非固定消耗,正常轮次思考几百到几千 token,成本几乎不变。
2. **截断续写**:content 空 + reasoning 非空时,不判空回复重试,而是把截断的 reasoning 作为 `assistant` 消息回传给 API,附"直接给最终答复,别展开思考"的 `user` 提示,再用原 max_tokens 调一次。这是 DeepSeek 官方续写模式,跳出"重新想一遍又烧满"的循环。

## 关键澄清:续写不破坏"思考不参与协议"

续写把 reasoning 回传给 **API 自己接续**,不是写进 Agent 的 ReAct 上下文(messages 四分区)或长期记忆。`chat()` 对上层 `react_loop` 透明——它仍只返回 content,"思考不参与 ReAct 协议解析、不进回喂上下文"的原则(08-30 刚立)不受影响。

## 决策理由

- 选择续写而非"普通重试":普通重试重发同样请求,模型会重新想一遍、还可能再烧满;续写是"接着上次的思路直接给结果",跳出烧满循环。
- 选择续写而非"拿 reasoning 当降级回复":08-30 明确否了后者——"草稿 Action 被当真执行"是它们刚修掉的坑。续写让思考只回传 API 内部,不流入协议解析。
- 供应商兼容 fallback:续写请求若返回 400(该 API 不接受 reasoning_content 作为请求字段)→ 降级为普通重试,不阻塞。

## 代价

若 32k 仍频繁烧满,说明是模型病理(倾向病态长思考),届时再单独处理(可评估降 reasoning 预算或换非推理模型)。续写机制增加 llm_client 复杂度,但有 fallback 保证失败不崩。

## 状态

已定,待实现(2026-09-01)。实现见 to-spec 生成的 spec / tickets。
