# CAPE LLM Assessment Extension

这个仓库提供一个可选的 CAPE reporting 扩展：`llm_assessment`。
它在 CAPE 分析结束后执行“规则预处理 + LLM 研判 + 结构化落盘”，输出统一 JSON 与 Markdown 结果。

## 功能概览

- 新 reporting module：`modules/reporting/llm_assessment.py`
- 结果归一化与去噪：`lib/cuckoo/common/llm/normalizer.py`
- 规则信号检测：`lib/cuckoo/common/llm/heuristics.py`
- Prompt 构造：`lib/cuckoo/common/llm/prompt_builder.py`
- OpenAI-compatible client：`lib/cuckoo/common/llm/client.py`
- Schema 兜底与稳态化：`lib/cuckoo/common/llm/schema.py`
- 后处理与 Markdown 渲染：`lib/cuckoo/common/llm/postprocess.py`

## 如何与 CAPE 一起使用

1. 将仓库中的 `modules/reporting/` 与 `lib/cuckoo/common/llm/` 对应文件放入 CAPE 主仓同路径。  
2. 在 CAPE reporting 配置中加入（或合并）`[llm_assessment]` 配置段。  
3. 将 `enabled = yes`，并配置你的 OpenAI-compatible endpoint。  
4. 运行 CAPE 任务，查看输出文件：
   - `reports/llm_summary.json`
   - `reports/llm_summary.md`

## 配置示例

```ini
[llm_assessment]
enabled = yes
provider = openai_compatible
endpoint = http://127.0.0.1:8001/v1/chat/completions
api_key =
model = qwen2.5-72b-instruct
timeout = 120
verify_tls = yes
max_input_events = 80
max_processes = 20
max_signatures = 50
max_network_artifacts = 50
redact_pii = yes
temperature = 0
max_tokens = 2200
store_markdown = yes
attach_to_results = no
system_prompt_version = v1
```

## 安全与运维建议

- 默认建议使用本地/私有模型服务，不要默认发往公网 LLM。
- 样本字符串是不可信输入，模块已做清洗/截断，但不代表零风险。
- 模块为 fail-open 设计：LLM 异常不会中断主 reporting。

## 测试

```bash
pytest -q tests/test_llm_assessment.py
```
