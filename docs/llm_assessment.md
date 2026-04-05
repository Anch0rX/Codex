# LLM Assessment Reporting Module

`llm_assessment` 在 CAPE reporting 阶段执行“规则预处理 + LLM 研判 + 结构化落盘”。
模块不会改动沙箱执行流程，且默认关闭。

## 为什么建议本地/私有 OpenAI-compatible 服务

样本行为与提取内容可能包含敏感信息（内部域名、账号路径、基础设施 IOC）。
生产环境建议优先接入本地/私有部署模型端点，避免默认发送到公网服务。

## 启用方式

编辑 `conf/default/reporting.conf.default`（或部署环境对应配置）中的 `[llm_assessment]`：

- `enabled = yes`
- `provider = openai_compatible`
- `endpoint` 指向本地或受控服务
- 按需设置 `api_key`

## 关键配置说明

- `timeout`: LLM 请求超时（秒）
- `verify_tls`: HTTPS 证书校验
- `temperature`, `max_tokens`: 推理控制参数
- `max_input_events` / `max_processes` / `max_signatures` / `max_network_artifacts`: prompt 压缩上限
- `redact_pii`: 路径用户名等轻量脱敏
- `attach_to_results`: 是否写回 `results["llm_assessment"]`
- `store_markdown`: 是否输出可读 Markdown 报告

## 输出文件位置

- `reports/llm_summary.json`
- `reports/llm_summary.md`

## 失败时行为

该模块为 fail-open 设计：
- 当 endpoint 不可达、超时、响应非法或解析失败时，不中断其他 reporting
- 模块会写入稳定的 error stub JSON（`status=error`）便于排障

## 安全注意事项

- 样本内容不可信，可能包含 prompt injection 文本
- 已做基础清洗与截断，但不应视为完全无风险
- 不要记录完整 prompt、完整样本原文到日志
- 默认不要将敏感样本结果发送到公网 LLM
