<p align="center">
  <img src="assets/CAPE%20LLM%20Assessment.png" width="260" alt="CAPE LLM Assessment Logo" />
</p>

<h1 align="center">CAPE LLM Assessment</h1>

<p align="center">
  An LLM-enhanced CAPE Sandbox reporting extension for structured malware assessment,
  IOC extraction, ATT&CK-aligned findings, and analyst-ready threat intelligence reports.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/CAPE-Sandbox-2563EB?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Language-Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/LLM-OpenAI%20Compatible-10B981?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Output-JSON%20%2B%20Markdown-F59E0B?style=for-the-badge" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Detection-IOC%20Extraction-8B5CF6?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Mapping-MITRE%20ATT%26CK-DC2626?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Design-Fail--Open-111827?style=for-the-badge" />
  <img src="https://img.shields.io/badge/Architecture-Modular-0EA5E9?style=for-the-badge" />
</p>

<p align="center">
  <b>Results Normalization</b> • <b>Rule-Based Signals</b> • <b>LLM Reasoning</b> • <b>Stable Schema</b> • <b>Analyst Reports</b>
</p>

---

## Overview

**CAPE LLM Assessment** is an optional reporting extension for **CAPE Sandbox** that enhances post-analysis intelligence through Large Language Models (LLMs).

Instead of raw sandbox outputs, this module transforms CAPE analysis results into:

- Structured threat assessments
- Extracted Indicators of Compromise (IOCs)
- ATT&CK-aligned behavioral insights
- Analyst-friendly JSON and Markdown reports

The module operates **after CAPE analysis completes**, without modifying the sandbox execution pipeline.

---

## Key Capabilities

### Results Normalization & Denoising
- Extracts high-value signals from CAPE results
- Removes redundant or noisy data
- Builds a compact, LLM-friendly evidence package

### Heuristic Signal Detection
- Detects suspicious behaviors such as persistence, injection, and LOLBins usage
- Converts raw events into structured risk indicators

### LLM-Based Reasoning
- Uses OpenAI-compatible APIs
- Performs structured malware interpretation
- Reduces hallucination through schema-constrained outputs

### Structured Output Generation
- JSON output for automation pipelines
- Markdown output for human analysts
- Evidence-linked findings for traceability

### Secure-by-Design
- Prompt injection mitigation
- Sample data sanitization and truncation
- Fail-open architecture that never breaks CAPE reporting

---

## Architecture

~~~text
CAPE Analysis Pipeline
        │
        ▼
┌──────────────────────────────┐
│ CAPE Results (raw JSON)      │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ Normalizer (denoise & reduce)│
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ Heuristics Engine            │
│ (rule-based signals)         │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ Prompt Builder               │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ LLM Client (OpenAI API)      │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ Postprocess & Schema Guard   │
└──────────────┬───────────────┘
               ▼
┌──────────────────────────────┐
│ Output                       │
│ - llm_summary.json           │
│ - llm_summary.md             │
└──────────────────────────────┘
~~~

---

## Project Structure

~~~text
CAPE-LLM-Assessment/
├── modules/
│   └── reporting/
│       └── llm_assessment.py
├── lib/
│   └── cuckoo/
│       └── common/
│           └── llm/
│               ├── client.py
│               ├── normalizer.py
│               ├── heuristics.py
│               ├── prompt_builder.py
│               ├── schema.py
│               ├── postprocess.py
│               └── utils.py
├── conf/
│   └── default/
│       └── reporting.conf.default
├── tests/
│   └── test_llm_assessment.py
└── docs/
    └── llm_assessment.md
~~~

---

## Installation & Integration

### 1. Copy Files into CAPE

~~~bash
cp -r modules/reporting/* <CAPE>/modules/reporting/
cp -r lib/cuckoo/common/llm <CAPE>/lib/cuckoo/common/
~~~

### 2. Update CAPE Configuration

~~~ini
[llm_assessment]
enabled = yes
provider = openai_compatible
endpoint = http://127.0.0.1:8001/v1/chat/completions
api_key =
model = qwen2.5-72b-instruct
timeout = 120
verify_tls = yes
temperature = 0
max_tokens = 2200
store_markdown = yes
attach_to_results = no
system_prompt_version = v1
~~~

### 3. Start LLM Service

~~~bash
curl http://127.0.0.1:8001/v1/chat/completions
~~~

### 4. Run CAPE Analysis

Outputs will be generated in:

~~~text
storage/analyses/<task_id>/reports/
~~~

- `llm_summary.json`
- `llm_summary.md`

---

## Output Format

### JSON (Machine-Friendly)
- Verdict (malicious + confidence)
- Observed behaviors
- ATT&CK techniques
- IOC list
- Analyst actions
- Uncertainty notes

### Markdown (Human-Friendly)
- Executive summary
- Attack flow
- Key findings
- Threat intelligence insights
- Recommended actions

---

## Testing

~~~bash
pytest -q tests/test_llm_assessment.py
~~~

---

## Security Considerations

- Sample-derived content is **untrusted input**
- Prompt injection is mitigated via sanitization
- Avoid sending sensitive data to public LLM APIs
- Prefer local or private OpenAI-compatible endpoints

---

## Failure Handling

This module follows a **fail-open design**:

- LLM failures do **not** interrupt CAPE reporting
- Errors are captured as structured JSON
- Partial outputs remain available

---

## Use Cases

- Malware triage automation
- SOC analyst augmentation
- Threat intelligence reporting
- Incident response acceleration
- Security research workflows

---

## Roadmap

- [ ] Improved ATT&CK mapping accuracy
- [ ] Multi-model support
- [ ] Streaming report generation
- [ ] CAPE Web UI integration
- [ ] Threat clustering and similarity analysis

---

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests
4. Ensure all tests pass
5. Submit a pull request

---

## License

MIT License

---

## Author

**Anchor Cao**  

---

## Acknowledgements

- CAPE Sandbox
- OpenAI-compatible LLM ecosystems
- Malware analysis community
