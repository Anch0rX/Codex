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

## 📌 Overview

**CAPE LLM Assessment** is an optional reporting extension for **CAPE Sandbox** that enhances post-analysis intelligence through Large Language Models (LLMs).

Instead of raw sandbox outputs, this module transforms CAPE analysis results into:

- Structured threat assessments  
- Extracted Indicators of Compromise (IOCs)  
- ATT&CK-aligned behavioral insights  
- Analyst-friendly JSON and Markdown reports  

The module operates **after CAPE analysis completes**, without modifying the sandbox execution pipeline.

---

## 🧠 Key Capabilities

### 🔍 Results Normalization & Denoising
- Extracts high-value signals from CAPE results  
- Removes redundant or noisy data  
- Builds a compact, LLM-friendly evidence package  

### ⚙️ Heuristic Signal Detection
- Detects suspicious behaviors (persistence, injection, LOLBins, etc.)  
- Converts raw events into structured risk indicators  

### 🧩 LLM-Based Reasoning
- Uses OpenAI-compatible APIs  
- Performs structured malware interpretation  
- Reduces hallucination via schema-constrained outputs  

### 📊 Structured Output Generation
- JSON output for automation pipelines  
- Markdown output for human analysts  
- Evidence-linked findings for traceability  

### 🛡️ Secure-by-Design
- Prompt injection mitigation  
- Sample data sanitization and truncation  
- Fail-open architecture (never breaks CAPE reporting)  

---

## 🏗️ Architecture
