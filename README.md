# Prompt Injection Firewall (Open-Source Gateway)

A production-grade AI security gateway engineered to intercept prompt injection attacks, jailbreaks, role hijacks, RAG poisoning, and sensitive data leakage before requests reach the LLM or responses reach users.

## Architecture

- **Input Injection Scanner (Module 1)**: Multi-layer ensemble combining regex/heuristic rules, obfuscation decoders, and a fine-tuned DeBERTa ML classifier for high recall and balanced precision.
- **Output Scanner**: Exfiltration and PII detection.
- **RAG Poisoning Detector**: Context document injection screening.
- **Audit Logging**: Structured attack telemetry and latency tracking.
- **Red-Team Suite**: Comprehensive benchmark test suite.
