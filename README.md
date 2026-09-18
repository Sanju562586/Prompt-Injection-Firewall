# 🔥 LLM Firewall — Prompt Injection Security Gateway

A production-grade AI security gateway with dual-stage scanning, RAG poisoning detection, and a 50-case red-team suite.

## Features

| Feature | Details |
|---|---|
| **Input Scanner** | 3-layer pipeline: regex → sentence-transformer → pre-trained DeBERTa |
| **Output Scanner** | PII detection (Presidio) + prompt exfiltration detection |
| **RAG Poisoning Detector** | Scans retrieved documents before they enter LLM context |
| **Audit Log** | SQLite-backed, every scan recorded with attack type + latency |
| **Red-Team Suite** | 50 attack vectors across 7 categories with pass/fail scoring |
| **Interactive Dashboard** | Streamlit UI to test live, view logs, run red-team |
| **REST API** | FastAPI gateway — 3-line integration |

## Quick Start

### 1. Create virtual environment & install dependencies

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/macOS

pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 2. Launch the Interactive Dashboard

```bash
streamlit run dashboard/app.py
```

Open http://localhost:8501 — use the **Test Scanner** tab to try prompts live.

### 3. Launch the REST API

```bash
uvicorn api.main:app --reload --port 8000
```

Interactive API docs at http://localhost:8000/docs

### 4. Run the Red-Team Suite

```bash
python -m redteam.runner
```

### 5. Run Tests

```bash
pytest tests/ -v
```

## 3-Line Integration

```python
import httpx

response = httpx.post("http://localhost:8000/v1/scan/input",
                      json={"text": user_prompt})
if response.json()["decision"] == "BLOCK":
    raise ValueError(f"Injection detected: {response.json()['reason']}")
```

## Detection Pipeline

```
User Prompt
    │
    ▼
┌─────────────────────────────────────────┐
│  Layer 1 — Pattern Detector             │  regex + keyword rules (~0ms)
│  40+ patterns across 6 attack types     │  → BLOCK if score ≥ 0.80
└─────────────────────────────────────────┘
    │ (only if Layer 1 doesn't block)
    ▼
┌─────────────────────────────────────────┐
│  Layer 2 — Semantic Detector            │  sentence-transformer similarity (~50ms)
│  Catches paraphrased variants           │  → BLOCK if score ≥ 0.80
└─────────────────────────────────────────┘
    │ (only if Layer 2 doesn't block)
    ▼
┌─────────────────────────────────────────┐
│  Layer 3 — DeBERTa Classifier           │  pre-trained HuggingFace model (~200ms)
│  protectai/deberta-v3-base-prompt-      │  → BLOCK if score ≥ 0.80
│  injection-v2 (~95% accuracy)           │
└─────────────────────────────────────────┘
    │
    ▼
 Decision: BLOCK / WARN / ALLOW + reason + audit log entry
```

## Attack Categories (Red-Team)

| ID | Category | # Attacks |
|---|---|---|
| DI | Direct Injection | 10 |
| JB | Jailbreaks | 10 |
| RH | Role Hijacking | 10 |
| II | Indirect Injection | 10 |
| TS | Token Smuggling | 5 |
| PE | PII Exfiltration | 5 |
| RP | RAG Poisoning | 5 |

## Docker

```bash
docker compose up
```

- API:       http://localhost:8000/docs
- Dashboard: http://localhost:8501

## Tech Stack

- **Python 3.11** · **FastAPI** · **Pydantic v2**
- **sentence-transformers** (`all-MiniLM-L6-v2`)
- **HuggingFace Transformers** (`protectai/deberta-v3-base-prompt-injection-v2`)
- **Microsoft Presidio** (PII detection)
- **SQLite** (audit log)
- **Streamlit** (dashboard)
- **Docker** + **Docker Compose**
