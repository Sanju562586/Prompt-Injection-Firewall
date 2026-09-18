# 🔥 LLM Firewall — Prompt Injection Security Gateway

A modular, enterprise-grade AI security gateway with dual-stage scanning, RAG context defense, PII masking, LLM reverse proxy, and red-team evaluation suite.

---

## 🏛️ Modular 8-Component Architecture

```
llm-firewall/
│
├── gateway/              # Module 1: API endpoints, security middleware, and reverse proxy
│   ├── api.py            # FastAPI REST router (/v1/scan/*, /v1/chat/completions, /v1/audit)
│   ├── middleware.py     # Request tracing, latency headers, security headers, CORS
│   └── proxy.py          # Reverse LLM proxy with pre-call and post-call interception
│
├── scanners/             # Module 2: Lifecycle security scanning
│   ├── input_scanner.py  # Stage 1 user prompt scanner
│   ├── rag_scanner.py    # RAG document poisoning & indirect injection scanner
│   ├── output_scanner.py # Stage 2 LLM response & exfiltration scanner
│   └── pii_scanner.py    # Dedicated PII detector & redactor (Presidio + regex fallback)
│
├── detection/            # Module 3: Threat detection & scoring engines
│   ├── classifier.py     # Transformer classifier (protectai/deberta-v3-base-prompt-injection-v2)
│   ├── rules.py          # Fast regex & heuristic pattern matching library
│   ├── risk_engine.py    # Multi-factor threat scoring & risk tier evaluator
│   └── ensemble.py       # Multi-layer detector ensemble with short-circuiting
│
├── audit/                # Module 4: Persistence, telemetry, and forensic models
│   ├── models.py         # Unified Pydantic schemas (Decision, AttackCategory, RiskLevel, etc.)
│   ├── logger.py         # Thread-safe audit event logger
│   └── database.py       # SQLite database manager with WAL mode and indexing
│
├── redteam/              # Module 5: Adversarial attack evaluation & benchmarking
│   ├── attacks/          # Categorized attack suites (DI, JB, RH, II, TS, PE, RP)
│   ├── runner.py         # CLI & programmatic red-team attack runner
│   ├── evaluator.py      # Quantitative security metrics (Accuracy, Precision, Recall, Bypass Rate)
│   └── benchmark.py      # Latency distribution (p50, p95, p99) and throughput benchmark
│
├── dashboard/            # Module 6: Interactive SOC Operations Console
│   └── app.py            # Streamlit dashboard for testing, audit logs, and red-team suite
│
├── tests/                # Module 7: Comprehensive test suite
│   ├── test_gateway.py   # Gateway, middleware, and proxy test cases
│   ├── test_scanners.py  # Input, output, RAG, and PII scanner test cases
│   ├── test_detection.py # Rules, risk engine, and ensemble test cases
│   ├── test_audit.py     # Database, logger, and model test cases
│   └── test_redteam.py   # Attack collection, runner, and evaluator test cases
│
├── config/               # Module 8: Centralized configuration management
│   ├── config.yaml       # Central YAML settings for thresholds, models, and layers
│   └── __init__.py       # Config loader with environment variable overrides
│
├── Dockerfile            # Container configuration
├── docker-compose.yml    # Multi-service composition (Gateway, Dashboard, Frontend)
├── requirements.txt      # Python dependencies
└── pyproject.toml        # Packaging configuration and CLI entrypoints
```

---

## 🚀 Quick Start

### 1. Installation
```bash
python -m venv .venv
.venv\Scripts\activate       # Windows
# source .venv/bin/activate  # Linux/macOS

pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 2. Launch the Security Gateway API
```bash
uvicorn gateway.api:app --reload --port 8000
```
Interactive Swagger documentation is available at http://localhost:8000/docs

### 3. Launch the Streamlit SOC Dashboard
```bash
streamlit run dashboard/app.py --server.port 8501
```
Open http://localhost:8501 in your browser.

### 4. Run the Red-Team Suite
```bash
python -m redteam.runner
# or filter by category:
python -m redteam.runner --category direct_injection
```

### 5. Run the Latency & Throughput Benchmark
```bash
python -m redteam.benchmark --samples 10
```

### 6. Run Unit & Integration Tests
```bash
python -m pytest tests/ -v
```

---

## 🔌 3-Line Integration Examples

### REST API Integration:
```python
import httpx

resp = httpx.post("http://localhost:8000/v1/scan/input", json={"text": user_prompt})
if resp.json()["decision"] == "BLOCK":
    raise ValueError(f"Threat blocked: {resp.json()['reason']}")
```

### Direct Python Library Integration:
```python
from audit.models import ScanRequest, Decision
from scanners.input_scanner import scan_input

result = scan_input(ScanRequest(text=user_prompt))
if result.decision == Decision.BLOCK:
    print(f"Malicious prompt rejected! Score: {result.score:.2f} ({result.reason})")
```

### Drop-in Reverse LLM Proxy:
Configure your OpenAI client base URL to point directly to the firewall gateway:
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="your-openai-key",
)

# Intercepts prompt -> scans -> forwards -> scans completion -> returns safe output
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello world"}],
)
```

---

## 🛡️ Detection Pipeline & Multi-Factor Risk Engine

```
User Prompt
    │
    ▼
┌─────────────────────────────────────────┐
│  Layer 1 — Pattern & Heuristic Rules    │  Instant (~0ms) regex pre-filter
│  40+ patterns across 7 attack types     │  → Short-circuit if high-confidence rule match
└─────────────────────────────────────────┘
    │ (if Layer 1 doesn't block)
    ▼
┌─────────────────────────────────────────┐
│  Layer 2 — Semantic Vector Similarity   │  sentence-transformer (all-MiniLM-L6-v2)
│  Embeds & compares against attack seeds │  → Short-circuit if score ≥ 0.78
└─────────────────────────────────────────┘
    │ (if Layer 2 doesn't block)
    ▼
┌─────────────────────────────────────────┐
│  Layer 3 — DeBERTa Transformer Model    │  protectai/deberta-v3-base-prompt-injection-v2
│  Deep semantic injection classification │  → Pre-trained HuggingFace inference
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  Multi-Factor Risk Engine               │  Combines signals, correlates layers,
│  Assigns RiskLevel (LOW/MED/HIGH/CRIT)  │  evaluates policies & produces final verdict
└─────────────────────────────────────────┘
    │
    ▼
 Final Decision: BLOCK / WARN / ALLOW + forensic audit log entry
```

---

## 🐳 Docker Deployment

```bash
docker compose up --build
```
- **Gateway API**: http://localhost:8000/docs
- **SOC Dashboard**: http://localhost:8501
- **Next.js Console**: http://localhost:3000
