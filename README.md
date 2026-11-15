# Vision-Language Model (VLM) for Zero-Day Phishing Detection

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688.svg)](https://fastapi.tiangolo.com/)
[![React + Vite](https://img.shields.io/badge/Frontend-React%20%2B%20Vite-61DAFB.svg)](https://vitejs.dev/)
[![Tailwind CSS](https://img.shields.io/badge/Styling-Tailwind%20CSS-38B2AC.svg)](https://tailwindcss.com/)
[![Pytest Suite](https://img.shields.io/badge/Tests-72%20Passed-brightgreen.svg)](https://pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An AI-powered, multimodal cybersecurity platform engineered to detect and explain **novel zero-day phishing websites**. By corroborating **visual brand discrepancy**, **DOM structure**, **NLP semantic coercion**, and **URL lexical heuristics**, the system identifies brand impersonation, urgent social engineering, and credential harvesting without relying on outdated domain blacklists or static keyword signatures.

---

## Table of Contents

1. [System Overview & Zero-Day Detection Concept](#1-system-overview--zero-day-detection-concept)
2. [Threat Model & Security Architecture](#2-threat-model--security-architecture)
3. [Multimodal Scoring Cascade & Additive Threat Rules](#3-multimodal-scoring-cascade--additive-threat-rules)
4. [Domain Trust & User-Content Infrastructure Disqualification](#4-domain-trust--user-content-infrastructure-disqualification)
5. [Baseline ML Model Integration](#5-baseline-ml-model-integration)
6. [System Architecture & Dataflow](#6-system-architecture--dataflow)
7. [Installation & Setup](#7-installation--setup)
8. [Running with vs. Without Heavy VLM Backends](#8-running-with-vs-without-heavy-vlm-backends)
9. [Docker Hardened Deployment](#9-docker-hardened-deployment)
10. [API Reference & Demonstration Workflow](#10-api-reference--demonstration-workflow)
11. [Running Regression & Acceptance Tests](#11-running-regression--acceptance-tests)
12. [Benchmark Evaluation & Honest Metrics](#12-benchmark-evaluation--honest-metrics)
13. [Operational Limitations](#13-operational-limitations)
14. [Ethical Considerations](#14-ethical-considerations)

---

## 1. System Overview & Zero-Day Detection Concept

Modern phishing campaigns employ ephemeral infrastructure—domains registered minutes prior to an attack wave, hosted on serverless platforms or low-cost TLDs, and taken down within 4 to 12 hours. Traditional blacklist feeds (Google Safe Browsing, PhishTank, Spamhaus) are purely reactive and offer zero coverage during the initial, most devastating hours of an attack.

### What Zero-Day Detection Means in This System:
Zero-day phishing cannot be detected by domain age or URL reputation alone. Instead, detection relies on **Cross-Modal Discrepancy**:
- **Visual Perception**: The rendered interface convincingly mimics a high-value brand (e.g. Microsoft 365, Google Workspace, Chase Bank, PayPal).
- **Domain Identity**: The registrable apex domain (parsed using Public Suffix Rules via `tldextract`) does **NOT** belong to the official brand (e.g., `login.microsoftonline.security-verify.xyz` vs. `microsoft.com`).
- **DOM & Form Action**: An authentication password field or cross-domain POST action routes credentials to external infrastructure.
- **Semantic Manipulation**: Page copy leverages urgent threats of account termination, legal repercussions, or wire fraud.

When an unauthorized domain presents high visual brand similarity coupled with credential collection, the system triggers a zero-day phishing verdict regardless of how newly registered or clean the domain appears to reputation engines.

---

## 2. Threat Model & Security Architecture

Because this system ingests untrusted, potentially hostile URLs submitted by arbitrary users, security hardening is applied across all layers:

### 2.1 Multi-Hop SSRF Defense-in-Depth
- **Pre-execution DNS Validation**: Resolves hostnames prior to connection. Rejects loopback (`127.0.0.1/8`), RFC1918 private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), carrier-grade NAT (`100.64.0.0/10`), multicast (`224.0.0.0/4`), IPv6 unique local (`fc00::/7`), and AWS/GCP/Azure instance metadata endpoints (`169.254.169.254`, `fd00:ec2::254`).
- **Playwright Subresource Interception**: Intercepts every subresource, script, stylesheet, WebSocket, and redirect via `context.route("**/*", handler)` and aborts any internal destination with `blockedbyclient`.
- **Manual Redirect Validation**: Fallback HTTP fetcher disables automatic redirect following (`allow_redirects=False`) and inspects each hop manually up to 5 hops, aborting if any intermediate 3xx target resolves to a private IP.
- **Byte-Streaming Limit**: Enforces `MAX_HTML_SIZE_BYTES` (5 MB) during HTTP streaming to prevent memory exhaustion from zip bombs or unbounded streams.
- **Unresolvable Host Handling**: Unresolvable hostnames are explicitly classified as `UNREACHABLE` with reduced confidence, never marked as validated or safe.

### 2.2 Path Containment & Local Demonstration Security
- **No Localhost Exemption**: Localhost URLs are unconditionally rejected by SSRF guards.
- **Allow-List Test Page Registry**: Controlled demonstration pages are selected solely through verified IDs (`legit-portal`, `fake-login`, `fake-bank`, `fake-account`).
- **Path Containment Enforcement**: Demonstration files are resolved and verified against `resolved.is_relative_to(TEST_PAGES_DIR)`. Path traversal (`..`, `..%2f`), absolute paths, and symbolic links are strictly rejected with HTTP 400.

### 2.3 Headless Browser Concurrency & Sandboxing
- **Weakened Flags Removed**: Prohibits dangerous Chromium flags (`--no-sandbox`, `--disable-features=IsolateOrigins,site-per-process`, `--disable-web-security`).
- **Concurrency Control**: Concurrency is throttled via an asynchronous `Semaphore(MAX_CONCURRENT_BROWSERS=3)` to protect CPU and memory.
- **Context Isolation**: A single Chromium browser instance is maintained across requests, with every scan executing inside a fresh, isolated `BrowserContext` with blocked downloads, blocked popups, zero permissions, and disabled file choosers.

### 2.4 API Abuse & Information Disclosure Prevention
- **Sliding-Window Rate Limiting**: Per-IP sliding-window rate limiting (`60 req/min`) with automatic timestamp expiration.
- **Custom Weights Validation**: The `custom_weights` parameter is strictly validated: values must be finite floating-point numbers between 0.0 and 1.0, and the sum must be greater than 0. Malformed weights return HTTP 422, preventing `ZeroDivisionError`.
- **Sanitized 500 Responses**: Unhandled server exceptions log full stack traces internally while returning generic, safe error messages to clients.
- **Repo Hygiene & Data Retention**: Base64 screenshot payloads are excluded from database persistence. Screenshots in `temp_screenshots/` and scans exceeding retention TTL (1 hour) are automatically purged.

---

## 3. Multimodal Scoring Cascade & Additive Threat Rules

The `MultimodalFusionEngine` combines modality sub-scores with documented, bounded threat rules:

### 3.1 Modality Weighting Baseline
- **URL Lexical Risk**: 20% weight (`WEIGHT_URL = 0.20`)
- **Visual Brand & Layout Risk**: 40% weight (`WEIGHT_VISUAL = 0.40`)
- **Text & Semantic Coercion**: 25% weight (`WEIGHT_TEXT = 0.25`)
- **HTML & DOM Structure**: 15% weight (`WEIGHT_HTML = 0.15`)

$$\text{Weighted Base Score} = 0.20 \cdot S_{\text{url}} + 0.40 \cdot S_{\text{visual}} + 0.25 \cdot S_{\text{text}} + 0.15 \cdot S_{\text{html}}$$

### 3.2 Additive Threat Correlation Rules
When specific high-risk cross-modal signals correlate, additive threat rules fire and are logged in the audit trail:

1. **RULE_1_BRAND_IMPERSONATION_CREDENTIAL_HARVEST**:
   - Condition: Visual brand impersonation detected + password field or credential harvesting form.
   - Boost: +0.45 (Clamped to minimum 0.88).
2. **RULE_2_CROSS_DOMAIN_FORM_POST**:
   - Condition: Password or sensitive input element posts to an external third-party domain.
   - Boost: +0.35 (Clamped to minimum 0.85).
3. **RULE_3_EXCESSIVE_URGENCY_CREDENTIAL_INPUT**:
   - Condition: Critical NLP urgency/coercion detected alongside credential input fields.
   - Boost: +0.25 (Clamped to minimum 0.70).
4. **RULE_4_SUSPICIOUS_TLD_CREDENTIAL_PROMPT**:
   - Condition: High-risk suspicious TLD (`.xyz`, `.top`, `.sbs`, `.cc`) combined with login prompts.
   - Boost: +0.20 (Clamped to minimum 0.65).

### 3.3 Classification Thresholds
- **SAFE**: Final Risk Score $< 0.30$
- **SUSPICIOUS**: Final Risk Score between $0.30$ and $0.65$
- **PHISHING**: Final Risk Score $> 0.65$

---

## 4. Domain Trust & User-Content Infrastructure Disqualification

To prevent false positives on legitimate enterprise services while stopping attackers from abusing trusted infrastructure:
- **Registrable Domain Matching**: Apex domains are resolved using Public Suffix Rules via `tldextract` (e.g. `login.microsoft.com` resolves to `microsoft.com`).
- **Bounded Trust Discount**: High-reputation enterprise domains (`google.com`, `microsoft.com`, `apple.com`, `.gov`, `.edu`) receive a bounded discount of up to $-0.35$ on URL risk. Crucially, trust **never clamps final risk to 0.0 or overrides visual/DOM evidence**.
- **User-Content Exclusion**: Multi-tenant PaaS and user-uploaded content hosts (`sites.google.com`, `github.io`, `pages.dev`, `firebaseapp.com`, `blob.core.windows.net`) are **explicitly disqualified** from domain trust. Phishing pages hosted on these platforms are analyzed under full threat rules and correctly flagged as phishing.

---

## 5. Baseline ML Model Integration

The system incorporates a versioned scikit-learn Random Forest model (`baseline_model_v1.joblib`, `MODEL_VERSION = "v1.0-rf"`):
- **18-Dimensional Feature Vector**:
  1. `url_length`: Character length of the URL.
  2. `num_dots`: Count of period characters in hostname and path.
  3. `num_hyphens`: Subdomain and path hyphenation count.
  4. `has_ip_address`: Binary flag indicating direct IP address navigation.
  5. `num_subdomains`: Depth of subdomain labels.
  6. `has_at_symbol`: Userinfo `@` credential masking flag.
  7. `url_entropy`: Shannon entropy of the URL string.
  8. `has_suspicious_tld`: High-risk TLD indicator.
  9. `brand_in_subdomain`: Brand keyword spoofing count.
  10. `has_password_field`: Presence of `<input type="password">`.
  11. `has_cross_domain_form`: External credential POST action.
  12. `num_forms`: Total HTML form count.
  13. `num_inputs`: Total HTML input elements count.
  14. `has_disabled_rightclick`: Context menu suppression evasion flag.
  15. `text_risk`: Semantic NLP urgency and coercion score.
  16. `urgency_count`: Count of psychological urgency keywords.
  17. `credential_request_count`: Count of sensitive data collection phrases.
  18. `visual_risk`: Perceptual brand discrepancy score.
- **Inference Pipeline**: Loaded dynamically by `PhishingDetectionPipeline`. Feature predictions are returned under `analysis["ml_baseline"]` with class probabilities and feature vectors for transparent auditing.

---

## 6. System Architecture & Dataflow

```
[ User Browser / Analyst Dashboard ]
               │
               ▼
   [ POST /api/analyze ] ──► [ Sliding-Window Rate Limiter & Auth ]
               │
               ▼
     [ SSRF Guard & DNS Check ] ──(If unresolvable)──► [ SUSPICIOUS / Unreachable Verdict ]
               │
               ├──► [ BrowserWorker (Persistent Event Loop) ] ──► [ Pooled Chromium / Isolated Context ]
               │                                                            │
               │                                                            ▼
               │                                                  [ Hardened Screenshot & HTML ]
               │
               ├──► [ URL Feature Extractor (tldextract & Shannon Entropy) ]
               ├──► [ HTML Structural Parser (Forms, Password Inputs, Obfuscation) ]
               ├──► [ Text Semantic Analyzer (NLP Urgency & Coercion Keywords) ]
               ├──► [ DOM & Visual Brand Discrepancy Analyzer (Perceptual dHash) ]
               ├──► [ Traditional ML Baseline (18-Feature Random Forest Inference) ]
               │
               ▼
     [ Multimodal Fusion Engine (Additive Threat Rules & Calibrated Agreement) ]
               │
               ▼
     [ SQLite Scan Persistence (Base64 Screenshots Excluded) ]
               │
               ▼
     [ JSON Result + Transparent Audit Trail + Fired Rules ]
```

---

## 7. Installation & Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ and npm
- Playwright Chromium browser binaries

### Step 1: Clone Repository & Create Virtual Environment
```bash
git clone <repository-url>
cd IS

python -m venv .venv

# On Linux/macOS:
source .venv/bin/activate

# On Windows:
.venv\Scripts\activate
```

### Step 2: Install Python Dependencies
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
playwright install chromium
```

### Step 3: Configure Environment Variables
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
Default configuration values:
```ini
HOST=0.0.0.0
PORT=8000
DEBUG=True
ENVIRONMENT=development
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000
VLM_BACKEND=heuristic
WEIGHT_URL=0.20
WEIGHT_VISUAL=0.40
WEIGHT_TEXT=0.25
WEIGHT_HTML=0.15
THRESHOLD_SAFE=0.30
THRESHOLD_SUSPICIOUS=0.65
RATE_LIMIT_PER_MINUTE=60
MAX_CONCURRENT_BROWSERS=3
SCREENSHOT_TTL_SECONDS=3600
ENABLE_ML_BASELINE=True
```

### Step 4: Install Frontend Dependencies
```bash
cd frontend
npm install
cd ..
```

---

## 8. Running with vs. Without Heavy VLM Backends

The platform is architected with modular visual backends:

### Mode A: Lightweight Local Deployment (Default)
Fast, deterministic computer vision utilizing perceptual difference hashing (`dHash`), layout geometry analysis, and registrable domain discrepancy. Requires **zero GPU memory** and zero external model downloads.
```ini
# in .env:
VLM_BACKEND=heuristic
```
Start backend:
```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
Start frontend:
```bash
cd frontend
npm run dev
```

### Mode B: Deep HuggingFace Vision-Language Model
Instantiates neural Vision-Language Models (e.g. `HuggingFaceTB/SmolVLM-Instruct`, `vikhyatk/moondream2`) for visual reasoning. Requires PyTorch and GPU acceleration.
1. Install heavy dependencies:
   ```bash
   pip install -r requirements-vlm.txt
   ```
2. Update `.env`:
   ```ini
   VLM_BACKEND=huggingface
   VLM_MODEL_ID=HuggingFaceTB/SmolVLM-Instruct
   DEVICE=cuda
   ```
3. Start the application as normal.

---

## 9. Docker Hardened Deployment

The container environment implements non-root execution and security profiles:

```bash
# Build and run using Docker Compose
docker-compose up --build -d
```

### Security Controls Applied in Docker:
- **Unprivileged Non-Root User**: Runs under `appuser` (UID `10001`, GID `10001`).
- **No Weakened Flags**: Chromium runs with default seccomp profiles, keeping full browser sandboxing enabled.
- **Resource Constraints**: Backend container is restricted to 2.0 CPUs and 2048 MB RAM.
- **Dual Bridge Networks**: `frontend_net` and `backend_net` isolate the database and internal services from public ingress.
- **Healthchecks**: Built-in container healthprobe against `/health` with automatic restart on failure.

---

## 10. API Reference & Demonstration Workflow

### 10.1 Key Endpoints
| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Service health status and active VLM backend identifier. |
| `POST` | `/api/analyze` | Initiates multimodal scan of submitted URL or test page ID. |
| `GET` | `/api/test-pages` | Lists authorized local test pages for safe zero-day demonstration. |
| `GET` | `/api/scans` | Paginated scan history (limit, offset). |
| `GET` | `/api/scans/{id}` | Detailed multimodal breakdown for a specific scan. |
| `DELETE` | `/api/scans/{id}` | Purges scan record from database. |
| `GET` | `/api/stats` | Aggregated dashboard telemetry (total scans, phishing rate). |
| `GET` | `/api/metrics` | Serves authentic empirical zero-day evaluation metrics. |

### 10.2 Safe Demonstration Analysis
To demonstrate zero-day phishing detection without accessing live malicious websites, submit authorized test-page IDs:
```bash
# Analyze safe corporate portal
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"test_page_id": "legit-portal"}'

# Analyze Zero-Day Microsoft 365 credential harvesting page
curl -X POST http://localhost:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"test_page_id": "fake-login"}'
```

---

## 11. Running Regression & Acceptance Tests

The test suite covers unit features, SSRF guards, scoring cascades, API contracts, and the 7 core acceptance criteria.

```bash
# Run entire test suite (72 tests)
pytest tests/ -v
```

### Acceptance Test Suite (`tests/test_phase4_acceptance.py`):
1. **Local File Read Prevention**: Path traversal (`..`, `..%2f`) rejected via HTTP 400; no file outside `test_pages` can be read.
2. **SSRF Redirect & Subresource Defense**: 302 redirects to private IPs and Playwright subresources targeting metadata/loopback are blocked.
3. **Evasion Resistance**: Hidden `"offline or unreachable"` HTML text cannot bypass detection; authentic phishing pages score `PHISHING`.
4. **User-Content Host Security**: Credential phishing hosted on `sites.google.com` or `github.io` is strictly denied domain trust and scores `PHISHING`.
5. **Robust Input Validation**: `custom_weights` with zeros, negatives, or NaN return HTTP 422, never causing a 500 error.
6. **Authentic Metric Reporting**: `evaluate.py` generates verified `data/metrics.json` reflecting real zero-day campaign partitions.
7. **Container Hardening**: Chromium runs without weakened `--no-sandbox` flags under non-root UID 10001.

---

## 12. Benchmark Evaluation & Honest Metrics

To generate benchmark metrics across novel zero-day campaigns without training domain leakage:
```bash
# Train Random Forest baseline
python training/train_classifier.py

# Run zero-day evaluation benchmark
python training/evaluate.py
```

The benchmark saves results to `data/metrics.json` and reports:
- **Precision, Recall, F1 Score, and PR-AUC** across all modalities.
- **Strict Campaign-Aware Partitioning**: Zero domain overlap between training campaigns and test campaigns.
- **False Positive Rate at 95% True Positive Rate**: Measures operational viability in production environments.
- **Dynamic Frontend Integration**: The React dashboard displays actual empirical metrics from `GET /api/metrics` alongside exact sample sizes ($n$).

---

## 13. Operational Limitations

- **Multi-Step Authentication Workflows**: Single-page applications requiring SMS MFA prompts or multi-step reloads before rendering password fields may require extended interaction scripts.
- **IP / Geographic Cloaking**: Malicious infrastructure that selectively displays 404 pages to automated scrapers while serving phishing payloads to human victims cannot be evaluated if cloaking is active during scan time.
- **Offline / Unreachable Sites**: Sites that fail DNS resolution or drop network connections are classified as `SUSPICIOUS` with reduced confidence. The system explicitly reminds operators that **unreachable does not mean safe**, as attackers frequently dismantle zero-day infrastructure immediately after campaign execution.

---

## 14. Ethical Considerations

This project is developed exclusively for defensive cybersecurity research, threat analysis, and automated detection engineering. The bundled test pages are contained, non-functional simulations designed solely for demonstrating multimodal corroboration without harvesting or storing sensitive user credentials.
