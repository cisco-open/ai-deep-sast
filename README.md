# AI Deep SAST

LLM-powered deep static analysis tool that combines **Semgrep** static analysis
with **frontier model** vulnerability analysis for CI/CD pipelines.

Two scan modes:
- **Fast scan**: Semgrep + local Foundation-Sec-8B LLM for per-finding triage (~5 min)
- **Deep scan**: Tree-sitter indexing + frontier model (GPT-4o, Claude, etc.) for whole-codebase analysis (~30 min–14 hr depending on mode)

## Features

- Automated OWASP Top 10 vulnerability detection via Semgrep
- **Secret scanning**: built-in detection of hardcoded passwords, API keys, and tokens in config files (`.properties`, `.env`, `.conf`, `.cfg`, `.ini`)
- AI-powered analysis using [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct) (GGUF quantised)
- Structured 9-point security analysis per finding:
  - OWASP category mapping
  - CWE mapping
  - CVSS v3.1 score estimation
  - Attack vector with example payloads
  - Business and technical impact
  - Remediation with corrected code
  - Defence in depth recommendations
  - References (CWE, OWASP)
- **Severity-based filtering**: only analyse findings at or above a configurable threshold with the LLM
- **Smart LLM skipping**: deterministic rules (e.g. custom secret detection) use Semgrep metadata instead of LLM, dramatically reducing scan time
- Multiple report formats: Markdown, JSON, JUnit XML
- Quality gate with configurable severity thresholds
- Secure prompt handling (no code in shell history or process logs)
- Hybrid Jenkins CI/CD pipeline (Semgrep gate + AI on PRs)
- Docker support for reproducible environments
- YAML-based configuration with CLI and environment variable overrides
- Optimised for Apple Silicon Macs (Metal GPU acceleration)

## Architecture

```
Developer Pushes Code
        ↓
┌─────────────────────────────────┐
│  Stage 1: Semgrep Scan          │  ~3-5 seconds
│  Runs on EVERY commit           │
│                                 │
│  No findings? ──→ PASS ✅       │
│  Findings? ──→ Continue ↓       │
└─────────────────────────────────┘
        ↓
┌─────────────────────────────────┐
│  Stage 2: AI Analysis           │  ~40s per finding
│  Runs ONLY on:                  │
│    - Pull requests              │
│    - Manual triggers            │
│    - Forced via parameter       │
└─────────────────────────────────┘
        ↓
┌─────────────────────────────────┐
│  Stage 3: Quality Gate          │
│  Uses AI report if available    │
│  Falls back to Semgrep report   │
└─────────────────────────────────┘
        ↓
┌─────────────────────────────────┐
│  Post: Archive & Notify         │
│  Reports, JUnit, Slack/Email    │
└─────────────────────────────────┘
```


## Project Structure
```
ai-deep-sast/
├── aideepsast.py               # Fast-path scanner (Semgrep + Foundation-Sec-8B)
├── deepscan.py                 # Deep scan CLI (tree-sitter + frontier LLM)
├── deepscan_reporter.py        # Deep scan report generator
├── llm_client.py               # Generic OpenAI-compatible LLM client
├── detector.py                 # LLM-powered vulnerability detector
├── triager.py                  # Evidence-gated triage agent
├── finding_store.py            # SQLite finding store & work queue
├── indexer.py                  # Tree-sitter code indexer (15 languages)
├── redactor.py                 # Secret redaction before LLM calls
├── rule_matcher.py             # ASVS/CodeGuard rule matcher
├── requirements.txt            # Python dependencies
├── Dockerfile                  # Docker image
├── Jenkinsfile                 # CI/CD pipeline
├── config/
│   ├── scanner_config.yaml     # Default configuration
│   ├── custom-secrets.yaml     # Custom Semgrep rules for secret detection
│   ├── asvs/                   # ASVS 5.0 requirements (CC BY-SA 4.0, OWASP Foundation)
│   └── codeguard/              # CodeGuard security patterns
├── tests/                      # Test suite (220+ tests)
├── samples/                    # Sample vulnerable files
└── README.md                   # This file
```
---

## Quick Start (Local / Laptop)

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Python | 3.9+ | [python.org](https://www.python.org/downloads/) |
| Semgrep | 1.50+ | `pip install semgrep` |
| llama.cpp | Latest | `brew install llama.cpp` (macOS) |

### Hardware Requirements (Local)

| Hardware | Minimum | Recommended |
|----------|---------|-------------|
| **RAM** | 16 GB | 32 GB |
| **Disk** | 10 GB free (model cache) | 20 GB free |
| **CPU** | Apple M1 / Intel i7 | Apple M2 Pro+ |
| **GPU** | Apple Metal (unified memory) | Apple Metal / NVIDIA CUDA |

### Step 1: Clone and Install

```bash
git clone <repository-url>
cd ai-deep-sast

# Create and activate a virtual environment (recommended)
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies inside the virtual environment
pip install -r requirements.txt
```
### Step 2: Pre-Download the Model

This downloads the ~8 GB GGUF model once. Subsequent runs use the cached version.

```bash
llama-completion \
    --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
    --hf-file foundation-sec-8b-instruct-q8_0.gguf \
    -p "test" \
    -n 1
```

### Step 3: Verify Model Speed
```bash
time llama-completion \
    --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
    --hf-file foundation-sec-8b-instruct-q8_0.gguf \
    -c 2048 -ngl -1 -t 6 --temp 0.1 -n 256 \
    --no-display-prompt \
    -p "What is SQL injection? Explain in 3 sentences."
```
Expected: ~10-30 seconds on Apple Silicon.

### Step 4: Run Your First Scan
```bash
# Full scan with AI analysis
python3 aideepsast.py --target samples/sample_vuln.py

# Semgrep only (no AI, instant results)
python3 aideepsast.py --target samples/sample_vuln.py --skip-llm

# Using config file
python3 aideepsast.py \
    --config config/scanner_config.yaml \
    --target samples/sample_vuln.py
    ```

### Step 5: Review Reports
```bash
# Human-readable report
cat security-reports/owasp_ai_report.md

# Machine-readable report
python3 -m json.tool security-reports/owasp_ai_report.json

# Jenkins-compatible report
cat security-reports/owasp_junit_report.xml
```

## Usage

### Basic Commands
```bash
# Scan a single file
python3 aideepsast.py --target app.py

# Scan a directory
python3 aideepsast.py --target ./src

# Scan with custom severity threshold
python3 aideepsast.py --target ./src --severity-threshold ERROR

# Scan without AI (Semgrep only — fast)
python3 aideepsast.py --target ./src --skip-llm

# Scan with config file
python3 aideepsast.py --config config/scanner_config.yaml

# Scan with ERROR-only threshold (skip WARNING/INFO for LLM)
python3 aideepsast.py \
    --target ./src \
    --severity-threshold ERROR

# Disable LLM skipping for custom rules (analyse everything with AI)
python3 aideepsast.py \
    --target ./src \
    --skip-llm-rules ""

# Scan with all options
python3 aideepsast.py \
    --target ./src \
    --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
    --hf-file foundation-sec-8b-instruct-q8_0.gguf \
    --ctx-size 2048 \
    --n-gpu-layers -1 \
    --threads 6 \
    --max-tokens 1024 \
    --temperature 0.1 \
    --output-dir security-reports \
    --severity-threshold WARNING \
    --llm-timeout 600 \
    --log-level DEBUG
```

## CLI Arguments


| Argument | Description | Default |
|----------|-------------|---------|
| --target | File or directory to scan | . |
| --hf-repo | Hugging Face GGUF repo | fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF |
| --hf-file | GGUF model filename | foundation-sec-8b-instruct-q8_0.gguf |
| --ctx-size | Context window size | 2048 |
| --n-gpu-layers | GPU layers (-1 = all) | -1 |
| --threads | CPU threads | Auto-detected |
| --max-tokens | Max generation tokens | 1024 |
| --temperature | Generation temperature | 0.1 |
| --output-dir | Report output directory | security-reports |
| --severity-threshold | Fail threshold (INFO/WARNING/ERROR) | WARNING |
| --llm-timeout | LLM timeout in seconds | 600 |
| --semgrep-config | Semgrep ruleset(s), comma-separated | p/owasp-top-ten,p/secrets,config/custom-secrets.yaml |
| --semgrep-timeout | Semgrep timeout in seconds | 300 |
| --config | YAML config file path | None |
| --log-level | Log level (DEBUG/INFO/WARNING/ERROR) | INFO |
| --log-file | Log file path | None (console only) |
| --skip-llm | Skip AI analysis | false |
| --skip-llm-rules | Rule ID prefixes to skip LLM for (comma-separated) | config. |


## Configuration Priority

Settings are resolved in this order (highest to lowest):

- CLI arguments (`--target ./src`)
- Environment variables (`SCANNER_TARGET=./src`)
- YAML config file (`config/scanner_config.yaml`)
- Built-in defaults

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| SCANNER_TARGET | Target file or directory | . |
| SCANNER_HF_REPO | Hugging Face GGUF repo | fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF |
| SCANNER_HF_FILE | GGUF model filename | foundation-sec-8b-instruct-q8_0.gguf |
| SCANNER_CTX_SIZE | Context window size | 2048 |
| SCANNER_N_GPU_LAYERS | GPU layers (-1 = all) | -1 |
| SCANNER_THREADS | CPU threads | Auto-detected |
| SCANNER_MAX_TOKENS | Max generation tokens | 1024 |
| SCANNER_TEMPERATURE | Generation temperature | 0.1 |
| SCANNER_OUTPUT_DIR | Report output directory | security-reports |
| SCANNER_SEVERITY_THRESHOLD | Fail threshold (INFO/WARNING/ERROR) | WARNING |
| SCANNER_LLM_TIMEOUT | LLM timeout in seconds | 600 |
| SCANNER_SEMGREP_CONFIG | Semgrep ruleset(s), comma-separated | p/owasp-top-ten,p/secrets,config/custom-secrets.yaml |
| SCANNER_SEMGREP_TIMEOUT | Semgrep timeout in seconds | 300 |
| SCANNER_LOG_LEVEL | Log level (DEBUG/INFO/WARNING/ERROR) | INFO |
| SCANNER_LOG_FILE | Log file path | None (console only) |
| SCANNER_SKIP_LLM | Skip AI analysis | false

## Semgrep Rulesets

The scanner runs three Semgrep rulesets by default:

| Ruleset | Source | Detects |
|---------|--------|---------|
| `p/owasp-top-ten` | Semgrep Registry | OWASP Top 10 vulnerabilities (SQL injection, XSS, XXE, path traversal, etc.) |
| `p/secrets` | Semgrep Registry | Known vendor secret patterns (AWS keys, GitHub PATs, Stripe keys, etc.) |
| `config/custom-secrets.yaml` | Custom (this repo) | Hardcoded passwords, Redis credentials, API keys, and JDBC connection strings in config files |

### Custom Secret Detection Rules

The `config/custom-secrets.yaml` file contains 4 rules using Semgrep's `generic` language mode, which performs regex pattern matching on file types Semgrep cannot natively parse (e.g. `.properties`):

| Rule ID | Severity | Detects |
|---------|----------|---------|
| `hardcoded-password-properties` | ERROR | `password=`, `passwd=`, `pwd=`, `secret=`, `credential=` in `.properties`, `.env`, `.conf`, `.cfg`, `.ini` |
| `hardcoded-redis-password` | ERROR | `redis.sentinel.password:`, `redis.auth=`, etc. in config files |
| `hardcoded-api-key-properties` | ERROR | `api_key=`, `auth_token=`, `access_token=`, `bearer_token=` in config files |
| `hardcoded-jdbc-connection-string` | WARNING | JDBC URLs with hardcoded internal IP addresses |

These rules complement `p/secrets` which only matches known vendor token formats and cannot parse `.properties` files.

### Smart LLM Skipping

Findings from deterministic rules (where CWE, OWASP category, and remediation are already known from the Semgrep rule metadata) skip LLM analysis automatically. This is controlled by the `skip_llm_rules` setting:

```yaml
# In scanner_config.yaml
skip_llm_rules: "config."   # Skip LLM for all rules with IDs starting with "config."
```

```bash
# CLI override: skip LLM for multiple rule prefixes
python3 aideepsast.py --target ./src --skip-llm-rules "config.,generic."

# CLI override: disable skipping (analyse everything with LLM)
python3 aideepsast.py --target ./src --skip-llm-rules ""
```

This reduces scan time significantly when custom rules produce many findings (e.g. 92 secret findings across 21 `.properties` files would add ~60 minutes of LLM calls with no added value).

## Deep Scan

The deep scan analyses every function in your codebase using a frontier LLM (GPT-4o, Claude, etc.) via an OpenAI-compatible API. It supports 15 languages via tree-sitter: Python, Java, JavaScript, TypeScript, Go, C, C++, Ruby, Rust, Scala, Kotlin, C#, PHP, Swift, and Bash.

### Quick Start

```bash
# Set your LLM provider
export LLM_API_KEY=sk-proj-abc123...
export LLM_BASE_URL=https://api.openai.com/v1   # default
export LLM_MODEL=gpt-4o                          # default

# Run deep scan (index + detect + triage + report)
python3 deepscan.py --target ./src

# Dry run (index only, no LLM calls — free)
python3 deepscan.py --target ./src --dry-run

# Guided mode (faster, targeted — recommended)
python3 deepscan.py --target ./src --guided --guide-rules both
```

### LLM Provider Examples

```bash
# OpenAI
export LLM_API_KEY=sk-proj-...
export LLM_MODEL=gpt-4o

# Anthropic (via OpenAI-compatible proxy like LiteLLM)
export LLM_BASE_URL=http://localhost:4000/v1
export LLM_API_KEY=sk-ant-...
export LLM_MODEL=claude-sonnet-4-20250514

# Azure OpenAI
export LLM_BASE_URL=https://your-resource.openai.azure.com/openai/deployments/gpt-4o/
export LLM_API_KEY=your-azure-key

# Ollama (local, free)
export LLM_BASE_URL=http://localhost:11434/v1
export LLM_API_KEY=ollama
export LLM_MODEL=llama3.1:70b
```

### Deep Scan CLI Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--target` | File or directory to scan | (required) |
| `--output-dir` | Report output directory | security-reports |
| `--db-path` | SQLite database path | `<output-dir>/deepscan.db` |
| `--llm-url` | LLM API base URL | env `LLM_BASE_URL` or `https://api.openai.com/v1` |
| `--llm-api-key` | LLM API key | env `LLM_API_KEY` |
| `--llm-model` | Model name | env `LLM_MODEL` or `gpt-4o` |
| `--dry-run` | Index only, no LLM calls | false |
| `--guided` | Use rule-guided scanning | false |
| `--guide-rules` | Rule set: `asvs`, `codeguard`, `both`, `semgrep` | both |
| `--skip-exploratory` | Skip exploratory detection | false |
| `--show-needs-review` | Include needs-review findings | false |
| `--log-level` | Log level | INFO |
| `--json-summary` | Print JSON summary to stdout | false |

### Scan Modes

| Mode | Flag | Speed | Description |
|------|------|-------|-------------|
| Brute-force | (default) | Slowest | Every function analysed by LLM |
| ASVS-guided | `--guided --guide-rules asvs` | Fast | ASVS 5.0 requirements guide analysis |
| CodeGuard-guided | `--guided --guide-rules codeguard` | Fast | CodeGuard patterns guide analysis |
| Combined | `--guided --guide-rules both` | Fast | ASVS + CodeGuard combined |
| Semgrep-guided | `--guided --guide-rules semgrep` | Fastest | Semgrep findings validated by LLM |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No findings above threshold (pipeline passes) |
| 1 | Findings detected above threshold (pipeline fails) |
| 2 | Execution error (missing tools, I/O error, model load failure) |

## Reports

Reports are saved in the `security-reports/` directory by default. Each scan generates:

| File | Format | Purpose |
|------|--------|---------|
| `owasp_ai_report.md` | Markdown | Human-readable detailed report with AI analysis |
| `owasp_ai_report.json` | JSON | Machine-readable for integrations and dashboards |
| `owasp_junit_report.xml` | JUnit XML | Jenkins test result integration |


## Sample AI Analysis Output

For each finding, the AI provides:

1. OWASP Category: A03:2021 - Injection
2. CWE Mapping: CWE-78
3. CVSS Estimate: 8.8 (High) CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
4. Severity: ERROR
5. Attack Vector: Attacker inputs "; rm -rf /" via the host parameter
6. Impact: Unauthorized command execution, data loss
7. Remediation: [corrected code provided]
8. Defence in Depth: WAF rules, input validation, least privilege
9. References: CWE-78, OWASP Command Injection

## Production Deployment (Jenkins CI/CD)

### Prerequisites (Production)

| Component | Requirement |
|-----------|-------------|
| Jenkins | 2.375+ with Pipeline plugin |
| Docker | 20.10+ on Jenkins agents |
| Agent Resources | 16 GB+ RAM, GPU recommended |
| Network | Access to Hugging Face (first run) or pre-cached model |
| Plugins | Docker Pipeline, Pipeline Utility Steps, HTML Publisher, JUnit

### Step 1: Build the Docker Image

```bash
docker build -t your-registry/ai-deep-sast:latest .
docker push your-registry/ai-deep-sast:latest
```

### Step 2: Pre-Cache the Model (Recommended)

On the Jenkins agent or in the Docker image build, pre-download the model:

```bash
llama-completion \
    --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
    --hf-file foundation-sec-8b-instruct-q8_0.gguf \
    -p "test" \
    -n 1
```

Or mount a shared model cache volume on Jenkins agents:

```bash
# On the host, download once:
mkdir -p /model-cache
LLAMA_CACHE=/model-cache llama-completion \
    --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
    --hf-file foundation-sec-8b-instruct-q8_0.gguf \
    -p "test" -n 1
```

### Step 3: Add Jenkinsfile to Your Repository

The included Jenkinsfile implements the hybrid pipeline:

**Every commit**: Semgrep scan (~3-5 seconds)
**Pull requests**: Semgrep + AI analysis (if findings detected)
**Manual trigger**: Full scan with AI analysis

### Step 4: Create Jenkins Pipeline Job

1. Go to Jenkins → New Item → Pipeline
2. Under Pipeline, select "Pipeline script from SCM"
3. Point to your repository and set the script path to Jenkinsfile
4. Configure the Docker agent image in the Jenkinsfile

## Pipeline Behaviour

| Trigger | Semgrep | AI Analysis | Estimated Time |
|---------|---------|-------------|----------------|
| Commit (no findings) | ✅ | ❌ Skipped | ~5 seconds |
| Commit (findings) | ✅ | ❌ Skipped | ~5 seconds |
| PR (no findings) | ✅ | ❌ Skipped | ~5 seconds |
| PR (findings) | ✅ | ✅ Runs | ~5 minutes |
| Manual (findings) | ✅ | ✅ Runs | ~5 minutes |
| Force AI flag | ✅ | ✅ Runs | ~5 minutes |

## Jenkins Plugins Required

| Plugin | Purpose |
|--------|---------|
| Docker Pipeline | Run builds in Docker containers |
| Pipeline Utility Steps | Read/write JSON in pipeline |
| HTML Publisher | Display Markdown reports in Jenkins UI |
| JUnit | Parse and display test results |
| Slack Notification (optional) | Alert teams on failures |
| Email Extension (optional) | Send report emails |

## Testing

### Run Unit Tests:

```bash
# Ensure the virtual environment is active
source .venv/bin/activate

pip install pytest
python -m pytest tests/ -v
```

### Test Semgrep Only (No AI)
```bash
python3 aideepsast.py \
    --target samples/sample_vuln.py \
    --skip-llm \
    --output-dir test-reports
echo "Exit code: $?"
```

### Test Full Scan With AI
```bash
python3 aideepsast.py \
    --target samples/sample_vuln.py \
    --config config/scanner_config.yaml \
    --output-dir test-reports-full
echo "Exit code: $?"
```

### Test Secret Detection (Config Files)
```bash
# All sample config files — triggers custom secret rules
python3 aideepsast.py \
    --target samples/ \
    --skip-llm \
    --output-dir test-reports-secrets
echo "Exit code: $?"  # Should be 1 (secrets found)
```

### Test Java Source Code Scan
```bash
# Java OWASP vulnerabilities — SQLi, XXE, path traversal, weak SSL
python3 aideepsast.py \
    --target samples/SampleVuln.java \
    --skip-llm \
    --output-dir test-reports-java
echo "Exit code: $?"  # Should be 1
```

### Test Different Severity Thresholds
```bash
# Only fail on ERROR
python3 aideepsast.py \
    --target samples/sample_vuln.py --skip-llm \
    --severity-threshold ERROR

# Fail on everything including INFO
python3 aideepsast.py \
    --target samples/sample_vuln.py --skip-llm \
    --severity-threshold INFO
```

### Test Edge Cases
```bash
# Clean file (no vulnerabilities)
echo 'print("hello")' > /tmp/clean.py
python3 aideepsast.py --target /tmp/clean.py --skip-llm
echo "Exit code: $?"  # Should be 0

# Non-existent target
python3 aideepsast.py --target /nonexistent
echo "Exit code: $?"  # Should be 2
```

### Test Docker Build
```bash
docker build -t ai-deep-sast:local .
docker run --rm \
    -v $(pwd)/samples:/app/samples \
    -v $(pwd)/docker-reports:/app/security-reports \
    ai-deep-sast:local \
    --target samples/sample_vuln.py --skip-llm
```

## Docker Usage

The scanner can be run in a Docker container for reproducible environments and CI/CD integration.

### Build the Docker Image

```bash
docker build -t ai-deep-sast:latest .
```

### Run with Docker

```bash
# Basic scan (Semgrep only, no AI)
docker run --rm \
    -v $(pwd):/app/src \
    -v $(pwd)/docker-reports:/app/security-reports \
    ai-deep-sast:latest \
    --target src/ --skip-llm

# Full scan with AI analysis (mount model cache for faster startup)
docker run --rm \
    -v $(pwd):/app/src \
    -v $(pwd)/docker-reports:/app/security-reports \
    -v /model-cache:/root/.cache/llama.cpp \
    ai-deep-sast:latest \
    --target src/

# Scan with custom config
docker run --rm \
    -v $(pwd):/app/src \
    -v $(pwd)/docker-reports:/app/security-reports \
    ai-deep-sast:latest \
    --target src/ --severity-threshold ERROR --skip-llm
```

### Pre-Cache the Model (Recommended)

To avoid downloading the ~8 GB model on every container run, pre-cache it on the host:

```bash
# Create cache directory
mkdir -p /model-cache

# Download model once
docker run --rm \
    -v /model-cache:/root/.cache/llama.cpp \
    ai-deep-sast:latest \
    --target samples/sample_vuln.py

# Subsequent runs use the cached model
docker run --rm \
    -v $(pwd):/app/src \
    -v $(pwd)/docker-reports:/app/security-reports \
    -v /model-cache:/root/.cache/llama.cpp \
    ai-deep-sast:latest \
    --target src/
```

### Bake Model into Image (Alternative)

For air-gapped environments or faster cold starts, uncomment the model download section in the Dockerfile:

```dockerfile
# In Dockerfile, uncomment lines 74-80:
RUN mkdir -p /root/.cache/llama.cpp && \
    llama-completion \
        --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
        --hf-file foundation-sec-8b-instruct-q8_0.gguf \
        -p "test" \
        -n 1 && \
    echo "Model pre-cached successfully."
```

**Note**: This increases the image size by ~8 GB.

### Testing Checklist

| Test | Command | Expected |
|------|---------|----------|
| Unit tests | `pytest tests/ -v` | All pass |
| Semgrep only | `--skip-llm --target samples/sample_vuln.py` | Reports generated, exit 1 |
| Full AI scan | `--target samples/sample_vuln.py` | AI analysis in reports, exit 1 |
| Clean file | `--target /tmp/clean.py --skip-llm` | Exit 0 |
| Missing target | `--target /nonexistent` | Exit 2 |
| Config file | `--config config/scanner_config.yaml` | Config applied |
| Threshold ERROR | `--severity-threshold ERROR` | Only ERRORs fail |
| Docker build | `docker build` | Image builds |

## Performance

### Tested on Apple Silicon Mac (M-series, 18 GB unified memory):

| Metric | Value |
|--------|-------|
| Semgrep scan | ~3 seconds |
| Model loading (cached) | ~3-5 seconds |
| AI inference per finding | ~30-40 seconds |
| 9 findings full scan | ~5.5 minutes |
| Memory usage (Q8_0 model) | ~8-9 GB |

## Tuning for Faster Scans

```
# Reduce max tokens (faster, shorter analysis)
python3 aideepsast.py --target ./src --max-tokens 512

# Reduce context window
python3 aideepsast.py --target ./src --ctx-size 1024

# Use more CPU threads
python3 aideepsast.py --target ./src --threads 8
```

## Model Information

| Property | Value |
|----------|-------|
| Model | Foundation-Sec-8B-Instruct |
| Quantisation | Q8_0 (GGUF) |
| Size | ~8 GB |
| Hugging Face | fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF |
| Inference Engine | llama.cpp via llama-completion |
| Specialisation | Cybersecurity analysis and secure code review |
| Context Window | Up to 8192 tokens (default: 2048 for performance) |

## Why This Model?

- **Security-focused**: Trained specifically for cybersecurity tasks
- **Instruct-tuned**: Follows structured prompts accurately
- **GGUF quantised**: Runs efficiently on consumer hardware
- **Local execution**: No code leaves your machine
- **Open source**: Community-driven security foundation model

## Security Notes

- ✅ **Fast scan**: LLM runs 100% locally — no code is sent to external services
- ✅ **Deep scan**: Secret values are redacted before sending code to the LLM API
- ✅ Prompts are written to temporary files, never passed via CLI arguments
- ✅ API keys are loaded from environment variables, never hardcoded
- ⚠️ **Deep scan** sends source code (with secrets redacted) to your configured LLM provider
- ⚠️ Reports contain detailed vulnerability data — treat as confidential
- ⚠️ Add security-reports/ to your .gitignore
- ⚠️ Restrict Jenkins job visibility to authorised personnel

### .gitignore

Add the following to your .gitignore:
```
security-reports/
test-reports/
*.log
``` 
## Troubleshooting

### SSL Certificate Error (Hugging Face Download)

If you see SSL: CERTIFICATE_VERIFY_FAILED when downloading the model:

```
# Option 1: Install Python certificates (macOS)
/Applications/Python\ 3.13/Install\ Certificates.command

# Option 2: Set certificate bundle
export REQUESTS_CA_BUNDLE=$(python3 -c "import certifi; print(certifi.where())")
export SSL_CERT_FILE=$(python3 -c "import certifi; print(certifi.where())")

# Option 3: Pre-download on another machine and copy cache
scp -r ~/.cache/llama.cpp/ user@your-mac:~/.cache/llama.cpp/
```

### LLM Timeout

If llama-completion times out:

```
# Increase timeout
python3 aideepsast.py --target ./src --llm-timeout 600

# Pre-download the model first
llama-completion \
    --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
    --hf-file foundation-sec-8b-instruct-q8_0.gguf \
    -p "test" -n 1
```

### Out of Memory

If the model causes memory issues:

```
# Reduce context window
python3 aideepsast.py --target ./src --ctx-size 1024

# Reduce generation tokens
python3 aideepsast.py --target ./src --max-tokens 512

# Use CPU only (slower but less memory)
python3 aideepsast.py --target ./src --n-gpu-layers 0
```

### Semgrep Returns No Findings

If Semgrep finds no issues with code you expect to be flagged:
```
# Try a broader ruleset
python3 aideepsast.py --target ./src --semgrep-config p/python

# Check what Semgrep detects directly
semgrep --config=p/owasp-top-ten --json samples/sample_vuln.py | python3 -m json.tool
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Run tests: python -m pytest tests/ -v
4. Run a full scan against samples/sample_vuln.py
5. Submit a pull request

## License

Apache License 2.0 — See [LICENSE](LICENSE) for details.

This project uses [Foundation-Sec-8B-Instruct](https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Instruct),
which is built on Meta's Llama 3.1 architecture and is subject to the
[Llama Community License Agreement](https://github.com/meta-llama/llama-models/blob/main/README.md).

**Built with Llama**
