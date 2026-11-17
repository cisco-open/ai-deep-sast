# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

# Multi-stage build:
#   Stage 1: Build llama.cpp from source
#   Stage 2: Production image with scanner + model
# ============================================================

# ============================================================
# STAGE 1: Build llama.cpp
# ============================================================
FROM ubuntu:22.04 AS llama-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Clone and build llama.cpp
RUN git clone https://github.com/ggerganov/llama.cpp.git /llama.cpp && \
    cd /llama.cpp && \
    cmake -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build --config Release -j$(nproc) && \
    cp build/bin/llama-completion /usr/local/bin/llama-completion && \
    chmod +x /usr/local/bin/llama-completion

# ============================================================
# STAGE 2: Production Image
# ============================================================
FROM python:3.11-slim

LABEL maintainer="security-team"
LABEL description="AI Deep SAST — LLM-powered deep static analysis"
LABEL model="fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF"

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV SCANNER_OUTPUT_DIR=security-reports
ENV SCANNER_HF_REPO=fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF
ENV SCANNER_HF_FILE=foundation-sec-8b-instruct-q8_0.gguf

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    libgomp1 \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy llama-completion from builder stage
COPY --from=llama-builder /usr/local/bin/llama-completion /usr/local/bin/llama-completion

# Verify llama-completion works
RUN llama-completion --version || echo "llama-completion installed (version check may return non-zero)"

# Install Python dependencies and verify semgrep
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt && \
    semgrep --version

# ============================================================
# Pre-download the model (optional but recommended)
# Uncomment the following lines to bake the model into the image.
# This makes the image ~8 GB larger but eliminates download time
# at runtime.
#
# If you prefer to mount the model cache at runtime instead,
# leave these lines commented and use:
#   docker run -v /model-cache:/root/.cache/llama.cpp ...
# ============================================================
# RUN mkdir -p /root/.cache/llama.cpp && \
#     llama-completion \
#         --hf-repo fdtn-ai/Foundation-Sec-8B-Instruct-Q8_0-GGUF \
#         --hf-file foundation-sec-8b-instruct-q8_0.gguf \
#         -p "test" \
#         -n 1 && \
#     echo "Model pre-cached successfully."

# Copy legal notices and license files
COPY LICENSE /app/LICENSE
COPY THIRD-PARTY-NOTICES.txt /app/THIRD-PARTY-NOTICES.txt
COPY foundation-sec-model/LICENSE_APACHE2.md /app/foundation-sec-model/LICENSE_APACHE2.md
COPY foundation-sec-model/LICENSE_LLAMA31.md /app/foundation-sec-model/LICENSE_LLAMA31.md
COPY foundation-sec-model/NOTICE.md /app/foundation-sec-model/NOTICE.md

# Copy application code
COPY aideepsast.py /app/aideepsast.py
COPY deepscan.py /app/deepscan.py
COPY deepscan_reporter.py /app/deepscan_reporter.py
COPY llm_client.py /app/llm_client.py
COPY detector.py /app/detector.py
COPY triager.py /app/triager.py
COPY finding_store.py /app/finding_store.py
COPY indexer.py /app/indexer.py
COPY redactor.py /app/redactor.py
COPY rule_matcher.py /app/rule_matcher.py
COPY asvs_loader.py /app/asvs_loader.py
COPY codeguard_loader.py /app/codeguard_loader.py
COPY config/ /app/config/
COPY samples/ /app/samples/

WORKDIR /app

# Health check
HEALTHCHECK --interval=60s --timeout=30s --retries=3 \
    CMD ["sh", "-c", "semgrep --version && llama-completion --version || true"]

# Default entrypoint
ENTRYPOINT ["python3", "aideepsast.py"]
CMD ["--config", "config/scanner_config.yaml"]


