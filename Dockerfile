# Reproducible Falsify environment (plan §9): pinned Python, Foundry, solc, Slither, Echidna.
FROM python:3.11-slim

ARG FOUNDRY_VERSION=1.8.3
ARG ECHIDNA_VERSION=2.3.3
ARG SOLC_VERSION=0.8.24

ENV DEBIAN_FRONTEND=noninteractive \
    PATH="/root/.foundry/bin:/opt/venv/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl git ca-certificates build-essential \
    && rm -rf /var/lib/apt/lists/*

# Foundry (forge), pinned.
RUN curl -fsSL https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup --install "${FOUNDRY_VERSION}"

# Echidna, pinned, for this image's CPU architecture (x86_64 or aarch64).
RUN curl -fsSL "https://github.com/crytic/echidna/releases/download/v${ECHIDNA_VERSION}/echidna-${ECHIDNA_VERSION}-$(uname -m)-linux.tar.gz" \
        | tar -xz -C /usr/local/bin echidna \
    && echidna --version

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY falsify ./falsify

RUN python -m venv /opt/venv \
    && pip install --no-cache-dir -e ".[dev,analysis]" \
    && solc-select install "${SOLC_VERSION}" 0.8.20 \
    && solc-select use "${SOLC_VERSION}"

COPY . .

# Default: run the deterministic end-to-end demo.
CMD ["python", "-m", "falsify.cli", "demo"]
