# Enigma PQC Scanner v4.0 — Docker Image
# Supports both CLI scanning and API server mode.
#
# Build:  docker build -t enigma-pqc-scanner .
# Scan:   docker run -v /path/to/code:/scan enigma-pqc-scanner scan /scan
# Grade:  docker run -v /path/to/code:/scan enigma-pqc-scanner scan /scan --grade
# CBOM:   docker run -v /path/to/code:/scan enigma-pqc-scanner scan /scan --format cbom
# API:    docker run -p 8000:8000 enigma-pqc-scanner --api

FROM python:3.12-slim AS builder

WORKDIR /build

# Install build tools for tree-sitter grammars
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ && rm -rf /var/lib/apt/lists/*

# Install all Python dependencies
RUN pip install --no-cache-dir --prefix=/install \
    click reportlab cryptography fastapi uvicorn \
    tree-sitter \
    tree-sitter-python tree-sitter-java tree-sitter-go \
    tree-sitter-javascript tree-sitter-typescript tree-sitter-rust \
    tree-sitter-c tree-sitter-c-sharp tree-sitter-ruby \
    tree-sitter-php tree-sitter-kotlin tree-sitter-swift \
    tree-sitter-scala

# --- Final stage (no build tools) ---
FROM python:3.12-slim

LABEL maintainer="Ribbz (Jacob Ribbe)"
LABEL description="Enigma PQC Scanner — Post-Quantum Cryptography Migration Scanner"
LABEL version="4.0.0"

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy scanner source
COPY phases/phase6_scanner/ ./phases/phase6_scanner/
COPY api.py .
COPY conftest.py .
COPY demo/ ./demo/

# Set Python path so scanner imports work
ENV PYTHONPATH="/app/phases/phase6_scanner:${PYTHONPATH}"
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Entrypoint script handles both CLI and API modes
COPY <<'ENTRYPOINT' /app/entrypoint.sh
#!/bin/sh
if [ "$1" = "--api" ]; then
    shift
    exec uvicorn api:app --host 0.0.0.0 --port 8000 "$@"
else
    exec python -m pqc_scanner "$@"
fi
ENTRYPOINT
RUN chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["--help"]
