# syntax=docker/dockerfile:1.7
#
# TrustModel Edge — multi-arch container (amd64 + arm64).
#
# Two-stage build to keep the runtime layer below the 200MB acceptance
# bar set in TRUS-986:
#   • builder stage compiles wheels (needs gcc, build-essential)
#   • runtime stage installs only the pre-built wheels into python:3.12-slim
#
# Build:
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     -t ghcr.io/pdxlab/trustmodel-edge:0.1.0 --push .

ARG PYTHON_VERSION=3.12

# ─── Stage 1: builder ────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM python:${PYTHON_VERSION}-slim AS builder

WORKDIR /build

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install --no-install-recommends -y build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --upgrade pip build \
 && pip wheel --wheel-dir /wheels .

# ─── Stage 2: runtime ────────────────────────────────────────────────
FROM python:${PYTHON_VERSION}-slim AS runtime

ARG APP_USER=edge
ARG APP_UID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    EDGE_HOST=0.0.0.0 \
    EDGE_PORT=8080

WORKDIR /app

RUN groupadd --gid ${APP_UID} ${APP_USER} \
 && useradd  --uid ${APP_UID} --gid ${APP_UID} \
             --home-dir /app --shell /usr/sbin/nologin ${APP_USER} \
 && mkdir -p /etc/trustmodel /var/lib/trustmodel \
 && chown -R ${APP_USER}:${APP_USER} /etc/trustmodel /var/lib/trustmodel /app

COPY --from=builder /wheels /tmp/wheels
RUN pip install --no-index --find-links=/tmp/wheels edge \
 && rm -rf /tmp/wheels /root/.cache

USER ${APP_USER}

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import sys, urllib.request as r; sys.exit(0 if r.urlopen('http://127.0.0.1:8080/health/live', timeout=4).status == 200 else 1)"

ENTRYPOINT ["python", "-m", "edge"]
