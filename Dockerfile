# syntax=docker/dockerfile:1.7
# Multi-stage build for HoneyTrap AI.
#
# Stage 1 installs the package (and its "full" extras) into an isolated
# prefix so stage 2 can copy a clean site-packages tree on top of a
# minimal runtime base. Running as a non-root user with a tiny curl
# install keeps the final image small and suitable for HEALTHCHECK.

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /src

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential gcc \
 && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src ./src
COPY profiles ./profiles
COPY templates ./templates

RUN pip install --prefix=/install .


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/install/bin:${PATH}" \
    PYTHONPATH="/install/lib/python3.12/site-packages"

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --system --gid 10001 honeytrap \
 && useradd --system --uid 10001 --gid honeytrap --home /app --shell /usr/sbin/nologin honeytrap \
 && mkdir -p /app/data /app/profiles \
 && chown -R honeytrap:honeytrap /app

COPY --from=builder /install /install
COPY --from=builder /src/profiles /app/profiles
COPY --from=builder /src/templates /app/templates

WORKDIR /app
USER honeytrap

EXPOSE 21 22 23 25 80 445 3306 9200

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl --fail --silent http://127.0.0.1:9200/healthz || exit 1

ENTRYPOINT ["honeytrap"]
CMD ["--profile", "web_server", "--dashboard-mode", "none"]
