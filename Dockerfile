# syntax=docker/dockerfile:1
#
# SIEM Log Correlation Engine - production image
#
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# tini reaps the worker/ingestor child processes and forwards signals (PID 1)
RUN apt-get update \
    && apt-get install -y --no-install-recommends tini \
    && rm -rf /var/lib/apt/lists/*

# Runtime dependencies first (better layer caching)
COPY requirements.txt requirements-prod.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-prod.txt

# Application source and assets
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY config ./config
COPY rules ./rules
COPY scripts ./scripts
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# Install the package (no deps; already installed above) and create a
# non-root runtime user that owns the writable data/log directories.
RUN pip install --no-cache-dir --no-deps -e . \
    && sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh \
    && useradd --create-home --uid 10001 --shell /usr/sbin/nologin siem \
    && mkdir -p /app/data /app/logs \
    && chown -R siem:siem /app

USER siem

# 5000 = dashboard/API, 5514 = syslog (mapped from host 514 in compose)
EXPOSE 5000 5514/udp 5514/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/health').status==200 else 1)"

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["run", "--web"]
