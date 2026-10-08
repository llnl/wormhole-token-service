FROM python:3.11-slim-bookworm

WORKDIR /app

ARG project_version="0.2.3"

COPY pyproject.toml pyproject.toml
COPY uv.lock uv.lock
COPY alembic alembic
COPY scripts scripts
COPY token_service/config/settings.toml settings.local.toml

RUN chgrp -R 0 /app && chmod -R g=u /app

# libpq-dev for psycopg2
# libkrb5-dev for gssapi (krb5 headers and krb5-config on PATH)
RUN apt-get update && apt-get install -y \
    gcc \
    libkrb5-dev \
    libpq-dev \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install dependencies exactly as pinned in uv.lock; --locked fails the build
# if uv.lock is out of date with pyproject.toml
RUN --mount=from=ghcr.io/astral-sh/uv:0.12.23,source=/uv,target=/bin/uv \
    uv export --locked --no-dev --extra all --no-emit-project \
        --output-file /tmp/requirements.txt \
    && pip install --no-deps --requirement /tmp/requirements.txt \
    && pip install --no-deps "wormhole-token-service==$project_version" \
    # OpenTelemetry is not in uv.lock
    && pip install opentelemetry-distro opentelemetry-exporter-otlp \
    # The opentelemetry-bootstrap -a install command reads through
    # active site-packages folder, and installs the corresponding instrumentation
    && opentelemetry-bootstrap -a install \
    # Restore any locked version OpenTelemetry changed; pip check then fails
    # if OpenTelemetry needs the changed version
    && pip install --no-deps --requirement /tmp/requirements.txt \
    && pip check \
    && rm /tmp/requirements.txt

ENTRYPOINT ["opentelemetry-instrument", "wormhole_token_service", "run"]
