FROM python:3.11-slim-bookworm

WORKDIR /app

ARG project_version="0.2.3"

COPY pyproject.toml pyproject.toml
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

RUN pip install "wormhole-token-service[all]==$project_version" \
    && pip install opentelemetry-distro opentelemetry-exporter-otlp \
# The opentelemetry-bootstrap -a install command reads through
# active site-packages folder, and installs the corresponding instrumentation
    && opentelemetry-bootstrap -a install

ENTRYPOINT ["opentelemetry-instrument", "wormhole_token_service", "run"]
