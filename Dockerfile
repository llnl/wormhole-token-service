FROM python:3.11-slim-bookworm

WORKDIR /app

ARG index_url
ARG project_version

COPY pyproject.toml pyproject.toml
COPY alembic alembic
COPY scripts scripts
COPY token_service/config/settings.toml settings.local.toml

RUN chgrp -R 0 /app && chmod -R g=u /app

# Install system dependencies for psycopg2
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    dnsutils \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install wormhole-token-service==$project_version \
    && pip install opentelemetry-distro opentelemetry-exporter-otlp \
# The opentelemetry-bootstrap -a install command reads through
# active site-packages folder, and installs the corresponding instrumentation
    && opentelemetry-bootstrap -a install

ENTRYPOINT ["opentelemetry-instrument", "wormhole_token_service", "run"]
