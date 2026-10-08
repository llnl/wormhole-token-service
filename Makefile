.PHONY: sync-dev sync-prod lock lock-check build refresh test run-dev \
        run-prod pre-commit jwks migrate openapi seed run-local-docker-krb test-krb5

.NOTPARALLEL:

export WORMHOLE_TOKEN_SVC_DIR := $(CURDIR)
HOST ?= localhost
PORT ?= 5000

sync-dev:
	uv sync --dev

sync-prod:
	uv sync --frozen --no-dev --extra all

lock-check:
	uv lock --check

lock:
	uv lock

build:
	rm -rf dist/
	uv build --wheel

refresh: lock lock-check build

test: sync-dev
	uvx tox -e py311

run-dev: sync-dev seed
	uv run wormhole_token_service run --host $(HOST) --port $(PORT)

# find out command to run in production environment
#run-prod: sync-prod
#	uv run wormhole_token_service run --host $(HOST) --port $(PORT)

# Local Docker KDC (docker-compose.krb5.yml); its files land in .krb5/.
KRB5_DIR := $(CURDIR)/.krb5

run-local-docker-krb:
	docker compose -f docker-compose.krb5.yml up -d --wait

pre-commit:
	uvx pre-commit run

jwks:
	uv run wormhole_token_service generate-jwks --write-settings --overwrite

migrate:
	uv run alembic upgrade head

openapi:
	uv run wormhole_token_service openapi

seed: sync-dev
	uv run wormhole_token_service seed-dev-user

# depends on app database
test-krb5: run-local-docker-krb
	DYNACONF_TEST__KERBEROS__mode=live \
	DYNACONF_TEST__KERBEROS__service_name=HTTP/localhost@WORMHOLE.TEST \
	DYNACONF_TEST__KERBEROS__keytab=$(KRB5_DIR)/service.keytab \
	DYNACONF_TEST__KERBEROS__krb5_config=$(KRB5_DIR)/krb5.conf \
	DYNACONF_TEST__KERBEROS__client_principal=svc-tokentest@WORMHOLE.TEST \
	DYNACONF_TEST__KERBEROS__client_keytab=$(KRB5_DIR)/client.keytab \
	DYNACONF_TEST__KERBEROS__allowed_realms=WORMHOLE.TEST \
	uv run pytest tests/integration/test_kerberos_live_config.py tests/integration/test_kerberos.py -m integration -v
