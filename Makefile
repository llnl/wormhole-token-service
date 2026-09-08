.PHONY: sync-dev sync-prod lock lock-check build-ui build refresh test run-dev \
        run-prod pre-commit jwks migrate openapi seed

.NOTPARALLEL:

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

# Build the frontend into token_service/ui/dist so the wheel can bundle it
# The server mounts these assets at / when present.
build-ui:
	cd token_service/ui && npm ci && npm run build

build: build-ui
	rm -rf dist/
	uv build --wheel

# Everything derived from pyproject.toml, regenerated in dependency order. Run
# this after changing dependencies or extras: the lockfile records extra names,
# and the wheel bakes in the metadata, so both go stale on a rename.
refresh: lock lock-check build

test: sync-dev
	uvx tox -e py311

run-dev: sync-dev seed
	uv run wormhole_token_service run --host $(HOST) --port $(PORT)

# find out command to run in production environment
#run-prod: sync-prod
#	uv run wormhole_token_service run --host $(HOST) --port $(PORT)

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
