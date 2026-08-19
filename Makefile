.PHONY: prod dev test run-app run-dev run-prod pre-commit jwks migrate openapi seed ui

.NOTPARALLEL:

HOST ?= localhost
PORT ?= 5000

sync-dev:
	uv sync --dev --no-default-groups

sync-prod:
	uv sync --frozen

test: sync-dev
	uvx tox -e py311

run-dev: sync-dev seed
	uv run wormhole_token_service run --host $(HOST) --port $(PORT)

# find out command to run in production environment
#run-prod: sync-prod
#	uv run wormhole_token_service run --host $(HOST) --port $(PORT)

pre-commit:
	uvx pre-commit install

jwks:
	uv run wormhole_token_service generate-jwks --write-settings --overwrite

migrate:
	uv run alembic upgrade head

openapi:
	uv run wormhole_token_service openapi

seed: sync-dev
	uv run wormhole_token_service seed-dev-user
