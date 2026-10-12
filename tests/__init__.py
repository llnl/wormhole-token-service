import os
from pathlib import Path

from token_service.config import settings

CONFIG_DIR = Path(__file__).resolve().parent / "config"
PROJECT_DIR = CONFIG_DIR.parents[1]

# Used by settings.local.toml. `make` and tox export it too.
os.environ.setdefault("WORMHOLE_TOKEN_SVC_DIR", str(PROJECT_DIR))

# Run only once via import. Calling `settings.configure` again drops the test signing key.
settings.configure(
    FORCE_ENV_FOR_DYNACONF="testing",
    INCLUDES_FOR_DYNACONF=[
        str(CONFIG_DIR / "test_settings.toml"),
        str(CONFIG_DIR / "test_settings.local.toml"),
    ],
    PROJECT_DIR=str(PROJECT_DIR),
)
