import argparse
import copy
import pytest
from unittest import mock

from token_service.command import seed_dev_user
from token_service.dependencies import LocalDevAuthenticator
from token_service.services import get_user


@pytest.fixture
def seed_args():
    def _fn(**kwargs) -> argparse.Namespace:
        defaults = {"uid": None, "admin": None}
        return argparse.Namespace(**(defaults | kwargs))

    return _fn


@pytest.fixture
def seed_config(config):
    """A per-test copy of the config, so mutations do not leak between tests."""

    return copy.deepcopy(config)


@pytest.fixture
def seed_settings(seed_config, engine):
    """Point the command's settings and engine at the test database.

    seed_dev_user builds its own UOW from settings, so without this it would
    reach for a different database than the one the fixtures set up.
    """

    with (
        mock.patch("token_service.command.settings") as settings,
        mock.patch("token_service.command.make_engine", return_value=engine),
    ):
        settings.to_dict.return_value = seed_config
        yield settings


def test_seed_creates_the_local_user(UOW, seed_args, seed_settings):
    # Execute
    seed_dev_user(seed_args(uid="dev_user", admin=True))

    # Verify
    user = get_user(UOW, "dev_user")
    assert user.uid == "dev_user"
    assert user.is_admin


def test_seed_defaults_to_the_local_machine_username(UOW, seed_args, seed_settings):
    # Setup/Execute
    with mock.patch(
        "token_service.command.local_username", return_value="machine_user"
    ):
        seed_dev_user(seed_args())

    # Verify
    assert get_user(UOW, "machine_user")


def test_seed_is_idempotent(UOW, seed_args, seed_settings):
    # Execute
    seed_dev_user(seed_args(uid="dev_user", admin=True))
    seed_dev_user(seed_args(uid="dev_user", admin=True))

    # Verify
    assert get_user(UOW, "dev_user").is_admin


def test_seed_reconciles_the_admin_flag(UOW, seed_args, seed_settings):
    # Setup
    seed_dev_user(seed_args(uid="dev_user", admin=True))
    assert get_user(UOW, "dev_user").is_admin

    # Execute
    seed_dev_user(seed_args(uid="dev_user", admin=False))

    # Verify
    assert not get_user(UOW, "dev_user").is_admin


def test_seed_falls_back_to_configured_is_admin(
    UOW, seed_args, seed_settings, seed_config
):
    # Setup
    seed_config["AUTH"]["local_dev"] = {"uid": "", "is_admin": False}

    # Execute -- admin=None means "take it from config"
    seed_dev_user(seed_args(uid="dev_user"))

    # Verify
    assert not get_user(UOW, "dev_user").is_admin


@pytest.mark.asyncio
async def test_seeded_user_authenticates(UOW, seed_args, seed_settings):
    """Both halves of the issue together: seed, then authenticate as that user."""

    # Setup
    seed_dev_user(seed_args(uid="dev_user", admin=True))

    # Execute
    user = await LocalDevAuthenticator(UOW, {"uid": "dev_user"})()

    # Verify
    assert user.uid == "dev_user"
    assert user.is_admin
