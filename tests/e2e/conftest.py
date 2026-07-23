import pytest

from joserfc import jwt
from tenacity import retry, wait_fixed
from threading import Thread
from unittest import mock

from token_service.config import settings
from token_service.store.orm import make_engine, reset_db
from token_service.server import make_server
from token_service.service.uow import make_sql_uow

from tests.helpers.fake_deps import FakeOIDCAuthenticator, FakeJWTAuthenticator


@pytest.fixture(scope="session")
def claims_registry():
    return jwt.JWTClaimsRegistry(leeway=1)


@pytest.fixture(scope="session")
def config(private_pem, public_pem, kid):
    key = {
        "public_pem": public_pem,
        "private_pem": private_pem,
        "key_type": "RSA",
    }

    settings.SERVER.loop = "asyncio"
    settings.log_level = "debug"
    settings.AUTH.JWT.alg = "RS256"
    settings.AUTH.JWT.active_kid = kid

    config = settings.to_dict()
    config["AUTH"]["jwt"]["keys"][kid] = key
    return config


@pytest.fixture(scope="module")
def engine(config):
    return make_engine(config["DB"])


@pytest.fixture(autouse=True)
def clean_db(engine):
    reset_db(engine)


@pytest.fixture(scope="module")
def UOW(engine):
    return make_sql_uow(engine)


@pytest.fixture(scope="session")
async def server(config):
    with (
        mock.patch(
            "token_service.server.AuthenticatorFactory.make_authenticator",
            new=FakeOIDCAuthenticator,
        ),
        mock.patch("token_service.server.JWTAuthenticator", new=FakeJWTAuthenticator),
    ):
        server = make_server(config)

        t = Thread(target=server.run)
        t.start()

        @retry(wait=wait_fixed(3))
        def wait_up():
            if not server.started:
                raise

        wait_up()
        yield f"http://{server.config.host}:{server.config.port}"
        server.should_exit = True
        t.join()


@pytest.fixture(scope="session")
async def server_api(server):
    yield f"{server}/api"
