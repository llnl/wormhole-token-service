import pytest

from joserfc import jwt
from token_service import models
from token_service.config import settings
from token_service.store.orm import make_engine, reset_db
from token_service.service.uow import make_sql_uow


@pytest.fixture(scope="session")
def config():
    settings.SERVER.loop = "asyncio"
    settings.log_level = "debug"
    return settings.to_dict()


@pytest.fixture
def jwt_config(kid, public_pem, private_pem):
    key = {
        "public_pem": public_pem,
        "private_pem": private_pem,
        "key_type": "RSA",
    }

    settings.AUTH.JWT.alg = "RS256"
    settings.AUTH.JWT.active_kid = kid

    all_config = settings.to_dict()
    config = all_config["AUTH"]["jwt"]
    config["keys"][kid] = key

    return models.JWTConfig(config)


@pytest.fixture(scope="module")
def engine(config):
    return make_engine(config["DB"])


@pytest.fixture(autouse=True)
def clean_db(engine):
    reset_db(engine)


@pytest.fixture(scope="module")
def UOW(engine):
    return make_sql_uow(engine)


@pytest.fixture
def a_persisted_admin_user(make_user, UOW):
    with UOW() as uow:
        user = make_user(uid="admin_user", is_admin=True)
        uow.user_repo.add(user)
    return user


@pytest.fixture
def a_persisted_user(make_user, UOW):
    with UOW() as uow:
        user = make_user(uid="test", duid="123")
        uow.user_repo.add(user)

    return user


@pytest.fixture
def a_jwt(jwt_config, a_persisted_user):
    header = {"alg": jwt_config.alg, "kid": jwt_config.active_kid}
    payload = {
        "sub": a_persisted_user.uid,
    }

    return jwt.encode(header, payload, jwt_config.signing_secret)
