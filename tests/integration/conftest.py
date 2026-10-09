import pytest

from joserfc import jwt
from token_service import models
from token_service.config import settings
from token_service.store.orm import make_engine, reset_db
from token_service.service.uow import make_sql_uow

from .krb5_harness import gss_name, k5test_env


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


@pytest.fixture(scope="session")
def krb5_env():
    """An ephemeral k5test realm, shared by the whole session.

    Session-scoped on purpose: `k5test` sets process-wide GSSAPI state
    (KRB5_CONFIG, KRB5_KTNAME, KRB5CCNAME).

    Yields:
        A `Krb5Env` describing the realm.
    """

    yield from k5test_env()


@pytest.fixture(scope="session")
def service_name(krb5_env):
    """The SPN clients target and the server accepts as.

    Under `k5test` this is `host/<hostname>`, which `K5Realm` seeds into
    the default keytab for free. Under `live` it is whatever
    `TEST.KERBEROS.service_name` says. The handshake is identical either way.
    """

    return gss_name(krb5_env.service_name)
