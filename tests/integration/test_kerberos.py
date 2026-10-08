"""The Kerberos token endpoint through the real app (`make_app`).

Runs against k5test or a live realm, selected by `TEST.KERBEROS.mode`.
As close to end-to-end as possible without starting a server.
"""

import pytest
from fastapi import status
from fastapi.testclient import TestClient

from token_service.auth.kerberos import KerberosConfigError
from token_service.server import make_app
from token_service.services import list_user_tokens

from .krb5_harness import initiate, negotiate_header

pytestmark = pytest.mark.integration


# TODO: fix test ordering error
@pytest.fixture(scope="module")
def krb_base_config(config, kid, public_pem, private_pem):
    """App config with a coherent JWT block, independent of run order.

    `make_app` builds a `JWTConfig`, which resolves `active_kid` against
    `keys`. `tests/e2e/conftest.py` mutates the shared `settings`
    singleton's `active_kid` but injects the matching key only into its own
    dict copy, so a config derived from `settings` after e2e has run names a
    kid that is not in `keys` and raises `KeyError`. Pinning a matched pair
    here keeps this module independent of whether e2e ran first.
    """

    cfg = {**config}
    cfg["AUTH"] = {**cfg["AUTH"]}
    jwt_cfg = {**cfg["AUTH"]["jwt"]}
    jwt_cfg["alg"] = "RS256"
    jwt_cfg["active_kid"] = kid
    jwt_cfg["keys"] = {
        **jwt_cfg.get("keys", {}),
        kid: {
            "public_pem": public_pem,
            "private_pem": private_pem,
            "key_type": "RSA",
        },
    }
    cfg["AUTH"]["jwt"] = jwt_cfg
    return cfg


@pytest.fixture(scope="module")
def krb_config(krb_base_config, krb5_env):
    """App config with Kerberos enabled and pointed at the test realm."""

    cfg = {**krb_base_config}
    cfg["AUTH"] = {**cfg["AUTH"]}
    cfg["AUTH"]["kerberos"] = {
        "enabled": True,
        "service_name": krb5_env.service_name,
        "allowed_realms": [krb5_env.realm],
    }
    return cfg


@pytest.fixture(scope="module")
def krb_app(krb_config):
    return make_app(krb_config)


@pytest.fixture(scope="module")
def krb_client(krb_app):
    return TestClient(krb_app)


@pytest.fixture
def a_kerberos_user(make_user, UOW, krb5_env):
    """A seeded User matching the principal the fixture authenticates as.

    An unknown uid is a 401 with no auto-provisioning, so the row has to exist
    before a handshake can produce a token.
    """

    with UOW() as uow:
        user = make_user(uid=krb5_env.uid, duid="krb-duid")
        uow.user_repo.add(user)
    return user


def _negotiate(service_name):
    _, client_token = initiate(service_name)
    return {"Authorization": negotiate_header(client_token)}


def test_endpoint_is_mounted_under_the_versioned_prefix(krb_app, config):
    """The route goes through bind_endpoints like every other router."""

    paths = {route.path for route in krb_app.routes}
    version = config["API_VERSION"]

    assert f"/api/{version}/krb/token" in paths
    # bind_endpoints emits one mount per declared version.
    assert "/api/latest/krb/token" in paths


@pytest.mark.parametrize(
    "realms",
    [pytest.param([], id="empty"), pytest.param(["A.GOV", "B.GOV"], id="two")],
)
def test_app_refuses_to_start_unless_exactly_one_realm_is_allowed(
    krb_base_config, realms
):
    """Enabling Kerberos without exactly one realm stops `make_app`."""

    cfg = {**krb_base_config}
    cfg["AUTH"] = {
        **cfg["AUTH"],
        "kerberos": {"enabled": True, "allowed_realms": realms},
    }

    with pytest.raises(KerberosConfigError, match="exactly one realm"):
        make_app(cfg)


def test_endpoint_is_absent_when_disabled(krb_base_config):
    """`gssapi` stays optional and the spec is unchanged without Kerberos."""

    cfg = {**krb_base_config}
    cfg["AUTH"] = {**cfg["AUTH"], "kerberos": {"enabled": False}}

    paths = {route.path for route in make_app(cfg).routes}

    assert not any("/krb/token" in path for path in paths)


def test_creates_a_token_for_the_authenticated_principal(
    krb_client, service_name, a_kerberos_user, UOW, config
):
    """The happy path: a valid Negotiate header mints a real token row."""

    version = config["API_VERSION"]
    response = krb_client.post(
        f"/api/{version}/krb/token",
        headers=_negotiate(service_name),
        data={"name": "krb-token"},
    )

    assert response.status_code == status.HTTP_201_CREATED

    # The response contract matches POST /token: the bare token string.
    token_value = response.json()
    assert isinstance(token_value, str)
    assert "." in token_value

    # A row was actually created and belongs to the Kerberos principal.
    tokens = list_user_tokens(UOW, a_kerberos_user.uid)
    assert [t.name for t in tokens] == ["krb-token"]


def test_completed_handshake_returns_a_mutual_auth_token(
    krb_client, service_name, a_kerberos_user, config
):
    """The reply carries WWW-Authenticate so the client can verify the server."""

    version = config["API_VERSION"]
    client_ctx, client_token = initiate(service_name)
    response = krb_client.post(
        f"/api/{version}/krb/token",
        headers={"Authorization": negotiate_header(client_token)},
        data={"name": "krb-mutual"},
    )

    assert response.status_code == status.HTTP_201_CREATED
    challenge = response.headers.get("WWW-Authenticate", "")
    assert challenge.startswith("Negotiate ")


def test_unknown_principal_is_401_not_auto_provisioned(
    krb_client, service_name, UOW, config
):
    """No seeded User means 401, matching every other authenticator."""

    version = config["API_VERSION"]
    response = krb_client.post(
        f"/api/{version}/krb/token",
        headers=_negotiate(service_name),
        data={"name": "krb-nobody"},
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize(
    "header",
    [
        pytest.param("Negotiate Z2FyYmFnZQ==", id="not_a_gss_token"),
    ],
)
def test_unusable_credentials_are_challenged_not_crashed(krb_client, config, header):
    """Every bad-credential path is a 401 challenge, never a 500."""

    version = config["API_VERSION"]
    headers = {"Authorization": header} if header is not None else {}
    response = krb_client.post(
        f"/api/{version}/krb/token", headers=headers, data={"name": "krb-bad"}
    )

    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.headers["WWW-Authenticate"].startswith("Negotiate")
