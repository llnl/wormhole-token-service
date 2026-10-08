import base64
import pytest
import json
import time
import inspect
import requests
from unittest import mock
from fastapi import HTTPException, Response, status
from tests.helpers.fake_deps import fake_gssapi
from token_service.dependencies import (
    AuthenticatorFactory,
    LocalDevAuthenticator,
    require_admin,
    JWTAuthenticator,
)

# Treat unawaited coroutine warnings as errors for this file
pytestmark = pytest.mark.filterwarnings(
    "error:coroutine.*was never awaited:RuntimeWarning"
)


@pytest.fixture(scope="session")
def oauth_jwt_config(config):
    return config["AUTH"]["oauth_jwt"]


@pytest.fixture
def a_jwks_response(jwt_config):
    resp = requests.Response()
    resp.status_code = 200
    resp._content = json.dumps(jwt_config.jwks.keys).encode()
    return resp


@pytest.mark.asyncio
async def test_require_admin(a_persisted_admin_user):
    # Setup
    stub_user_auth = mock.AsyncMock(return_value=a_persisted_admin_user)
    wrapped = require_admin(stub_user_auth)

    # Execute
    user = await wrapped()

    # Verify
    assert user is a_persisted_admin_user
    assert stub_user_auth.await_count == 1
    assert inspect.iscoroutinefunction(wrapped)


@pytest.mark.asyncio
async def test_require_admin_fails_when_not_admin(a_persisted_user):
    # Setup
    stub_user_auth = mock.AsyncMock(return_value=a_persisted_user)
    wrapped = require_admin(stub_user_auth)

    # Execute and Verify
    with pytest.raises(Exception):
        await wrapped()
    assert stub_user_auth.await_count == 1
    assert inspect.iscoroutinefunction(wrapped)


@pytest.mark.asyncio
async def test_local_dev_authenticator_returns_configured_user(UOW, a_persisted_user):
    # Setup
    auth = LocalDevAuthenticator(UOW, {"uid": a_persisted_user.uid})

    # Execute
    user = await auth()

    # Verify
    assert user.uid == a_persisted_user.uid


@pytest.mark.asyncio
async def test_local_dev_authenticator_defaults_to_local_username(UOW):
    # Setup
    with mock.patch(
        "token_service.dependencies.local_username", return_value="machine_user"
    ):
        auth = LocalDevAuthenticator(UOW, {})

    # Verify
    assert auth.uid == "machine_user"


@pytest.mark.asyncio
async def test_local_dev_authenticator_401s_when_user_not_seeded(UOW):
    # Setup
    auth = LocalDevAuthenticator(UOW, {"uid": "never_seeded"})

    # Execute and Verify
    with pytest.raises(Exception) as excinfo:
        await auth()
    assert "seed-dev-user" in str(excinfo.value.detail)


@pytest.mark.asyncio
async def test_local_dev_authenticator_takes_no_request_parameters(UOW):
    """FastAPI derives the request contract from __call__'s signature.

    An empty signature is what makes the endpoint require no credential; if a
    parameter ever creeps in, callers start getting 422s.
    """

    auth = LocalDevAuthenticator(UOW, {"uid": "whoever"})
    params = inspect.signature(auth.__call__).parameters

    assert not params


def test_local_dev_authenticator_is_hashable(UOW):
    """FastAPI hashes dependency callables; @define would otherwise break it."""

    assert hash(LocalDevAuthenticator(UOW, {"uid": "whoever"}))


def test_local_dev_is_registered_with_the_factory(config):
    """Registration plus a matching config table.

    make_authenticator does config[auth_name], so a registered authenticator
    with no settings.toml section of the same name is a startup KeyError.

    NOTE: asserts on the registry rather than calling make_authenticator,
    because tests/e2e/conftest.py patches that method for the whole session.
    """

    assert AuthenticatorFactory().authenticators["local_dev"] is LocalDevAuthenticator
    assert "local_dev" in config["AUTH"]


@pytest.mark.asyncio
async def test_jwt_authenticator(
    UOW, a_persisted_user, oauth_jwt_config, jwt_config, a_jwks_response, a_jwt
):
    # Setup/Execute
    with mock.patch("token_service.dependencies.requests") as mock_requests:
        mock_requests.get.return_value = a_jwks_response
        jwt_auth = JWTAuthenticator(oauth_jwt_config, UOW)
        user = await jwt_auth(a_jwt)

    # Verify
    assert user
    assert user.uid == a_persisted_user.uid


@pytest.mark.asyncio
async def test_jwt_authenticator_caches_jwks_call(
    UOW, a_persisted_user, oauth_jwt_config, jwt_config, a_jwks_response, a_jwt
):
    # Setup/Execute
    with mock.patch("token_service.dependencies.requests") as mock_requests:
        mock_requests.get.return_value = a_jwks_response
        jwt_auth = JWTAuthenticator(oauth_jwt_config, UOW)
        await jwt_auth(a_jwt)
        assert mock_requests.get.call_count == 1

        await jwt_auth(a_jwt)
        # Call count should still be 1 because of the cache
        assert mock_requests.get.call_count == 1


@pytest.mark.asyncio
async def test_jwt_authenticator_jwks_cache_expires_after_duration(
    UOW, a_persisted_user, oauth_jwt_config, jwt_config, a_jwks_response, a_jwt
):
    # Setup/Execute
    with mock.patch("token_service.dependencies.requests") as mock_requests:
        ttl = 0.2
        mock_requests.get.return_value = a_jwks_response
        jwt_auth = JWTAuthenticator(oauth_jwt_config, UOW, jwks_cache_ttl=ttl)
        await jwt_auth(a_jwt)
        assert mock_requests.get.call_count == 1

        time.sleep(ttl)
        await jwt_auth(a_jwt)
        assert mock_requests.get.call_count == 2


def make_kerberos_authenticator(UOW, **config):
    from token_service.dependencies import KerberosAuthenticator

    defaults = {"enabled": True, "allowed_realms": ["EXAMPLE.GOV"]}
    return KerberosAuthenticator(UOW, {**defaults, **config})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "header",
    [
        pytest.param(None, id="absent"),
        pytest.param("Bearer sometoken", id="wrong_scheme"),
        pytest.param("Negotiate", id="no_payload"),
        pytest.param("Negotiate !!!not-base64!!!", id="undecodable"),
    ],
)
async def test_unusable_headers_challenge_without_touching_gssapi(UOW, header):
    """A malformed header is rejected before any credential is built.

    Asserting `creds` is never reached also proves a missing keytab cannot turn
    a bad request into a server error.
    """
    auth = make_kerberos_authenticator(UOW, allowed_realms=["EXAMPLE.GOV"])
    response = Response()

    with mock.patch.object(
        type(auth.acceptor), "creds", new_callable=mock.PropertyMock
    ) as creds:
        with pytest.raises(HTTPException) as exc:
            await auth(response, header)

        creds.assert_not_called()

    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc.value.headers["WWW-Authenticate"].startswith("Negotiate")


@pytest.mark.asyncio
async def test_gsserror_becomes_a_401_not_a_500(UOW):
    """A rejected token must not let GSSError escape as a 500."""

    auth = make_kerberos_authenticator(UOW, allowed_realms=["EXAMPLE.GOV"])
    response = Response()
    ctx = mock.MagicMock()

    with mock.patch.object(
        type(auth.acceptor), "creds", new_callable=mock.PropertyMock
    ):
        with fake_gssapi(ctx) as gssapi:
            ctx.step.side_effect = gssapi.exceptions.GSSError("rejected")
            with pytest.raises(HTTPException) as exc:
                await auth(response, "Negotiate Z2FyYmFnZQ==")

    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert exc.value.headers["WWW-Authenticate"].startswith("Negotiate")


@pytest.mark.asyncio
async def test_incomplete_context_returns_the_continuation_token(UOW):
    """Multi-leg negotiation gets a 401 carrying the next token, not a 403."""

    auth = make_kerberos_authenticator(UOW, allowed_realms=["EXAMPLE.GOV"])
    response = Response()
    ctx = mock.MagicMock()
    ctx.step.return_value = b"continue-me"
    ctx.complete = False

    with mock.patch.object(
        type(auth.acceptor), "creds", new_callable=mock.PropertyMock
    ):
        with fake_gssapi(ctx):
            with pytest.raises(HTTPException) as exc:
                await auth(response, "Negotiate Z2FyYmFnZQ==")

    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED
    expected = base64.b64encode(b"continue-me").decode()
    assert exc.value.headers["WWW-Authenticate"] == f"Negotiate {expected}"


@pytest.mark.asyncio
async def test_completed_handshake_returns_the_seeded_user(UOW, a_persisted_user):
    """The happy path maps the principal onto an existing User row."""

    auth = make_kerberos_authenticator(UOW, allowed_realms=["EXAMPLE.GOV"])
    response = Response()
    ctx = mock.MagicMock()
    ctx.step.return_value = b"server-token"
    ctx.complete = True
    ctx.initiator_name = f"{a_persisted_user.uid}@EXAMPLE.GOV"

    with mock.patch.object(
        type(auth.acceptor), "creds", new_callable=mock.PropertyMock
    ):
        with fake_gssapi(ctx):
            user = await auth(response, "Negotiate Z2FyYmFnZQ==")

    assert user.uid == a_persisted_user.uid
    expected = base64.b64encode(b"server-token").decode()
    assert response.headers["WWW-Authenticate"] == f"Negotiate {expected}"


@pytest.mark.asyncio
async def test_unseeded_principal_is_401_not_auto_provisioned(UOW):
    """An unknown uid is a 401, matching every other authenticator."""

    auth = make_kerberos_authenticator(UOW, allowed_realms=["EXAMPLE.GOV"])
    response = Response()
    ctx = mock.MagicMock()
    ctx.step.return_value = b""
    ctx.complete = True
    ctx.initiator_name = "nobody-here@EXAMPLE.GOV"

    with mock.patch.object(
        type(auth.acceptor), "creds", new_callable=mock.PropertyMock
    ):
        with fake_gssapi(ctx):
            with pytest.raises(HTTPException) as exc:
                await auth(response, "Negotiate Z2FyYmFnZQ==")

    assert exc.value.status_code == status.HTTP_401_UNAUTHORIZED


def test_kerberos_authenticator_is_hashable(UOW):
    """FastAPI caches dependencies by hash, like the other authenticators."""

    assert hash(make_kerberos_authenticator(UOW)) == hash(
        make_kerberos_authenticator(UOW)
    )


def test_kerberos_is_not_a_factory_entry():
    """The factory picks one authenticator; Kerberos is an additional path."""

    from token_service.dependencies import AuthenticatorFactory

    assert "kerberos" not in AuthenticatorFactory().authenticators
