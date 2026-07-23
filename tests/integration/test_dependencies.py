import pytest
import json
import time
import inspect
import requests
from unittest import mock
from token_service.dependencies import require_admin, JWTAuthenticator

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
