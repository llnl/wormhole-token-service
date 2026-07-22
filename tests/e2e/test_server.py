import bcrypt
import pytest
import pendulum
import requests
import uuid
from unittest import mock
from requests import HTTPError
from joserfc import jwt
from joserfc.jwk import KeySet

from token_service.services import authenticated
from token_service.models import AdminRole

# Treat unawaited coroutine warnings as errors for this file
pytestmark = pytest.mark.filterwarnings(
    "error:coroutine.*was never awaited:RuntimeWarning"
)


@pytest.fixture
def a_user_uid():
    return "foo"


@pytest.fixture
def a_user_duid():
    return "1234567890"


@pytest.fixture
def a_token_name():
    return "my_token"


@pytest.fixture
def a_token_value():
    return "token"


@pytest.fixture
def an_encrypted_token_value(a_token_value):
    return bcrypt.hashpw(a_token_value.encode(), bcrypt.gensalt(12)).decode("utf-8")


@pytest.fixture
def a_group_name():
    return "group_name"


@pytest.fixture
def a_persisted_user(a_user_uid, a_user_duid, make_user, UOW):
    with UOW() as uow:
        user = make_user(uid=a_user_uid, duid=a_user_duid)
        uow.user_repo.add(user)

    return user


@pytest.fixture
def a_persisted_token(
    a_token_name, an_encrypted_token_value, a_persisted_user, make_token, UOW
):
    with UOW() as uow:
        token = make_token(
            name=a_token_name,
            value=an_encrypted_token_value,
            user_uid=a_persisted_user.uid,
        )
        uow.token_repo.add(token)

    return token


@pytest.fixture
def a_persisted_group(a_group_name, make_group, UOW):
    with UOW() as uow:
        group = make_group(name=a_group_name)
        uow.group_repo.add(group)

    return group


@pytest.fixture
def mock_oidc_call(a_persisted_user):
    with mock.patch("tests.helpers.fake_deps.oidc_call_target") as mock_call:
        mock_call.return_value = a_persisted_user
        yield mock_call


@pytest.fixture
def mock_jwt_auth_call(a_persisted_user):
    with mock.patch("tests.helpers.fake_deps.jwt_call_target") as mock_call:
        mock_call.return_value = a_persisted_user
        yield mock_call


@pytest.fixture
def a_persisted_admin_impersonation_token(UOW, make_admin_token):
    admin_token = make_admin_token(role=AdminRole.IMPERSONATION)
    with UOW() as uow:
        uow.admin_token_repo.add(admin_token)

    return admin_token


@pytest.fixture
def admin_impersonation_auth_headers(
    UOW, a_persisted_admin_impersonation_token, plain_admin_token
):
    return {"X-Token": plain_admin_token}


@pytest.fixture
def a_persisted_admin_identity_token(UOW, make_admin_token):
    admin_token = make_admin_token(role=AdminRole.IDENTITY)
    with UOW() as uow:
        uow.admin_token_repo.add(admin_token)

    return admin_token


@pytest.fixture
def admin_identity_auth_headers(
    UOW, a_persisted_admin_identity_token, plain_admin_token
):
    return {"X-Token": plain_admin_token}


@pytest.fixture
def a_persisted_admin_user(make_user, UOW):
    with UOW() as uow:
        user = make_user(uid="admin_user", is_admin=True)
        uow.user_repo.add(user)
    return user


@pytest.fixture
def mock_oidc_admin(a_persisted_admin_user):
    with mock.patch(
        "tests.helpers.fake_deps.oidc_call_target", new_callable=mock.AsyncMock
    ) as mock_call:
        mock_call.return_value = a_persisted_admin_user
        yield mock_call


@pytest.fixture
def token_headers(plain_token):
    return {"X-Token": plain_token}


def test_create_token(server_api, mock_oidc_call, UOW, make_scope):
    # Setup
    scope = make_scope()
    with UOW() as uow:
        uow.scope_repo.add(scope)
    token_data = {
        "name": "foo_token",
        "scopes": [scope.name],
    }

    # Execute
    resp = requests.post(f"{server_api}/latest/token/", data=token_data)

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 201
    with UOW() as uow:
        assert authenticated(uow, resp.json())


@pytest.mark.skip(reason="requires postgres specific feature")
def test_create_token_fails_with_same_name(server_api, mock_oidc_call, UOW, make_scope):
    # Setup
    scope = make_scope()
    with UOW() as uow:
        uow.scope_repo.add(scope)
    token_data = {
        "name": "foo_token",
        "scopes": [scope.name],
    }

    # Execute
    resp = requests.post(f"{server_api}/latest/token/", data=token_data)

    resp.raise_for_status()
    assert resp.status_code == 201

    # repeat
    resp = requests.post(f"{server_api}/latest/token/", data=token_data)

    assert resp.status_code == 409


def test_create_token_fails_with_invalid_scope(server_api, mock_oidc_call, UOW):
    # Setup
    token_data = {
        "name": "foo_token",
        "scopes": ["blah"],
    }

    # Execute
    resp = requests.post(f"{server_api}/latest/token/", data=token_data)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_list_tokens(server_api, a_persisted_token, mock_oidc_call, UOW):
    # Setup/Execute
    resp = requests.get(f"{server_api}/latest/token/")

    # Verify
    resp.raise_for_status()
    token = resp.json()[0]
    assert token["name"] == a_persisted_token.name
    assert token["exp"] == a_persisted_token.exp.timestamp()
    assert token["nbf"] == a_persisted_token.nbf.timestamp()
    assert token["iat"] == a_persisted_token.iat.timestamp()


def test_list_tokens_fails_with_invalid_user(
    server_api, a_user_uid, a_persisted_token, mock_oidc_call, UOW
):
    # Setup
    with UOW() as uow:
        uow.user_repo.remove(a_user_uid)

    # Execute
    resp = requests.get(f"{server_api}/latest/token/")

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_delete_token_by_value(server_api, a_persisted_token, mock_oidc_call, UOW):
    # Setup
    token_name = "foo_token"
    token_data = {"name": token_name, "iat": float(), "nbf": float(), "exp": float()}
    plain_token = requests.post(f"{server_api}/latest/token/", data=token_data).json()

    # Execute
    resp = requests.delete(f"{server_api}/latest/token/{plain_token}")
    resp.raise_for_status()
    assert resp.status_code == 204
    with UOW() as uow:
        assert not uow.token_repo.get(plain_token)


def test_delete_token_by_name(server_api, a_persisted_token, mock_oidc_call, UOW):
    # Setup
    token_name = "foo_token"
    token_data = {"name": token_name, "iat": float(), "nbf": float(), "exp": float()}
    plain_token = requests.post(f"{server_api}/latest/token/", data=token_data).json()

    # Execute
    resp = requests.delete(f"{server_api}/latest/token?name={token_name}")
    resp.raise_for_status()
    assert resp.status_code == 204
    with UOW() as uow:
        assert not uow.token_repo.get(plain_token)


def test_delete_token_fail_with_name_DNE(
    server_api, a_persisted_token, mock_oidc_call, UOW
):
    # Setup and Execute
    token_name = "foo_token"
    token_data = {"name": token_name, "iat": float(), "nbf": float(), "exp": float()}
    _ = requests.post(f"{server_api}/latest/token/", data=token_data).json()
    resp = requests.delete(f"{server_api}/latest/token?name=bar_token")

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_delete_token_fail_with_invalid_token_format(
    server_api, a_token_name, mock_oidc_call, UOW
):
    # Setup and Execute
    resp = requests.delete(f"{server_api}/latest/token/{a_token_name}")

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_delete_token_fail_with_missing_token(server_api, mock_oidc_call, UOW):
    # Setup and Execute
    resp = requests.delete(f"{server_api}/latest/token/1.foo")

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_delete_token_by_value_fails_with_invalid_user(
    server_api, mock_oidc_call, UOW, make_user, make_scope
):
    # Setup
    # Create another user with a token
    other_user = make_user(uid="other_user", duid="9876543210")
    scope = make_scope()
    with UOW() as uow:
        uow.user_repo.add(other_user)
        uow.scope_repo.add(scope)

    with mock.patch("tests.helpers.fake_deps.oidc_call_target") as mock_call:
        mock_call.return_value = other_user
        token_data = {"name": "other_user_token", "scopes": [scope.name]}
        resp = requests.post(f"{server_api}/latest/token/", data=token_data)
        resp.raise_for_status()
        other_user_token = resp.json()

    # Verify the token was created and belongs to other_user
    token_id = other_user_token.split(".")[0]
    with UOW() as uow:
        token = uow.token_repo.get(token_id)
        assert token.user_uid == other_user.uid

    # Execute
    resp = requests.delete(f"{server_api}/latest/token/{other_user_token}")

    # Verify
    # Should fail with 404 (not found for this user)
    with pytest.raises(HTTPError):
        resp.raise_for_status()
    assert resp.status_code == 404

    # Check token still exists
    with UOW() as uow:
        token = uow.token_repo.get(token_id)
        assert token is not None


def test_get_jwt_by_token(
    server_api, UOW, public_key, a_persisted_token, token_headers, a_persisted_user
):
    # Setup and Execute
    resp = requests.get(f"{server_api}/latest/token/jwt", headers=token_headers)

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 200
    data = resp.json()
    token = jwt.decode(data["jwt"], public_key)
    assert token.claims["sub"] == a_persisted_user.uid
    assert token.claims["duid"] == a_persisted_user.duid


def test_get_jwt_fails_when_invalid_token(server_api, UOW, a_persisted_token):
    # Setup
    headers = {"X-Token": "bad-token"}

    # Execute
    resp = requests.get(f"{server_api}/latest/token/jwt", headers=headers)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_jwks_setup(server, UOW, kid):
    # Setup and Execute
    resp = requests.get(f"{server}/.well-known/jwks.json")

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 200

    jwks = resp.json()
    assert "keys" in jwks

    key_ids = [key.get("kid") for key in jwks["keys"]]
    assert kid in key_ids


@pytest.mark.parametrize("jwt_url", ["/token/jwt", "/mfa/jwt"])
def test_valid_jwt_against_jwks(
    jwt_url,
    server,
    server_api,
    UOW,
    plain_token,
    kid,
    a_persisted_token,
    token_headers,
    mock_jwt_auth_call,
    claims_registry,
):
    # Setup
    resp = requests.get(f"{server_api}/latest{jwt_url}", headers=token_headers)
    new_jwt = resp.json()["jwt"]

    resp = requests.get(f"{server}/.well-known/jwks.json")
    jwks = KeySet.import_key_set(resp.json())

    # Execute and verify
    token = jwt.decode(new_jwt, jwks)

    # claims_request.validate will raise on validation failure
    claims_registry.validate(token.claims)


@pytest.mark.parametrize("session_state", ["missing", "active", "expired"])
def test_mfa_jwt_creates_token_session(
    session_state,
    config,
    server,
    server_api,
    UOW,
    plain_token,
    kid,
    a_persisted_user,
    token_headers,
    mock_jwt_auth_call,
    make_token,
    claims_registry,
):
    # Setup
    now = pendulum.now(tz="UTC").add(seconds=1)
    session_name = config["TOKEN"]["session_name"]

    if session_state == "missing":
        with UOW() as uow:
            session = uow.token_repo.get_session_token(
                a_persisted_user.uid, session_name
            )
            assert not session
    elif session_state == "active":
        with UOW() as uow:
            session = make_token(
                name=session_name,
                nbf=now.subtract(seconds=1),
                exp=now.add(seconds=60),
                session=True,
            )
            uow.token_repo.add(session)
    elif session_state == "expired":
        with UOW() as uow:
            session = make_token(
                name=session_name,
                nbf=now.subtract(seconds=30),
                exp=now.subtract(seconds=10),
                session=True,
            )
            uow.token_repo.add(session)

    resp = requests.get(f"{server_api}/latest/mfa/jwt", headers=token_headers)
    new_jwt = resp.json()["jwt"]

    resp = requests.get(f"{server}/.well-known/jwks.json")
    jwks = KeySet.import_key_set(resp.json())

    # Execute and verify
    token = jwt.decode(new_jwt, jwks)
    claims_registry.validate(token.claims)

    with UOW() as uow:
        session = uow.token_repo.get_session_token(a_persisted_user.uid, session_name)
        assert session
        # in all cases, we should get a refreshed session after a successful call
        assert session.nbf < now < session.exp
        assert token.claims["token_id"] == session.id


def test_invalid_token_fail_create_user(server_api, UOW, token_headers):
    # Setup
    sync_user_data = {"uid": "sync_user"}

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/users", headers=token_headers, json=sync_user_data
    )

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_create_user(server_api, UOW, a_user_duid, admin_identity_auth_headers):
    # Setup
    sync_user_data = {"uid": "sync_user", "duid": a_user_duid}

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/users",
        headers=admin_identity_auth_headers,
        json=sync_user_data,
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 201
    assert resp.json() == sync_user_data


def test_create_user_fails_unauthorized_admin_token(
    server_api, UOW, a_user_duid, admin_impersonation_auth_headers
):
    # Setup
    sync_user_data = {"uid": "sync_user", "duid": a_user_duid}

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/users",
        headers=admin_impersonation_auth_headers,
        json=sync_user_data,
    )
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_create_admin_token(server_api, mock_oidc_admin, UOW):
    # Setup
    admin_token_data = {"name": "admin-token-1", "role": "ANY"}

    # Execute
    resp = requests.post(f"{server_api}/latest/admin/token", json=admin_token_data)

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 201
    plain_admin_token = resp.json()
    admin_id, admin_plain = plain_admin_token.split(".")
    with UOW() as uow:
        stored = uow.admin_token_repo.get(admin_id)
    assert stored and stored.name == admin_token_data["name"]


def test_create_admin_token_fails_when_unprivledged_user(
    server_api, mock_oidc_call, UOW
):
    # Setup
    admin_token_data = {"name": "admin-token-1", "role": "ANY"}

    # Execute
    resp = requests.post(f"{server_api}/latest/admin/token", json=admin_token_data)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()

    with UOW() as uow:
        assert not uow.admin_token_repo.list()


def test_create_admin_token_fails_when_duplicate(
    server_api, mock_oidc_admin, a_persisted_admin_impersonation_token, UOW
):
    # Setup
    admin_token_data = {
        "name": a_persisted_admin_impersonation_token.name,
        "role": "ANY",
    }

    # Execute
    resp = requests.post(f"{server_api}/latest/admin/token", json=admin_token_data)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()
    assert resp.status_code == 409


def test_list_admin_tokens(
    server_api,
    mock_oidc_admin,
    UOW,
    admin_identity_auth_headers,
    a_persisted_admin_identity_token,
):
    # Execute
    resp = requests.get(f"{server_api}/latest/admin/token")

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 200
    tokens = resp.json()
    assert isinstance(tokens, list)
    assert any(t.get("name") == a_persisted_admin_identity_token.name for t in tokens)


def test_delete_admin_token_by_value(server_api, mock_oidc_admin, UOW):
    # Setup
    admin_token_data = {"name": "admin-token-1", "role": "ANY"}
    plain_admin_token = requests.post(
        f"{server_api}/latest/admin/token", json=admin_token_data
    ).json()

    # Execute
    resp = requests.delete(f"{server_api}/latest/admin/token/{plain_admin_token}")

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 204
    with UOW() as uow:
        assert not uow.admin_token_repo.get(plain_admin_token)


def test_create_token_for_user(
    server_api, UOW, admin_impersonation_auth_headers, make_scope, make_user, make_token
):
    # Setup
    scope = make_scope()
    user = make_user()
    with UOW() as uow:
        uow.scope_repo.add(scope)
        uow.user_repo.add(user)

    request_data = {
        "token": {
            "name": "foo_token",
            "scopes": [scope.name],
        },
    }

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/token/{user.uid}",
        headers=admin_impersonation_auth_headers,
        json=request_data,
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 201
    token_data = resp.json()
    with UOW() as uow:
        assert authenticated(uow, token_data["token"])


def test_create_subtoken_for_user(
    server_api,
    UOW,
    admin_impersonation_auth_headers,
    a_token_value,
    a_persisted_token,
    a_persisted_user,
    make_scope,
    make_token,
):
    # Setup
    external_id = str(uuid.uuid4())
    scope = make_scope()
    with UOW() as uow:
        uow.scope_repo.add(scope)

    request_data = {
        "token": {
            "name": "foo_subtoken",
        },
        "parent_id": a_persisted_token.id,
        "external_id": external_id,
    }

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/token/{a_persisted_user.uid}",
        headers=admin_impersonation_auth_headers,
        json=request_data,
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 201
    token_data = resp.json()
    plain_token = token_data["token"]
    with UOW() as uow:
        subtoken_id, plain_value = plain_token.split(".")
        subtoken = uow.token_repo.get(subtoken_id)

        assert subtoken.parent_id == a_persisted_token.id
        assert authenticated(uow, f"{a_persisted_token.id}.{a_token_value}")
        assert authenticated(uow, plain_token)
        assert plain_value == subtoken.value

    # Execute - second call idempotent
    resp = requests.post(
        f"{server_api}/latest/admin/token/{a_persisted_user.uid}",
        headers=admin_impersonation_auth_headers,
        json=request_data,
    )

    # Verify - second token same as the first
    resp.raise_for_status()
    assert resp.status_code == 201
    token_data = resp.json()
    retry_plain_token = token_data["token"]
    assert retry_plain_token == plain_token


def test_create_subtoken_for_user_allows_the_same_name_across_communities(
    server_api,
    UOW,
    admin_impersonation_auth_headers,
    a_token_value,
    a_persisted_token,
    a_persisted_user,
    make_scope,
    make_token,
):
    # Setup
    first_community_id = str(uuid.uuid4())
    second_community_id = str(uuid.uuid4())
    scope = make_scope()
    with UOW() as uow:
        uow.scope_repo.add(scope)

    request_data = {
        "token": {
            "name": "foo_subtoken",
        },
        "parent_id": a_persisted_token.id,
        "external_id": first_community_id,
    }

    # Execute
    first_resp = requests.post(
        f"{server_api}/latest/admin/token/{a_persisted_user.uid}",
        headers=admin_impersonation_auth_headers,
        json=request_data,
    )

    # Verify
    first_resp.raise_for_status()
    assert first_resp.status_code == 201
    token_data = first_resp.json()
    first_plain_token = token_data["token"]

    # Execute - second call idempotent
    request_data = {
        "token": {
            "name": "foo_subtoken",
        },
        "parent_id": a_persisted_token.id,
        "external_id": second_community_id,
    }

    second_resp = requests.post(
        f"{server_api}/latest/admin/token/{a_persisted_user.uid}",
        headers=admin_impersonation_auth_headers,
        json=request_data,
    )

    # Verify - second call also succeeds
    second_resp.raise_for_status()
    assert second_resp.status_code == 201
    token_data = second_resp.json()
    second_plain_token = token_data["token"]

    assert first_plain_token != second_plain_token


def test_create_token_for_user_fails_when_unauthorized_admin_token(
    server_api, make_user, make_scope, UOW, admin_identity_auth_headers
):
    # Setup
    scope = make_scope()
    user = make_user()
    with UOW() as uow:
        uow.scope_repo.add(scope)
        uow.user_repo.add(user)

    request_data = {
        "token": {
            "name": "foo_token",
            "scopes": [scope.name],
        },
    }

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/token/{user.uid}",
        headers=admin_identity_auth_headers,
        data=request_data,
    )

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()
    assert resp.status_code == 403


def test_delete_user(server_api, UOW, a_persisted_user, admin_identity_auth_headers):
    # Setup and Execute
    resp = requests.delete(
        f"{server_api}/latest/admin/users/{a_persisted_user.uid}",
        headers=admin_identity_auth_headers,
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 204
    with UOW() as uow:
        assert not uow.user_repo.get(a_persisted_user.uid)


def test_list_users(server_api, UOW, a_persisted_user, admin_identity_auth_headers):
    # Setup and Execute
    resp = requests.get(
        f"{server_api}/latest/admin/users", headers=admin_identity_auth_headers
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["uid"] == a_persisted_user.uid


def test_create_group(server_api, UOW, admin_identity_auth_headers):
    # Setup
    group_name = "group1"
    group_data = {"name": group_name}

    # Execute
    resp = requests.post(
        f"{server_api}/latest/admin/groups",
        headers=admin_identity_auth_headers,
        json=group_data,
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 201
    with UOW() as uow:
        assert uow.group_repo.get(group_name)


def test_delete_group(server_api, UOW, admin_identity_auth_headers, a_persisted_group):
    # Setup and Execute
    resp = requests.delete(
        f"{server_api}/latest/admin/groups/{a_persisted_group.name}",
        headers=admin_identity_auth_headers,
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 204
    with UOW() as uow:
        assert not uow.group_repo.get(a_persisted_group.name)


def test_list_groups(
    server_api, UOW, admin_identity_auth_headers, a_persisted_group, a_persisted_user
):
    # Setup
    with UOW() as uow:
        user = uow.user_repo.get(a_persisted_user.uid)
        group = uow.group_repo.get(a_persisted_group.name)
        group.users.append(user)

    # Execute
    resp = requests.get(
        f"{server_api}/latest/admin/groups", headers=admin_identity_auth_headers
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    assert resp.json()[0]["name"] == a_persisted_group.name
    assert resp.json()[0]["members"][0] == a_persisted_user.uid


def test_add_user_to_group(
    server_api, UOW, a_persisted_user, a_persisted_group, admin_identity_auth_headers
):
    # Setup and Execute
    resp = requests.post(
        f"{server_api}/latest/admin/groups/{a_persisted_group.name}/members/{a_persisted_user.uid}",
        headers=admin_identity_auth_headers,
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 201
    with UOW() as uow:
        assert uow.group_repo.get(a_persisted_group.name).users
        assert (
            uow.group_repo.get(a_persisted_group.name).users[0].uid
            == a_persisted_user.uid
        )


def test_remove_user_from_group(
    server_api, UOW, a_persisted_user, a_persisted_group, admin_identity_auth_headers
):
    # Setup
    with UOW() as uow:
        group = uow.group_repo.get(a_persisted_group.name)
        group.users.append(a_persisted_user)

    # Execute
    resp = requests.delete(
        f"{server_api}/latest/admin/groups/{a_persisted_group.name}/members/{a_persisted_user.uid}",
        headers=admin_identity_auth_headers,
    )

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 204
    with UOW() as uow:
        assert not uow.group_repo.get(a_persisted_group.name).users


def test_grant_admin_role(server_api, UOW, mock_oidc_admin, a_persisted_user):
    # Execute and Verify
    assert not a_persisted_user.is_admin
    resp = requests.put(f"{server_api}/latest/admin/users/{a_persisted_user.uid}/admin")

    assert resp.status_code == 204
    with UOW() as uow:
        assert uow.user_repo.get(a_persisted_user.uid).is_admin


def test_revoke_admin_role(server_api, UOW, mock_oidc_admin, a_persisted_user):
    # Setup
    with UOW() as uow:
        user = uow.user_repo.get(a_persisted_user.uid)
        user.is_admin = True
        assert user.is_admin

    # Execute
    resp = requests.delete(
        f"{server_api}/latest/admin/users/{a_persisted_user.uid}/admin"
    )

    # Assert
    assert resp.status_code == 204
    with UOW() as uow:
        assert not uow.user_repo.get(a_persisted_user.uid).is_admin


def test_attestation(server_api, UOW, a_persisted_user, make_token, mock_oidc_call):
    # Setup
    token_id = str(uuid.uuid4())
    with UOW() as uow:
        token = make_token(id=token_id, user_uid=a_persisted_user.uid)
        uow.token_repo.add(token)
        assert not token.rotatable

    request_data = {"ids": [token_id]}

    # Execute
    resp = requests.patch(f"{server_api}/latest/token/attestation", json=request_data)

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 204
    with UOW() as uow:
        token = uow.token_repo.get(token_id)
        assert token.rotatable


def test_attestation_fails_when_token_not_owned_by_user(
    server_api, UOW, make_user, make_token, mock_oidc_call
):
    # Setup
    other_user = make_user(uid="other_user")
    token_id = str(uuid.uuid4())
    with UOW() as uow:
        uow.user_repo.add(other_user)
        other_token = make_token(
            id=token_id, name="other_token", user_uid=other_user.uid
        )
        uow.token_repo.add(other_token)

    request_data = {"ids": [token_id]}

    # Execute
    resp = requests.patch(f"{server_api}/latest/token/attestation", json=request_data)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()
    assert resp.status_code == 404


def test_attestation_fails_when_token_invalid(
    server_api, UOW, a_persisted_user, make_token, mock_oidc_call
):
    # Setup
    token_id = str(uuid.uuid4())
    with UOW() as uow:
        token = make_token(id=token_id, user_uid=a_persisted_user.uid)
        uow.token_repo.add(token)
        token.valid = False

    request_data = {"ids": [token_id]}

    # Execute
    resp = requests.patch(f"{server_api}/latest/token/attestation", json=request_data)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()
    assert resp.status_code == 422


def test_attestation_fails_when_token_does_not_exist(server_api, UOW, mock_oidc_call):
    # Setup
    nonexistent_id = str(uuid.uuid4())
    request_data = {"ids": [nonexistent_id]}

    # Execute
    resp = requests.patch(f"{server_api}/latest/token/attestation", json=request_data)

    # Verify - should fail (actual error code may vary based on service implementation)
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_rotate_token(server_api, UOW, a_persisted_token, a_token_value):
    # Setup
    with UOW() as uow:
        token = uow.token_repo.get(a_persisted_token.id)
        token.rotatable = True
        original_exp = token.exp

    old_token_value = f"{a_persisted_token.id}.{a_token_value}"
    headers = {"X-Token": old_token_value}

    # Execute
    resp = requests.put(f"{server_api}/latest/token/rotate", headers=headers)

    # Verify
    resp.raise_for_status()
    assert resp.status_code == 200
    new_token_value = resp.json()

    # Verify new token is different from old
    assert new_token_value != old_token_value

    # Verify token is no longer rotatable
    with UOW() as uow:
        token = uow.token_repo.get(a_persisted_token.id)
        assert not token.rotatable
        # Verify expiration was extended
        assert token.exp > original_exp

    # Verify new token works for JWT endpoint
    new_headers = {"X-Token": new_token_value}
    jwt_resp = requests.get(f"{server_api}/latest/token/jwt", headers=new_headers)
    jwt_resp.raise_for_status()
    assert jwt_resp.status_code == 200


def test_rotate_token_cannot_be_rotated_twice(
    server_api, UOW, a_persisted_token, a_token_value
):
    # Setup
    with UOW() as uow:
        token = uow.token_repo.get(a_persisted_token.id)
        token.rotatable = True

    old_token_value = f"{a_persisted_token.id}.{a_token_value}"
    headers = {"X-Token": old_token_value}

    # Execute - first rotation
    resp = requests.put(f"{server_api}/latest/token/rotate", headers=headers)
    resp.raise_for_status()
    new_token_value = resp.json()

    # Verify - rotatable flag is now False
    with UOW() as uow:
        token = uow.token_repo.get(a_persisted_token.id)
        assert not token.rotatable

    # Try to rotate again with new token
    new_headers = {"X-Token": new_token_value}
    second_rotate_resp = requests.put(
        f"{server_api}/latest/token/rotate", headers=new_headers
    )
    with pytest.raises(HTTPError):
        second_rotate_resp.raise_for_status()
    assert second_rotate_resp.status_code == 422


def test_rotate_token_fails_when_not_rotatable(
    server_api, UOW, a_persisted_token, a_token_value
):
    # Setup
    with UOW() as uow:
        token = uow.token_repo.get(a_persisted_token.id)
        assert not token.rotatable

    token_value = f"{a_persisted_token.id}.{a_token_value}"
    headers = {"X-Token": token_value}

    # Execute
    resp = requests.put(f"{server_api}/latest/token/rotate", headers=headers)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()
    assert resp.status_code == 422


def test_rotate_token_fails_with_invalid_token(server_api, UOW):
    # Setup
    headers = {"X-Token": "invalid-token"}

    # Execute
    resp = requests.put(f"{server_api}/latest/token/rotate", headers=headers)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()


def test_rotate_token_fails_when_expired(
    server_api, UOW, a_persisted_token, a_token_value
):
    # Setup
    now = pendulum.now()
    with UOW() as uow:
        token = uow.token_repo.get(a_persisted_token.id)
        token.rotatable = True
        token.exp = now.subtract(days=1)

    token_value = f"{a_persisted_token.id}.{a_token_value}"
    headers = {"X-Token": token_value}

    # Execute
    resp = requests.put(f"{server_api}/latest/token/rotate", headers=headers)

    # Verify
    with pytest.raises(HTTPError):
        resp.raise_for_status()
    assert resp.status_code == 401
