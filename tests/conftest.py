import pytest
from token_service import models
import pendulum
import bcrypt
from joserfc import jwk
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


@pytest.fixture
def plain_token():
    return "1.token"


@pytest.fixture
def admin_token_name():
    return "test"


@pytest.fixture
def admin_token_id():
    return "1"


@pytest.fixture
def plain_admin_token(admin_token_id):
    return f"{admin_token_id}.admintoken"


@pytest.fixture
def admin_token_remote_id():
    return "123"


@pytest.fixture
def a_user_uid():
    return "foo_user"


@pytest.fixture
def make_user(a_user_uid):
    def _fn(**kwargs) -> models.User:
        defaults = {
            "uid": a_user_uid,
            "duid": "1234567890",
            "is_admin": False,
        }
        return models.User(**(defaults | kwargs))

    return _fn


@pytest.fixture
def make_group():
    def _fn(**kwargs) -> models.Group:
        defaults = {
            "name": "foo_group",
        }
        return models.Group(**(defaults | kwargs))

    return _fn


@pytest.fixture
def make_token(a_user_uid):
    def _fn(**kwargs) -> models.Token:
        defaults = {
            "id": "1",
            "name": "foo",
            "user_uid": a_user_uid,
            "value": bcrypt.hashpw("token".encode(), bcrypt.gensalt(12)).decode(
                "utf-8"
            ),
            "iat": pendulum.now(),
            "nbf": pendulum.now(),
            "exp": pendulum.now().add(days=30),
            "paths": ["/foo"],
            "valid": True,
            "session": False,
            "last_used": None,
            "rotatable": False,
        }
        return models.Token(**(defaults | kwargs))

    return _fn


@pytest.fixture
def make_scope():
    def _fn(**kwargs) -> models.Scope:
        defaults = {
            "name": "read",
            "description": "able to read",
        }
        return models.Scope(**(defaults | kwargs))

    return _fn


@pytest.fixture
def make_audit():
    def _fn(**kwargs) -> models.AuditRecord:
        defaults = {
            "id": 1,
            "event": models.AuditEvent.CREATION,
            "auth_failure_reason": None,
            "request_method": "POST",
            "token_id": "1",
            "timestamp": pendulum.now(),
            "source": "127.0.0.1",
            "destination": "/foo",
            "success": True,
        }
        return models.AuditRecord(**(defaults | kwargs))

    return _fn


@pytest.fixture
def make_httprequest():
    def _fn(**kwargs) -> models.HTTPRequest:
        defaults = {
            "method": "POST",
            "url": "example.com/foo",
            "headers": {},
            "client_host": "127.0.0.1",
        }
        return models.HTTPRequest(**(defaults | kwargs))

    return _fn


@pytest.fixture
def make_admin_token(
    plain_admin_token, admin_token_name, admin_token_id, admin_token_remote_id
):
    def _fn(**kwargs) -> models.AdminToken:
        _, secret = plain_admin_token.split(".")
        hashed_secret = bcrypt.hashpw(secret.encode(), bcrypt.gensalt(12)).decode(
            "utf-8"
        )
        defaults = {
            "id": admin_token_id,
            "name": admin_token_name,
            "value": hashed_secret,
            "remote_id": admin_token_remote_id,
            "role": models.AdminRole.ANY,
        }
        return models.AdminToken(**(defaults | kwargs))

    return _fn


@pytest.fixture(scope="session")
def kid():
    return "my-key-id"


@pytest.fixture(scope="session")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def private_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture(scope="session")
def public_pem(private_key):
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


@pytest.fixture(scope="session")
def public_key(public_pem):
    return jwk.RSAKey.import_key(public_pem)
