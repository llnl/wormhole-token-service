from typing import List
from attrs import define, field
from joserfc import jwk
import pendulum
from token_service.utils import make_token
from enum import StrEnum
import uuid


@define(slots=False)
class Scope:
    name: str = field(default=None)
    description: str = field(default=None)


def to_pendulum_dt(val) -> pendulum.DateTime:
    if isinstance(val, int) or isinstance(val, float):
        return pendulum.from_timestamp(val)
    elif isinstance(val, pendulum.DateTime):
        return val
    else:
        raise ValueError(f"Unable to convert {val} to a pendulum.DateTime")


@define(slots=False)
class Token:
    name: str
    id: str = field(factory=uuid.uuid4, converter=str)
    user_uid: str = field(default=None)
    parent_id: str = field(default=None)
    external_id: str = field(default=None)
    value: str = field(factory=make_token)
    iat: pendulum.DateTime = field(factory=pendulum.now, converter=to_pendulum_dt)
    nbf: pendulum.DateTime = field(factory=pendulum.now, converter=to_pendulum_dt)
    exp: pendulum.DateTime = field(
        factory=lambda: pendulum.now().add(days=30), converter=to_pendulum_dt
    )
    scopes: List[str] = field(factory=list)
    paths: List[str] = field(default=None)
    valid: bool = field(default=True)
    session: bool = field(default=False)
    last_used: pendulum.DateTime = field(default=None)
    rotatable: bool = field(default=False)


@define(slots=False)
class Group:
    name: str = field(default=None)


@define(slots=False)
class User:
    uid: str = field(default=None)
    duid: str = field(default=None)
    is_admin: bool = field(default=False)


class AuditEvent(StrEnum):
    AUTH = "AUTH"
    CREATION = "CREATION"
    DELETION = "DELETION"
    EXPIRATION = "EXPIRATION"


class AuthFailureReason(StrEnum):
    NOT_YET_VALID = "NOT_YET_VALID"
    EXPIRED = "EXPIRED"
    INVALID = "INVALID"
    NONEXISTENT = "NONEXISTENT"  # sent token does not match anything in our db
    ACCOUNT_INVALID = "ACCOUNT_INVALID"


@define(slots=False)
class AuditRecord:
    id: int = field(default=None)
    event: AuditEvent = field(default=None)
    auth_failure_reason: AuthFailureReason = field(default=None)
    request_method: str = field(default=None)
    token_id: str = field(default=None)
    timestamp: pendulum.DateTime = field(factory=pendulum.now)
    source: str = field(default=None)
    destination: str = field(default=None)
    success: bool = field(default=None)


@define(slots=False)
class HTTPRequest:
    method: str = field(default=None)
    url: str = field(default=None)
    headers: dict = field(default=None)
    client_host: str = field(default=None)


@define
class JWK:
    kid: str
    config: dict
    key_type: str = field()
    kid: str = field()
    public_key: jwk.Key = field()
    private_key: jwk.Key = field()

    def __hash__(self):
        return hash(self.__class__.__name__)

    @key_type.default
    def _key_type(self):
        return self.config["key_type"]

    @public_key.default
    def _public_key(self):
        public_pem = self.config.get("public_pem")
        if public_pem:
            return jwk.import_key(public_pem, self.key_type, {"kid": self.kid})

    @private_key.default
    def _private_key(self):
        private_pem = self.config.get("private_pem")
        if private_pem:
            return jwk.import_key(private_pem, self.key_type)


@define
class JWKS:
    config: dict
    key_map: dict[str, JWK] = field()
    keys: dict = field()

    @key_map.default
    def _key_map(self):
        keys = self.config.get("keys", {})
        return {k: JWK(k, v) for k, v in keys.items()}

    @keys.default
    def _keys(self):
        return {
            "keys": [
                k.public_key.as_dict() for k in self.key_map.values() if k.public_key
            ]
        }


@define
class JWTConfig:
    config: dict
    jwks: JWKS = field()
    alg: str = field()
    active_kid: str = field()
    lifespan: int = field()
    signing_secret: jwk.Key = field()

    @jwks.default
    def _jwks(self):
        return JWKS(config=self.config)

    @active_kid.default
    def _active_kid(self):
        return str(self.config["active_kid"])

    @alg.default
    def _alg(self):
        return self.config["alg"]

    @lifespan.default
    def _lifespan(self):
        return self.config["lifespan"]

    @signing_secret.default
    def _signing_secret(self):
        return self.jwks.key_map[self.active_kid].private_key


class AdminRole(StrEnum):
    ANY = "ANY"
    IMPERSONATION = "IMPERSONATION"
    IDENTITY = "IDENTITY"
    NONE = "NONE"


@define(slots=False)
class AdminToken:
    name: str
    role: AdminRole
    id: str = field(factory=uuid.uuid4, converter=str)
    value: str = field(factory=make_token)
    remote_id: str = field(default=None)
