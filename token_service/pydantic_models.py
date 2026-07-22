from pydantic import BaseModel
from uuid import UUID
from .models import AdminRole


class Token(BaseModel):
    name: str
    id: str | None = None
    iat: float | None = None
    nbf: float | None = None
    exp: float | None = None
    paths: list[str] | None = list()
    scopes: list[str] | None = list()
    rotatable: bool | None = False


class CreateTokenRequest(BaseModel):
    token: Token
    parent_id: str | None = ""
    external_id: str | None = ""


class CreateTokenResponse(BaseModel):
    token: str


class User(BaseModel):
    uid: str
    duid: str | None


class Group(BaseModel):
    name: str
    members: list | None = list()


class Scope(BaseModel):
    name: str
    description: str | None


class JWKSet(BaseModel):
    keys: list[dict] | None = list()


class AdminToken(BaseModel):
    name: str
    role: AdminRole


class JWTResponse(BaseModel):
    jwt: str


class TokenRotationRequest(BaseModel):
    ids: list[UUID]
