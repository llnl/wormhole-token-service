from .models import Token, User, Group, Scope, AdminToken
from .pydantic_models import (
    Token as PydanticToken,
    User as PydanticUser,
    Group as PydanticGroup,
    Scope as PydanticScope,
    AdminToken as PydanticAdminToken,
)


def drop_empty(data: dict) -> dict:
    return {k: v for k, v in data.items() if v}


def to_token(p_token: PydanticToken) -> Token:
    data = {
        "name": p_token.name,
        "nbf": p_token.nbf,
        "exp": p_token.exp,
        "paths": p_token.paths,
        "rotatable": p_token.rotatable,
    }
    data = drop_empty(data)

    return Token(**data)


def from_token(token: Token) -> PydanticToken:
    return PydanticToken(
        name=token.name,
        id=token.id,
        iat=token.iat.timestamp(),
        nbf=token.nbf.timestamp(),
        exp=token.exp.timestamp(),
        paths=token.paths,
        scopes=token.scopes,
        rotatable=token.rotatable,
    )


def to_user(p_user: PydanticUser) -> User:
    data = {"uid": p_user.uid, "duid": p_user.duid}

    return User(**data)


def from_user(user: User) -> PydanticUser:
    return PydanticUser(uid=user.uid, duid=user.duid)


def to_group(p_group: PydanticGroup) -> Group:
    data = {"name": p_group.name}

    return Group(**data)


def from_group(group: Group) -> PydanticGroup:
    members = [user.uid for user in group.users]
    return PydanticGroup(name=group.name, members=members)


def to_scope(p_scope: PydanticScope) -> Scope:
    data = {
        "name": p_scope.name,
        "description": p_scope.description,
    }

    data = drop_empty(data)

    return Scope(**data)


def from_scope(scope: Scope) -> PydanticScope:
    return PydanticScope(name=scope.name, description=scope.description)


def to_admin_token(p_admin_token: PydanticAdminToken) -> AdminToken:
    data = {"name": p_admin_token.name, "role": p_admin_token.role}
    return AdminToken(**data)


def from_admin_token(admin_token: AdminToken) -> PydanticAdminToken:
    return PydanticAdminToken(name=admin_token.name, role=admin_token.role)
