"""Service Layer for Token Service."""

from . import models
from token_service.service.uow import BaseUOW
from token_service.service.uow import (
    AlreadyExists as UOWAlreadyExists,
    NotFound as UOWNotFound,
)
from token_service.service.uow import UOWException
from .utils import make_token
from attrs import define
import pendulum
from joserfc import jwt
from typing import List, Optional, Tuple
import bcrypt


@define
class ServiceException(Exception):
    """Base Service Exception."""

    msg: str


@define
class NotFound(ServiceException):
    """Not found."""

    pass


@define
class AlreadyExists(ServiceException):
    """Creation Error."""

    pass


@define
class InvalidToken(ServiceException):
    """Invalid Token."""

    pass


def matches(token_val: str, token: models.Token) -> bool:
    if token.parent_id:
        return token_val == token.value
    else:
        return bcrypt.checkpw(token_val.encode(), token.value.encode("utf-8"))


def valid(UOW: BaseUOW, token: models.Token, now: pendulum.DateTime) -> bool:
    with UOW() as uow:
        if not token or not token.valid:
            return False

        parent_token = uow.token_repo.get(token.parent_id) if token.parent_id else None
        if parent_token:
            nbf = parent_token.nbf
            exp = parent_token.exp
        else:
            nbf = token.nbf
            exp = token.exp

        return nbf < now < exp


def authenticated(UOW: BaseUOW, x_token: str) -> bool:
    """Check if the provided token string is authenticated."""
    with UOW() as uow:
        token_id, token_val = x_token.split(".")
        token = uow.token_repo.get(token_id)

        return valid(uow, token, pendulum.now()) and matches(token_val, token)


# TODO decide if we should use invalidate_token. We do not currently use it.
def invalidate_token(UOW: BaseUOW, token_value: str) -> models.Token:
    with UOW() as uow:
        token_id, _ = token_value.split(".")
        token = uow.token_repo.get(token_id)

        if not token:
            raise NotFound(f"Token {token_value} does not exist")

        token.valid = False

    return token


def update_token_last_used(UOW: BaseUOW, token_value: str) -> models.Token:
    now = pendulum.now()
    with UOW() as uow:
        token_id, _ = token_value.split(".")
        token = uow.token_repo.get(token_id)
        token.last_used = now

    return token


def make_composite_token(_id: str, value: str) -> str:
    return f"{_id}.{value}"


def create_token(
    UOW: BaseUOW,
    token: models.Token,
    scope_names: List[str],
    parent_id: Optional[str] = None,
    external_id: Optional[str] = None,
) -> str:
    try:
        with UOW() as uow:
            parent_token = None
            if parent_id:
                parent_token = uow.token_repo.get(parent_id)
                if not parent_token:
                    raise NotFound(f"Unable to find parent with id {parent_id}")
            token.scopes = [
                uow.scope_repo.get(s) for s in scope_names
            ]  # scope `get` should raise on not finding a scope

            plain_token = token.value

            if parent_token:
                token.parent_id = parent_token.id
            else:
                token.value = bcrypt.hashpw(
                    token.value.encode(), bcrypt.gensalt(12)
                ).decode("utf-8")
            token.external_id = external_id
            uow.token_repo.add(token)
    except UOWNotFound:
        raise NotFound("Scope not found")
    except UOWAlreadyExists:
        raise AlreadyExists(f"Token name: {token.name} already exists")
    except UOWException as e:
        raise ServiceException(e)

    return make_composite_token(token.id, plain_token)


def update_session(
    UOW: BaseUOW, user: models.User, token: models.Token
) -> models.Token:
    now = pendulum.now()
    try:
        with UOW() as uow:
            session = uow.token_repo.get_session_token(user.uid, token.name)
            if session:
                if session.nbf < now < session.exp:
                    return session
                uow.token_repo.remove(session.id)
                uow.session.flush()

            uow.token_repo.add(token)

            return token

    except UOWException as e:
        raise ServiceException(e)


def list_user_tokens(UOW: BaseUOW, user_uid: str) -> List[models.Token]:
    with UOW() as uow:
        user = uow.user_repo.get(user_uid)
        if not user:
            raise NotFound(f"User: {user_uid} does not exist")

        return user.tokens


def list_all_tokens(UOW: BaseUOW) -> List[models.Token]:
    with UOW() as uow:
        return uow.token_repo.list()


def get_token(UOW: BaseUOW, token_value: str) -> models.Token:
    with UOW() as uow:
        token_id, _ = token_value.split(".")
        token = uow.token_repo.get(token_id)
        if not token:
            raise NotFound(f"Token: {token_value} not found")

    return token


def get_subtoken(
    UOW: BaseUOW, name: str, parent_id: str, external_id: str
) -> Optional[models.Token]:
    with UOW() as uow:
        return uow.token_repo.get_subtoken(name, parent_id, external_id)


def remove_token_by_value(UOW: BaseUOW, token_value: str, user_uid: str):
    try:
        with UOW() as uow:
            token_id, _ = token_value.split(".")
            user = uow.user_repo.get(user_uid)
            token = next(t for t in user.tokens if t.id == token_id)
            uow.token_repo.remove(token.id)
    except StopIteration:
        raise NotFound(f"{user_uid}'s token {token_value} not found")
    except ValueError:
        raise ValueError("Invalid Token Format")


def remove_token_by_name(UOW: BaseUOW, token_name: str, user_uid: str):
    try:
        with UOW() as uow:
            user = uow.user_repo.get(user_uid)
            token = next(t for t in user.tokens if t.name == token_name)
            uow.token_repo.remove(token.id)
    except StopIteration:
        raise NotFound(f"{user_uid}'s token {token_name} not found")


def create_jwt_from_token(
    UOW: BaseUOW,
    token_id: str,
    jwt_config: models.JWTConfig,
) -> str:
    with UOW() as uow:
        retrieved_token = uow.token_repo.get(token_id)
        header = {"alg": jwt_config.alg, "kid": jwt_config.active_kid}
        scope_names = [scope.name for scope in retrieved_token.scopes]
        groups = [group.name for group in retrieved_token.user.groups]
        now = pendulum.now()
        payload = {
            "groups": groups,
            "scopes": scope_names,
            "iat": now.timestamp(),
            "exp": now.add(seconds=jwt_config.lifespan).timestamp(),
            "nbf": now.timestamp(),
            "parent_id": retrieved_token.parent_id,
            "external_id": retrieved_token.external_id,
            "duid": retrieved_token.user.duid,
            "sub": retrieved_token.user_uid,
            "token_id": token_id,
        }

        return jwt.encode(header, payload, jwt_config.signing_secret)


def create_jwt_from_user(
    UOW: BaseUOW,
    user: models.User,
    token_id: str,
    jwt_config: models.JWTConfig,
) -> str:
    now = pendulum.now()
    with UOW() as uow:
        retrieved_user = uow.user_repo.get(user.uid)
        header = {"alg": jwt_config.alg, "kid": jwt_config.active_kid}
        groups = [group.name for group in retrieved_user.groups]

    payload = {
        "groups": groups,
        "scopes": [],
        "iat": now.timestamp(),
        "exp": now.add(seconds=jwt_config.lifespan).timestamp(),
        "nbf": now.timestamp(),
        "parent_id": "",
        "external_id": "",
        "duid": user.duid,
        "sub": user.uid,
        "token_id": token_id,
    }

    return jwt.encode(header, payload, jwt_config.signing_secret)


def make_rotatable(UOW: BaseUOW, user_uid: str, token_ids: list):
    now = pendulum.now()
    try:
        with UOW() as uow:
            # Fetch all tokens first
            tokens = [uow.token_repo.get(token_id) for token_id in token_ids]

            # Validate all tokens before making any changes
            if any(t is None for t in tokens):
                raise NotFound("Token not found in attestation set")

            if any(t.user_uid != user_uid for t in tokens):
                # Note: We're intentionally vague here for security reasons
                raise NotFound("Token not found")

            if any(not valid(uow, t, now) for t in tokens):
                raise InvalidToken(
                    "Attestation set contains an invalid or expired token"
                )

            # All validations passed, now update
            for t in tokens:
                t.rotatable = True

    except UOWException as e:
        raise ServiceException(str(e))


def rotate_token(
    UOW: BaseUOW,
    token_id: str,
    max_lifetime_days: int,
    exp_days: int | None = None,
) -> str:
    try:
        exp_days = exp_days or max_lifetime_days

        if exp_days > max_lifetime_days:
            raise ValueError(
                f"Requested lifetime ({exp_days} days) exceeds maximum allowed ({max_lifetime_days} days)"
            )

        with UOW() as uow:
            token = uow.token_repo.get(token_id)

            if not token.rotatable:
                raise InvalidToken("Token not rotatable")

            plain_token = make_token()

            token.value = bcrypt.hashpw(
                plain_token.encode(), bcrypt.gensalt(12)
            ).decode("utf-8")

            token.exp = pendulum.now().add(days=exp_days)
            token.rotatable = False

            return f"{token.id}.{plain_token}"
    except UOWException as e:
        raise ServiceException(str(e))


def create_user(UOW: BaseUOW, user: models.User) -> models.User:
    try:
        with UOW() as uow:
            uow.user_repo.add(user)
    except UOWAlreadyExists:
        raise AlreadyExists(f"User {user.uid} already exists")
    except UOWException as e:
        raise ServiceException(e)

    return user


def get_user(UOW: BaseUOW, user_uid: str) -> models.User:
    with UOW() as uow:
        user = uow.user_repo.get(user_uid)
        if not user:
            raise NotFound(f"User {user_uid} does not exist")
        return user


def add_admin(UOW: BaseUOW, user_uid: str):
    with UOW() as uow:
        user = uow.user_repo.get(user_uid)
        if not user:
            raise NotFound(f"User {user_uid} does not exist")
        user.is_admin = True


def remove_admin(UOW: BaseUOW, user_uid: str):
    with UOW() as uow:
        user = uow.user_repo.get(user_uid)
        if not user:
            raise NotFound(f"User {user_uid} does not exist")
        user.is_admin = False


def list_all_users(UOW: BaseUOW) -> List[models.User]:
    with UOW() as uow:
        return uow.user_repo.list()


def list_all_admins(UOW: BaseUOW) -> List[models.User]:
    with UOW() as uow:
        return [u for u in uow.user_repo.list() if u.is_admin]


def remove_user(UOW: BaseUOW, user_uid: str):
    try:
        with UOW() as uow:
            uow.user_repo.remove(user_uid)
    except UOWNotFound:
        raise NotFound(f"User {user_uid} does not exist")


def create_group(UOW: BaseUOW, group: models.Group) -> models.Group:
    try:
        with UOW() as uow:
            uow.group_repo.add(group)
    except UOWAlreadyExists:
        raise AlreadyExists(f"Group {group.name} already exists")
    except UOWException as e:
        raise ServiceException(e)

    return group


def get_group(UOW: BaseUOW, group_name: str) -> models.Group:
    with UOW() as uow:
        group = uow.group_repo.get(group_name)
        if not group:
            raise NotFound(f"Group {group_name} does not exist")


def list_all_groups(UOW: BaseUOW) -> List[dict]:
    with UOW() as uow:
        return uow.group_repo.list()


def remove_group(UOW: BaseUOW, group_name: str):
    try:
        with UOW() as uow:
            uow.group_repo.remove(group_name)
    except UOWNotFound:
        raise NotFound(f"Group {group_name} does not exist")


def add_user_to_group(UOW: BaseUOW, group_name: str, user_uid: str) -> [models.Group]:
    with UOW() as uow:
        group = uow.group_repo.get(group_name)
        user = uow.user_repo.get(user_uid)
        if not group:
            raise NotFound(f"{group_name} does not exist")
        if not user:
            raise NotFound(f"{user_uid} does not exist")

        group.users.append(user)

    return group


def remove_user_from_group(
    UOW: BaseUOW, group_name: str, user_uid: str
) -> [models.Group]:
    with UOW() as uow:
        group = uow.group_repo.get(group_name)
        user = uow.user_repo.get(user_uid)
        if not group:
            raise NotFound(f"{group_name} does not exist")
        if not user:
            raise NotFound(f"{user_uid} does not exist")

        group.users.remove(user)

    return group


def create_scope(UOW: BaseUOW, scope: models.Scope) -> models.Scope:
    try:
        with UOW() as uow:
            uow.scope_repo.add(scope)
    except UOWAlreadyExists:
        raise AlreadyExists(f"{scope.name} already exists")
    except UOWException as e:
        raise ServiceException(e)

    return scope


def get_scope(UOW: BaseUOW, scope_name: str) -> models.Scope:
    with UOW() as uow:
        scope = uow.scope_repo.get(scope_name)
        if not scope:
            raise NotFound(f"Scope {scope_name} does not exist")


def list_all_scope(UOW: BaseUOW) -> List[models.Scope]:
    with UOW() as uow:
        return uow.scope_repo.list()


def remove_scope(UOW: BaseUOW, scope_name: str):
    try:
        with UOW() as uow:
            uow.scope_repo.remove(scope_name)
    except UOWNotFound:
        raise NotFound(f"{scope_name} cannot be removed because it not existing")


def audit_event(
    UOW: BaseUOW,
    event: models.AuditEvent,
    auth_failure_reason: models.AuthFailureReason,
    http_request: models.HTTPRequest,
    token_id: str,
    result: bool,
):
    audit = models.AuditRecord(
        event=event,
        auth_failure_reason=auth_failure_reason,
        request_method=http_request.method,
        token_id=token_id,
        source=http_request.client_host,
        destination=http_request.url,
        success=result,
    )
    with UOW() as uow:
        uow.audit_repo.add(audit)


def audit_cleanup(UOW: BaseUOW, days_to_keep: int):
    cutoff_date = pendulum.now().subtract(days=days_to_keep)
    with UOW() as uow:
        uow.audit_repo.remove(
            filter_condition=models.AuditRecord.timestamp < cutoff_date
        )


# order_by can be a toggleable button we can click
# we can force "source", "destination" in the UI like they do in gitlab
def list_audits(
    UOW: BaseUOW,
    event: models.AuditEvent = None,
    auth_failure_reason: models.AuthFailureReason = None,
    request_method: str = None,
    token_id: int = None,
    source: str = None,
    destination: str = None,
    order_by: str = None,
    page: int = 1,
    page_size: int = 20,
) -> Tuple[List[models.AuditRecord], int]:
    filters = []
    if event:
        filters.append(models.AuditRecord.event == event)

    if auth_failure_reason:
        filters.append(models.AuditRecord.auth_failure_reason == auth_failure_reason)

    if request_method:
        filters.append(models.AuditRecord.request_method == request_method)

    if token_id:
        filters.append(models.AuditRecord.token_id == token_id)

    if source:
        filters.append(models.AuditRecord.source == source)

    if destination:
        filters.append(models.AuditRecord.destination == destination)

    with UOW() as uow:
        returned_audits = uow.audit_repo.list(
            filters=filters,
            order_by=order_by,
            offset=(page - 1) * page_size,
            limit=page_size,
        )

    has_next_page = len(returned_audits) == page_size
    return (returned_audits, page + 1 if has_next_page else None)


def create_admin_token(UOW: BaseUOW, admin_token: models.AdminToken) -> str:
    try:
        with UOW() as uow:
            plain_token = admin_token.value
            admin_token.value = bcrypt.hashpw(
                admin_token.value.encode(), bcrypt.gensalt(12)
            ).decode("utf-8")
            uow.admin_token_repo.add(admin_token)
    except UOWAlreadyExists:
        raise AlreadyExists(f"Admin Token name {admin_token.name} already exists.")
    except UOWException as e:
        raise ServiceException(e)

    return f"{admin_token.id}.{plain_token}"  # The end user will get the token value this once and then there is no way to retrieve it


def authenticate_admin_token(
    UOW: BaseUOW, admin_token_value: str
) -> models.AdminToken | None:
    with UOW() as uow:
        admin_token_id, admin_token_plain = admin_token_value.split(".")
        admin_token = uow.admin_token_repo.get(admin_token_id)
        if admin_token and bcrypt.checkpw(
            admin_token_plain.encode(), admin_token.value.encode("utf-8")
        ):
            return admin_token
        return None


def list_admin_tokens(UOW: BaseUOW) -> List[models.AdminToken]:
    with UOW() as uow:
        return uow.admin_token_repo.list()


def remove_admin_token(UOW: BaseUOW, admin_token_value: str):
    try:
        with UOW() as uow:
            admin_token_id, _ = admin_token_value.split(".")
            uow.admin_token_repo.remove(admin_token_id)
    except UOWNotFound:
        raise NotFound("Admin Token not found")
    except ValueError:
        raise ValueError("Invalid Token Format")
