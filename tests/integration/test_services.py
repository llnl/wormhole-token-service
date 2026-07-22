import pytest

import pendulum
import bcrypt
import uuid
from joserfc import jwt
from token_service import services, models


@pytest.fixture
def claims_registry():
    return jwt.JWTClaimsRegistry(leeway=1)


def test_valid_token_validates_successfully(
    UOW, plain_token, make_token, make_user, make_scope
):
    # Setup
    user = make_user()
    scope = make_scope()
    token = make_token()
    token.scopes.append(scope)
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)

    # Execute
    with UOW() as uow:
        is_valid = services.authenticated(uow, plain_token)

    # Verify
    assert is_valid


@pytest.mark.parametrize(
    "kwargs",
    [
        {"nbf": pendulum.now().add(1)},
        {"exp": pendulum.now().subtract(1)},
        {"valid": False},
    ],
)
def test_invalid_tokens_fail_validation(
    UOW, make_token, kwargs, plain_token, make_user, make_scope
):
    # Setup
    user = make_user()
    scope = make_scope()
    token = make_token(**kwargs)
    token.scopes.append(scope)
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)

    # Execute and Verify
    with UOW() as uow:
        assert not services.authenticated(uow, plain_token)


def test_invalidate_token(UOW, plain_token, make_token, make_user, make_scope):
    # Setup
    user = make_user()
    scope = make_scope()
    token = make_token()
    token.scopes.append(scope)
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)

    # Execute and Verify
    assert token.valid

    _ = services.invalidate_token(UOW, plain_token)

    with UOW() as uow:
        assert not uow.token_repo.get(token.id).valid


def test_update_token_last_used(UOW, plain_token, make_token, make_user, make_scope):
    # Setup
    user = make_user()
    scope = make_scope()
    token = make_token()
    token.scopes.append(scope)
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)

    # Execute and Verify
    token = services.update_token_last_used(UOW, plain_token)
    assert token.last_used
    original_token_used_time = token.last_used

    token = services.update_token_last_used(UOW, plain_token)
    assert original_token_used_time < token.last_used


def test_create_valid_jwt_by_token(
    UOW,
    kid,
    plain_token,
    jwt_config,
    claims_registry,
    make_token,
    make_user,
    make_scope,
    make_group,
):
    # Setup
    user = make_user()
    group = make_group()
    scope = make_scope()
    token = make_token()
    token.scopes.append(scope)
    user.tokens.append(token)
    user.groups.append(group)
    with UOW() as uow:
        uow.user_repo.add(user)

    token_id = plain_token.split(".")[0]
    # Execute
    with UOW() as uow:
        encoded_jwt = services.create_jwt_from_token(uow, token_id, jwt_config)
    tk = jwt.decode(encoded_jwt, jwt_config.signing_secret)

    # Verify
    with UOW() as uow:
        retrieved_token = uow.token_repo.get(token.id)
        scope_names = [scope.name for scope in retrieved_token.scopes]
        user = uow.user_repo.get(token.user_uid)
        groups = [group.name for group in user.groups]
        assert tk.claims["sub"] == retrieved_token.user_uid
        # TODO: unix timestamp
        assert tk.claims["scopes"] == scope_names
        assert tk.claims["groups"] == groups

        claims_registry.validate(tk.claims)


def test_create_valid_jwt_from_user(
    UOW, kid, jwt_config, claims_registry, make_user, make_group, make_token
):
    # Setup
    user = make_user()
    group = make_group()
    token = make_token()
    user.groups.append(group)
    with UOW() as uow:
        uow.user_repo.add(user)

    # Execute
    encoded_jwt = services.create_jwt_from_user(UOW, user, token.id, jwt_config)
    tk = jwt.decode(encoded_jwt, jwt_config.signing_secret)

    # Verify
    with UOW() as uow:
        retrieved_user = uow.user_repo.get(user.uid)
        groups = [group.name for group in retrieved_user.groups]
        assert tk.claims["sub"] == retrieved_user.uid
        assert tk.claims["groups"] == groups
        assert tk.claims["token_id"] == token.id


def test_jwt_structure(
    UOW,
    kid,
    jwt_config,
    claims_registry,
    make_user,
    make_group,
    make_token,
    make_scope,
    plain_token,
):
    # Setup
    user = make_user()
    group = make_group()
    user.groups.append(group)
    scope = make_scope()
    token = make_token()
    token.scopes.append(scope)
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)

    token_id = plain_token.split(".")[0]

    # Execute
    user_jwt = services.create_jwt_from_user(
        UOW,
        user,
        token.id,
        jwt_config,
    )
    user_tk = jwt.decode(user_jwt, jwt_config.signing_secret)
    with UOW() as uow:
        token_jwt = services.create_jwt_from_token(uow, token_id, jwt_config)
    token_tk = jwt.decode(token_jwt, jwt_config.signing_secret)

    # Verify
    assert abs(token_tk.claims["iat"] - user_tk.claims["iat"]) < 1
    assert abs(token_tk.claims["exp"] - user_tk.claims["exp"]) < 1
    assert abs(token_tk.claims["nbf"] - user_tk.claims["nbf"]) < 1
    assert user_tk.claims.keys() == token_tk.claims.keys()


def test_token_default_expiration_is_30_days(
    UOW, make_user, make_scope, plain_token, make_token
):
    # Setup
    user = make_user()
    scope = make_scope()
    with UOW() as uow:
        uow.user_repo.add(user)
        uow.scope_repo.add(scope)

    _, original_token = plain_token.split(".")
    token = make_token(value=original_token)  # make pre hash token

    # Execute
    plain_token = services.create_token(UOW, token, [scope.name])
    token_id, token_plain = plain_token.split(".")

    # Verify
    with UOW() as uow:
        token = uow.token_repo.get(token.id)

    delta_seconds = (token.exp - token.iat).total_seconds()
    days = delta_seconds / (24 * 60 * 60)
    assert 29 <= days <= 31


def test_create_token(UOW, plain_token, make_token, make_scope, make_user):
    # Setup
    user = make_user()
    scope = make_scope()
    with UOW() as uow:
        uow.user_repo.add(user)
        uow.scope_repo.add(scope)

    _, original_token = plain_token.split(".")
    token = make_token(value=original_token)  # make pre hash token

    # Execute
    plain_token = services.create_token(UOW, token, [scope.name])
    token_id, token_plain = plain_token.split(".")

    # Verify
    with UOW() as uow:
        token = uow.token_repo.get(token.id)

    assert bcrypt.checkpw(token_plain.encode(), token.value.encode("utf-8"))
    assert token_id == token.id
    assert original_token != token.value


def test_create_token_fails_when_invalid_scope(
    UOW, plain_token, make_token, make_user, make_scope
):
    # Setup
    user = make_user()
    scope = make_scope()
    with UOW() as uow:
        uow.user_repo.add(user)
        uow.scope_repo.add(scope)
    _, original_token = plain_token.split(".")
    token = make_token(value=original_token)  # make pre hash token
    bad_scope = make_scope(name="bad_scope")

    # Execute and Verify
    with pytest.raises(Exception):
        _ = services.create_token(UOW, token, [bad_scope])


def test_subtoken_valid_for_parent_lifetime(UOW, make_token, make_scope, make_user):
    # Setup
    token_value = "token"
    now = pendulum.now()
    user = make_user()
    scope = make_scope()
    with UOW() as uow:
        uow.user_repo.add(user)
        uow.scope_repo.add(scope)

    token = make_token(value=token_value)
    subtoken = make_token(id="2", name="bar", value=token_value, exp=now)

    # Execute
    plain_token = services.create_token(UOW, token, [scope.name])
    plain_subtoken = services.create_token(
        UOW, subtoken, [scope.name], parent_id=token.id
    )

    # Verify - even though the subtoken is expired now,
    # it derives its lifetime from the parent
    with UOW() as uow:
        token = uow.token_repo.get(token.id)
        subtoken = uow.token_repo.get(subtoken.id)
        assert subtoken.exp == now
        assert token.exp != subtoken.exp
        assert services.authenticated(uow, plain_token)
        assert services.authenticated(uow, plain_subtoken)


def test_subtoken_jwt_claims_filled(
    UOW, jwt_config, claims_registry, make_token, make_scope, make_user, kid
):
    # Setup
    token_value = "token"
    external_id = str(uuid.uuid4())
    now = pendulum.now()
    user = make_user()
    scope = make_scope()

    with UOW() as uow:
        uow.user_repo.add(user)
        uow.scope_repo.add(scope)

    token = make_token(value=token_value)
    subtoken = make_token(id="2", name="bar", value=token_value, exp=now)

    services.create_token(UOW, token, [scope.name])
    services.create_token(
        UOW, subtoken, [scope.name], parent_id=token.id, external_id=external_id
    )

    # Execute
    with UOW() as uow:
        encoded_jwt = services.create_jwt_from_token(
            uow,
            subtoken.id,
            jwt_config,
        )

    tk = jwt.decode(encoded_jwt, jwt_config.signing_secret)

    # Verify
    assert tk.claims["parent_id"] == token.id
    assert tk.claims["external_id"] == external_id


def test_delete_token_deletes_subtokens(
    UOW, plain_token, make_token, make_scope, make_user
):
    # Setup
    user = make_user()
    scope = make_scope()
    with UOW() as uow:
        uow.user_repo.add(user)
        uow.scope_repo.add(scope)

    token = make_token(value=plain_token)
    subtoken = make_token(id="2", name="bar", parent_id=token.id)

    # Execute
    services.create_token(UOW, token, [scope.name])
    services.create_token(UOW, subtoken, [scope.name], parent_id=token.id)

    # Verify
    with UOW() as uow:
        assert uow.token_repo.get(token.id)
        assert uow.token_repo.get(subtoken.id)

    # Execute - removing the parent removes the subtoken
    services.remove_token_by_value(UOW, plain_token, user.uid)

    # Verify
    with UOW() as uow:
        assert not uow.token_repo.get(token.id)
        assert not uow.token_repo.get(subtoken.id)


def test_delete_subtoken_leaves_parent_intact(
    UOW, plain_token, make_token, make_scope, make_user
):
    # Setup
    user = make_user()
    scope = make_scope()
    with UOW() as uow:
        uow.user_repo.add(user)
        uow.scope_repo.add(scope)

    token_id, token_value = plain_token.split(".")
    token = make_token(value=token_value)
    subtoken = make_token(id="2", name="bar", value=token_value, parent_id=token.id)

    services.create_token(UOW, token, [scope.name])
    services.create_token(UOW, subtoken, [scope.name], parent_id=token.id)

    # Verify
    with UOW() as uow:
        assert uow.token_repo.get(token.id)
        assert uow.token_repo.get(subtoken.id)

    # Execute
    services.remove_token_by_value(UOW, f"{subtoken.id}.{token_value}", user.uid)

    # Verify
    with UOW() as uow:
        assert uow.token_repo.get(token.id)
        assert not uow.token_repo.get(subtoken.id)


def test_adding_a_user_to_group(UOW, make_user, make_group):
    # Setup
    user = make_user()
    group = make_group()
    with UOW() as uow:
        uow.user_repo.add(user)
        uow.group_repo.add(group)

    # Execute
    group = services.add_user_to_group(UOW, group.name, user.uid)

    # Verify
    assert group.users[0] == user


def test_removing_a_user_from_group(UOW, make_user, make_group):
    # Setup
    user = make_user()
    group = make_group()
    group.users.append(user)
    with UOW() as uow:
        uow.group_repo.add(group)

    # Execute and Verify
    assert group.users
    group = services.remove_user_from_group(UOW, group.name, user.uid)
    assert not group.users


def test_audit_cleanup_removes_old_audits(UOW, make_user, make_token, make_audit):
    # Setup
    user = make_user()
    token = make_token()
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)
    audit = make_audit(timestamp=pendulum.now().subtract(91))

    # Execute
    with UOW() as uow:
        uow.audit_repo.add(audit)
        assert uow.audit_repo.list()

    services.audit_cleanup(UOW, days_to_keep=90)

    # Verify
    with UOW() as uow:
        assert not uow.audit_repo.list()


def test_audit_cleanup_does_not_remove_new_audits(
    UOW, make_user, make_token, make_audit
):
    # Setup
    user = make_user()
    token = make_token()
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)
    audit = make_audit()

    # Execute
    with UOW() as uow:
        uow.audit_repo.add(audit)
        assert uow.audit_repo.list()

    services.audit_cleanup(UOW, days_to_keep=90)

    # Verify
    with UOW() as uow:
        assert uow.audit_repo.list()


def test_audit_successful_token_creation_event(
    UOW, make_user, make_token, make_httprequest
):
    # Setup
    user = make_user()
    token = make_token()
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)
    http_request = make_httprequest()
    event = models.AuditEvent.CREATION
    auth_failure_reason = None
    result = True

    # Execute
    services.audit_event(
        UOW,
        event=event,
        auth_failure_reason=auth_failure_reason,
        http_request=http_request,
        token_id=token.id,
        result=result,
    )

    # Verify
    with UOW() as uow:
        audit = uow.audit_repo.get(1)
        assert audit.event == event
        assert audit.auth_failure_reason == auth_failure_reason
        assert audit.request_method == http_request.method
        assert audit.source == http_request.client_host
        assert audit.destination == http_request.url
        assert audit.token_id == token.id
        assert audit.success == result


def test_audit_unsuccessful_token_authentication_event(
    UOW, make_user, make_token, make_httprequest
):
    # Setup
    user = make_user()
    token = make_token()
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)
    http_request = make_httprequest(method="GET")
    event = models.AuditEvent.AUTH
    auth_failure_reason = models.AuthFailureReason.EXPIRED
    result = False

    # Execute
    services.audit_event(
        UOW,
        event=event,
        auth_failure_reason=auth_failure_reason,
        http_request=http_request,
        token_id=token.id,
        result=result,
    )

    # Verify
    with UOW() as uow:
        audit = uow.audit_repo.get(1)
        assert audit.event == event
        assert audit.auth_failure_reason == auth_failure_reason
        assert audit.request_method == http_request.method
        assert audit.source == http_request.client_host
        assert audit.destination == http_request.url
        assert audit.token_id == token.id
        assert audit.success == result


def test_list_audits_in_desc_order(UOW, make_user, make_token, make_audit):
    # Setup
    user = make_user()
    token = make_token()
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)
    for id in range(3):
        audit = make_audit(id=id)
        with UOW() as uow:
            uow.audit_repo.add(audit)

    # Execute
    audits, _ = services.list_audits(UOW, order_by="desc")

    # Verify
    ids = [audit.id for audit in audits]
    assert ids == sorted(ids, reverse=True)


def test_list_audits_paginates(UOW, make_user, make_token, make_audit):
    # Setup
    user = make_user()
    token = make_token()
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)
    for id in range(4):
        audit = make_audit(id=id)
        with UOW() as uow:
            uow.audit_repo.add(audit)

    page_size = 2

    # Execute
    audits1, next_page = services.list_audits(UOW, page=1, page_size=page_size)
    audits2, next_next_page = services.list_audits(
        UOW, page=next_page, page_size=page_size
    )
    audits3, next_next_next_page = services.list_audits(
        UOW, page=next_next_page, page_size=page_size
    )

    # Verify
    assert len(audits1) == 2 and len(audits2) == 2
    assert audits1[0] != audits2[0].id
    assert next_page == 2
    assert not next_next_next_page and not audits3


def test_list_audits_filter_by_source(UOW, make_user, make_token, make_audit):
    # Setup
    user = make_user()
    token = make_token()
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)
    for id in range(1, 3):
        audit = make_audit(id=id, source="foo")
        with UOW() as uow:
            uow.audit_repo.add(audit)

    for id in range(3, 5):
        audit = make_audit(id=id, source="bar")
        with UOW() as uow:
            uow.audit_repo.add(audit)

    # Execute
    audits_with_foo_source, _ = services.list_audits(UOW, source="foo")

    # Verify
    for audit in audits_with_foo_source:
        assert audit.source == "foo"


def test_list_audits_filter_by_source_and_destination(
    UOW, make_user, make_token, make_audit
):
    # Setup
    user = make_user()
    token = make_token()
    user.tokens.append(token)
    with UOW() as uow:
        uow.user_repo.add(user)
    audit1 = make_audit(id=1, source="foo", destination="example.com/foobar")
    audit2 = make_audit(id=2, source="bar", destination="example.com/barbaz")
    audit3 = make_audit(id=3, source="bar", destination="example.com/foobar")
    audit4 = make_audit(id=4, source="foo", destination="example.com/barbaz")
    with UOW() as uow:
        uow.audit_repo.add(audit1)
        uow.audit_repo.add(audit2)
        uow.audit_repo.add(audit3)
        uow.audit_repo.add(audit4)

    # Execute
    audits_with_foo_source_and_foobar_dest, _ = services.list_audits(
        UOW, source="foo", destination="example.com/foobar"
    )

    # Verify
    assert len(audits_with_foo_source_and_foobar_dest) == 1
    assert (
        audits_with_foo_source_and_foobar_dest[0].source == "foo"
        and audits_with_foo_source_and_foobar_dest[0].destination
        == "example.com/foobar"
    )
