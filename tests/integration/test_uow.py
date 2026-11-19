import pytest

from token_service.store.orm import make_engine, reset_db
from token_service.service.uow import make_sql_uow


@pytest.fixture(scope="module")
def engine():
    return make_engine()


@pytest.fixture(autouse=True)
def clean_db(engine):
    reset_db(engine)


@pytest.fixture(scope="module")
def UOW(engine):
    return make_sql_uow(engine)


def test_unique_keys_are_unique(UOW, make_token, make_scope, make_user, make_group):
    # Setup
    user1 = make_user(uid="foo_user")
    user2 = make_user(uid="foo_user")
    token1 = make_token()
    token2 = make_token()
    scope1 = make_scope()
    scope2 = make_scope()
    group1 = make_group()
    group2 = make_group()

    # Execute
    with UOW() as uow:
        user1.tokens.append(token1)
        uow.scope_repo.add(scope1)
        uow.user_repo.add(user1)
        uow.group_repo.add(group1)

    # Verify
    with pytest.raises(Exception):
        with UOW() as uow:
            uow.token_repo.add(token2)
    with pytest.raises(Exception):
        with UOW() as uow:
            uow.scope_repo.add(scope2)
    with pytest.raises(Exception):
        with UOW() as uow:
            user2.tokens.append(token2)
            uow.user_repo.add(user2)
    with pytest.raises(Exception):
        with UOW() as uow:
            uow.group_repo.add(group2)


def test_associations_exist(
    UOW, make_token, make_scope, make_user, make_group, make_audit
):
    # Setup
    token = make_token()
    scope = make_scope()
    user = make_user()
    group = make_group()

    # Execute
    with UOW() as uow:
        token.scopes.append(scope)
        user.groups.append(group)
        user.tokens.append(token)
        uow.user_repo.add(user)

    # Verify
    assert token.scopes[0] == scope
    assert scope.tokens[0] == token
    assert user.groups[0] == group
    assert group.users[0] == user


def test_removing_a_user_unlinks_group(UOW, make_token, make_user, make_group):
    # Setup
    user = make_user()
    group = make_group()

    with UOW() as uow:
        user.groups.append(group)
        uow.user_repo.add(user)

    # Execute and Verify
    with UOW() as uow:
        assert group in uow.user_repo.get(user.uid).groups
        uow.user_repo.remove(user.uid)

        # Ensure user group assocation is removed but group still exists
        retrieved_group = uow.group_repo.get(group.name)
        assert retrieved_group
        assert not retrieved_group.users


def test_removing_a_user_deletes_associated_tokens(UOW, make_token, make_user):
    # Setup
    token = make_token()
    user = make_user()

    with UOW() as uow:
        user.tokens.append(token)
        uow.user_repo.add(user)

    # Execute and Verify
    with UOW() as uow:
        assert token in uow.user_repo.get(user.uid).tokens
        uow.user_repo.remove(user.uid)

        # Ensure user tokens are cascade deleted
        assert not uow.token_repo.get(token.id)


def test_removing_a_group_unlinks_user(UOW, make_user, make_group):
    # Setup
    user = make_user()
    group = make_group()

    with UOW() as uow:
        user.groups.append(group)
        uow.user_repo.add(user)

    # Execute
    with UOW() as uow:
        assert user in uow.group_repo.get(group.name).users
        uow.group_repo.remove(group.name)
        # Ensure user-group association is removed
        retrieved_user = uow.user_repo.get(user.uid)
        assert retrieved_user
        assert not retrieved_user.groups


def test_removing_a_user_from_group_unlinks_group(UOW, make_user, make_group):
    # Setup
    user = make_user()
    group = make_group()

    with UOW() as uow:
        user.groups.append(group)
        uow.user_repo.add(user)

    # Execute and Verify
    assert user.groups
    assert group.users
    user.groups.remove(group)

    assert not user.groups
    assert not group.users


def test_removing_a_scope_unlinks_token(UOW, make_user, make_token, make_scope):
    # Setup
    user = make_user()
    token = make_token()
    scope = make_scope()

    with UOW() as uow:
        user.tokens.append(token)
        token.scopes.append(scope)
        uow.user_repo.add(user)
        uow.token_repo.add(token)

    # Execute and Verify
    with UOW() as uow:
        assert scope in uow.token_repo.get(token.id).scopes
        uow.scope_repo.remove(scope.name)

    with UOW() as uow:
        # Ensure token-scope assocation is removed
        retrieved_token = uow.token_repo.get(token.id)
        assert retrieved_token
        assert not retrieved_token.scopes


def test_deleting_a_token_leaves_user_intact(UOW, make_user, make_token):
    # Setup
    user = make_user()
    token = make_token()

    with UOW() as uow:
        user.tokens.append(token)
        uow.user_repo.add(user)

    # Execute and Verify
    with UOW() as uow:
        assert token in uow.user_repo.get(user.uid).tokens
        uow.token_repo.remove(token.id)

        # Ensure user is still there
        retrieved_user = uow.user_repo.get(user.uid)
        assert retrieved_user
        assert not retrieved_user.tokens
        assert not uow.token_repo.get(token.id)


def test_deleting_a_token_leaves_scope_intact(UOW, make_token, make_scope, make_user):
    # Setup
    user = make_user()
    token = make_token()
    scope = make_scope()

    with UOW() as uow:
        token.scopes.append(scope)
        user.tokens.append(token)
        uow.user_repo.add(user)

    # Execute and Verify
    with UOW() as uow:
        assert token in uow.scope_repo.get(scope.name).tokens
        uow.token_repo.remove(token.id)

    with UOW() as uow:
        # Ensure scope is still there
        retrieved_scope = uow.scope_repo.get(scope.name)
        assert retrieved_scope
        assert not retrieved_scope.tokens
        assert not uow.token_repo.get(token.id)


def test_removing_an_admin_token_deletes_associated_tokens(
    UOW, make_token, make_admin_token, make_user
):
    # Setup
    token = make_token()
    user = make_user()
    admin_token = make_admin_token()

    with UOW() as uow:
        user.tokens.append(token)
        uow.user_repo.add(user)
        admin_token.tokens.append(token)
        uow.admin_token_repo.add(admin_token)

    # Execute and Verify
    with UOW() as uow:
        assert token in uow.admin_token_repo.get(admin_token.id).tokens
        uow.admin_token_repo.remove(admin_token.id)

        assert not uow.token_repo.get(token.id)
