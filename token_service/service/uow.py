"""Unit of Work for Token Service."""

from attrs import define, field
from contextlib import contextmanager
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Callable

from ..store import repository
from ..store.orm import make_session_factory


@define
class UOWException(Exception):
    """Base Repo Exception."""

    msg: str


@define
class AlreadyExists(UOWException):
    """Already Exists Error."""

    pass


@define
class NotFound(UOWException):
    """Already Exists Error."""

    pass


@define
class BaseUOW:
    """Base UOW."""

    @contextmanager
    def __call__(self):
        yield self


@define
class SqlUOW(BaseUOW):
    session: Session
    token_repo: repository.SqlTokenRepo = field()
    scope_repo: repository.SqlScopeRepo = field()
    user_repo: repository.SqlUserRepo = field()
    group_repo: repository.SqlGroupRepo = field()
    audit_repo: repository.SqlAuditRepo = field()
    admin_token_repo: repository.SqlAdminTokenRepo = field()

    @token_repo.default
    def _token_repo(self):
        return repository.SqlTokenRepo(self.session)

    @scope_repo.default
    def _scope_repo(self):
        return repository.SqlScopeRepo(self.session)

    @user_repo.default
    def _user_repo(self):
        return repository.SqlUserRepo(self.session)

    @group_repo.default
    def _group_repo(self):
        return repository.SqlGroupRepo(self.session)

    @audit_repo.default
    def _audit_repo(self):
        return repository.SqlAuditRepo(self.session)

    @admin_token_repo.default
    def _admin_token_repo(self):
        return repository.SqlAdminTokenRepo(self.session)


def make_sql_uow(engine: Engine) -> Callable[[], SqlUOW]:
    Session = make_session_factory(engine)

    @contextmanager
    def _fn():
        with Session() as session:
            yield SqlUOW(session)

            try:
                session.commit()
            except IntegrityError as e:
                session.rollback()
                if "unique" in str(e.orig).lower():
                    raise AlreadyExists("")
                raise UOWException(e)
            except repository.NotFound as e:
                session.rollback()
                raise NotFound(e.msg)
            except (repository.RepoException, Exception) as e:
                session.rollback()
                raise UOWException(e)

    return _fn
