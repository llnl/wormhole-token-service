"""Repositories for Token Service."""

from attrs import define
from sqlalchemy import select, and_, delete
from sqlalchemy.orm import Session, selectinload
from sqlalchemy.exc import NoResultFound
from sqlalchemy.sql.expression import (
    BinaryExpression,
)
from typing import Optional, List
from multimethod import multimethod

from .. import models


@define
class RepoException(Exception):
    """Base Repo Exception."""

    msg: str


@define
class NotFound(RepoException):
    pass


@define
class BaseRepo:
    """Base repository."""


@define
class SqlAlchemyRepo(BaseRepo):
    session: Session


@define
class SqlTokenRepo(SqlAlchemyRepo):
    def get(self, token_id: Optional[str]) -> Optional[models.Token]:
        return (
            self.session.execute(
                select(models.Token).where(models.Token.id == token_id)
            )
            .unique()
            .scalar_one_or_none()
        )

    def get_subtoken(
        self, name: str, parent_id: str, external_id: str
    ) -> Optional[models.Token]:
        return (
            self.session.execute(
                select(models.Token).where(
                    and_(
                        models.Token.name == name,
                        models.Token.parent_id == parent_id,
                        models.Token.external_id == external_id,
                    )
                )
            )
            .unique()
            .scalar_one_or_none()
        )

    def get_session_token(self, user_uid: str, name: str) -> Optional[models.Token]:
        return (
            self.session.execute(
                select(models.Token).where(
                    and_(
                        models.Token.user_uid == user_uid,
                        models.Token.name == name,
                        models.Token.session,
                    )
                )
            )
            .unique()
            .scalar_one_or_none()
        )

    def remove(self, token_id: str):
        t = self.get(token_id)
        if t is None:
            raise NotFound(f"Token with id {token_id} does not exist.")

        self.session.delete(t)

    @multimethod
    def add(self, token: models.Token):
        self.session.add(token)

    @add.register
    def _(self, tokens: List[models.Token]):
        self.session.add_all(tokens)

    def list(self) -> List[models.Token]:
        return self.session.execute(select(models.Token)).unique().scalars().all()


@define
class SqlScopeRepo(SqlAlchemyRepo):
    def get(self, scope_name: str) -> Optional[models.Scope]:
        try:
            scope = self.session.execute(
                select(models.Scope).where(models.Scope.name == scope_name)
            ).scalar_one()
        except NoResultFound as e:
            raise NotFound(f"Scope with name {scope_name} does not exist.") from e

        return scope

    def remove(self, scope_name: str):
        # TODO refactor Scope get function to not return NoResultFound. Have this handled elsewhere to match other repositories
        s = self.get(scope_name)
        self.session.delete(s)

    @multimethod
    def add(self, scope: models.Scope):
        self.session.add(scope)

    @add.register
    def _(self, scopes: List[models.Scope]):
        self.session.add_all(scopes)

    def list(self) -> List[models.Scope]:
        return self.session.execute(select(models.Scope)).scalars().all()


@define
class SqlUserRepo(SqlAlchemyRepo):
    def get(self, user_uid: str) -> Optional[models.User]:
        return self.session.execute(
            select(models.User).where(models.User.uid == user_uid)
        ).scalar_one_or_none()

    def remove(self, user_uid: str):
        u = self.get(user_uid)
        if u is None:
            raise NotFound(f"User with uid {user_uid} does not exist.")
        self.session.delete(u)

    @multimethod
    def add(self, user: models.User):
        self.session.add(user)

    @add.register
    def _(self, users: List[models.User]):
        self.session.add_all(users)

    def list(self) -> List[models.User]:
        return self.session.execute(select(models.User)).scalars().all()


@define
class SqlGroupRepo(SqlAlchemyRepo):
    def get(self, group_name: str) -> Optional[models.Group]:
        return self.session.execute(
            select(models.Group).where(models.Group.name == group_name)
        ).scalar_one_or_none()

    def remove(self, group_name: str):
        g = self.get(group_name)
        if g is None:
            raise NotFound(f"Group with the name {group_name} does not exist.")
        self.session.delete(g)

    @multimethod
    def add(self, group: models.Group):
        self.session.add(group)

    @add.register
    def _(self, groups: List[models.Group]):
        self.session.add_all(groups)

    def list(self) -> List[models.Group]:
        query = select(models.Group).options(selectinload(models.Group.users))

        return self.session.execute(query).scalars().all()


@define
class SqlAuditRepo(SqlAlchemyRepo):
    def get(self, audit_id: int) -> Optional[models.AuditRecord]:
        return self.session.execute(
            select(models.AuditRecord).where(models.AuditRecord.id == audit_id)
        ).scalar_one_or_none()

    def remove(self, filter_condition: BinaryExpression):
        stmt = delete(models.AuditRecord).where(filter_condition)
        self.session.execute(stmt)

    @multimethod
    def add(self, audit: models.AuditRecord):
        self.session.add(audit)

    @add.register
    def _(self, audits: List[models.AuditRecord]):
        self.session.add_all(audits)

    def list(
        self,
        order_by: str = None,
        filters: List = None,
        offset: int = None,
        limit: int = None,
    ) -> Optional[List[models.AuditRecord]]:
        query = select(models.AuditRecord)
        if filters:
            query = query.where(and_(*filters))

        if order_by == "desc":
            order = models.AuditRecord.timestamp.desc()
        else:
            order = models.AuditRecord.timestamp

        query = query.order_by(order)

        if offset:
            query = query.offset(offset)

        if limit:
            query = query.limit(limit)
        return self.session.execute(query).scalars().all()


@define
class SqlAdminTokenRepo(SqlAlchemyRepo):
    def get(self, admin_token_id: str) -> Optional[models.AdminToken]:
        return self.session.execute(
            select(models.AdminToken).where(models.AdminToken.id == admin_token_id)
        ).scalar_one_or_none()

    def remove(self, admin_token_id: str):
        a = self.get(admin_token_id)
        if a is None:
            raise NotFound(f"AdminToken with id {admin_token_id} does not exist.")
        self.session.delete(a)

    @multimethod
    def add(self, admin_token: models.AdminToken):
        self.session.add(admin_token)

    @add.register
    def _(self, admin_tokens: List[models.AdminToken]):
        self.session.add_all(admin_tokens)

    def list(self) -> List[models.AdminToken]:
        return self.session.execute(select(models.AdminToken)).scalars().all()
