from .. import models
from sqlalchemy import (
    create_engine,
    event,
    Enum,
    Table,
    Column,
    Integer,
    String,
    ForeignKey,
    Identity,
    JSON,
    Boolean,
    DateTime,
    TypeDecorator,
    URL,
    UniqueConstraint,
)

from sqlalchemy.orm import registry, relationship, sessionmaker, Session
from sqlalchemy.engine import Engine
from urllib.parse import urlparse
from sqlite3 import Connection as SQLite3Connection
from typing import Optional
import pendulum


class PendulumDateTime(TypeDecorator):
    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """
        Converts a Pendulum datetime to a naive datetime before storing in the DB.
        """
        if isinstance(value, pendulum.DateTime):
            # Convert to UTC and make it naive
            return value.in_tz("UTC").naive()
        return value

    def process_result_value(self, value, dialect):
        """
        Converts a naive datetime from the DB back into a Pendulum datetime.
        """
        if value is not None:
            # Convert naive datetime to a timezone-aware Pendulum datetime in UTC
            return pendulum.instance(value, tz="UTC")
        return value


mapper_registry = registry()

# Tables

scope_table = Table(
    "scope",
    mapper_registry.metadata,
    Column("name", String(32), primary_key=True),
    Column("description", String(128)),
)

token_table = Table(
    "token",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("admin_token_id", String(36), ForeignKey("admin_token.id"), nullable=True),
    Column("name", String(256)),
    Column("user_uid", String(32), ForeignKey("user.uid"), nullable=False),
    Column("parent_id", String(36), ForeignKey("token.id"), nullable=True),
    Column("external_id", String(36), nullable=True),
    Column("value", String(128), unique=True, nullable=False),
    Column("iat", PendulumDateTime(), nullable=False),
    Column("nbf", PendulumDateTime(), nullable=False),
    Column("exp", PendulumDateTime(), nullable=False),
    Column("paths", JSON(), nullable=False),
    Column("valid", Boolean(), nullable=False),
    Column("session", Boolean(), nullable=False, server_default="f"),
    Column("last_used", PendulumDateTime()),
    Column("rotatable", Boolean(), nullable=False),
    # TODO: find a way to selectively set this on dialect
    UniqueConstraint(
        "user_uid",
        "name",
        "parent_id",
        "external_id",
        postgresql_nulls_not_distinct=True,
    ),
)

audit_table = Table(
    "audit",
    mapper_registry.metadata,
    Column("id", Integer, Identity(), primary_key=True),
    Column("event", Enum(models.AuditEvent), nullable=False),
    Column("auth_failure_reason", Enum(models.AuthFailureReason)),
    Column("request_method", String(32), nullable=False),
    Column("token_id", String(36), ForeignKey("token.id"), nullable=False),
    Column("timestamp", PendulumDateTime(), nullable=False),
    Column("source", String(32), nullable=False),
    Column("destination", String(32), nullable=False),
    Column("success", Boolean(), nullable=False),
)

token_scope_association_table = Table(
    "token_scope_association",
    mapper_registry.metadata,
    Column("token_id", String(36), ForeignKey("token.id"), primary_key=True),
    Column("scope_name", String(32), ForeignKey("scope.name"), primary_key=True),
)

group_table = Table(
    "group",
    mapper_registry.metadata,
    Column("name", String(32), primary_key=True),
)

user_table = Table(
    "user",
    mapper_registry.metadata,
    Column("uid", String(32), primary_key=True),
    Column("duid", String(128)),
    Column("is_admin", Boolean()),
)

user_group_association_table = Table(
    "user_group_association",
    mapper_registry.metadata,
    Column("user_uid", String(32), ForeignKey("user.uid"), primary_key=True),
    Column("group_name", String(32), ForeignKey("group.name"), primary_key=True),
)

admin_token_table = Table(
    "admin_token",
    mapper_registry.metadata,
    Column("id", String(36), primary_key=True),
    Column("name", String(128), unique=True, nullable=False),
    Column("value", String(128), unique=True, nullable=False),
    Column("remote_id", String(36), unique=True, nullable=True),
    Column("role", Enum(models.AdminRole), nullable=False),
)

mapper_registry.map_imperatively(
    models.Scope,
    scope_table,
    properties={
        "tokens": relationship(
            models.Token,
            secondary=token_scope_association_table,
            back_populates="scopes",
        )
    },
)

mapper_registry.map_imperatively(
    models.Token,
    token_table,
    properties={
        "user": relationship(models.User, back_populates="tokens"),
        "subtokens": relationship(models.Token, cascade="all, delete-orphan"),
        "admin_token": relationship(models.AdminToken, back_populates="tokens"),
        "scopes": relationship(
            models.Scope,
            secondary=token_scope_association_table,
            back_populates="tokens",
            lazy="joined",
        ),
    },
)


mapper_registry.map_imperatively(
    models.AuditRecord,
    audit_table,
)

mapper_registry.map_imperatively(
    models.Group,
    group_table,
    properties={
        "users": relationship(
            models.User,
            secondary=user_group_association_table,
            back_populates="groups",
        )
    },
)

mapper_registry.map_imperatively(
    models.User,
    user_table,
    properties={
        "tokens": relationship(
            models.Token, back_populates="user", cascade="all, delete-orphan"
        ),
        "groups": relationship(
            models.Group,
            secondary=user_group_association_table,
            back_populates="users",
        ),
    },
)

mapper_registry.map_imperatively(
    models.AdminToken,
    admin_token_table,
    properties={
        "tokens": relationship(
            models.Token, back_populates="admin_token", cascade="all, delete-orphan"
        )
    },
)


def escape_url(url: str, config: dict) -> str:
    parsed = urlparse(url)
    username = config.get("username", parsed.username)
    password = config.get("password", parsed.password)
    return URL.create(
        parsed.scheme,
        username=username,
        password=password,
        host=parsed.hostname,
        port=parsed.port,
        database=parsed.path.lstrip("/"),
    ).render_as_string(hide_password=False)


def make_engine(config: Optional[dict] = None) -> Engine:
    config = config or {}
    url = escape_url(config.get("url", "sqlite://"), config)
    engine_options = config.get("engine_options", {})
    return create_engine(url, **engine_options)


def create_db(engine: Engine):
    """Apply all mappings to create our db."""
    mapper_registry.metadata.create_all(engine)


def delete_db(engine: Engine):
    """Drop all tables to delete the db."""
    mapper_registry.metadata.drop_all(engine)


def reset_db(engine: Engine):
    delete_db(engine)
    create_db(engine)


def make_session_factory(
    engine: Optional[Engine] = None, config: Optional[dict] = None
) -> Session:
    engine = engine or make_engine(config=config)
    create_db(engine)
    Session = sessionmaker(engine, expire_on_commit=False)
    Session.configure(bind=engine)
    return Session


@event.listens_for(Engine, "connect")
def _sqlite_connect(dbapi_connection, connection_record):
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()
