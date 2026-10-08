import sys
import types
from contextlib import contextmanager
from unittest import mock

from attrs import define
from typing import Any, Annotated

from fastapi import Header

from token_service.models import User


def token_call_target():
    raise NotImplementedError("Implement via mock")


def oidc_call_target():
    raise NotImplementedError("Implement via mock")


def jwt_call_target():
    raise NotImplementedError("Implement via mock")


@define
class FakeTokenAuthenticator:
    uow: Any

    def __hash__(self):
        return hash(self.__class__.__name__)

    # NOTE: even for fakes, we need annotated calls for FastAPI to know the shape
    # of data and whether or not it is required
    async def __call__(
        self,
        x_token: Annotated[str, Header()] | None,
        x_machine: Annotated[str, Header()] | None,
    ) -> User | None:
        return token_call_target()


@define
class FakeOIDCAuthenticator:
    config: dict
    uow: Any

    def __hash__(self):
        return hash(self.__class__.__name__)

    def __call__(self) -> User | None:
        return oidc_call_target()

    def setup(self, app) -> None:
        return None


@define
class FakeJWTAuthenticator:
    config: dict
    uow: Any

    def __hash__(self):
        return hash(self.__class__.__name__)

    def __call__(self) -> User | None:
        return jwt_call_target()


@contextmanager
def fake_gssapi(ctx=None):
    """Stand in for the `gssapi` module, so Kerberos logic runs without it.

    `SecurityContext` returns `ctx`; `Name` and `Credentials` are mocks, and
    `raw.NameType` and `exceptions.GSSError` are stand-ins tests can use.

    Yields:
        The stub module, installed as `gssapi` in `sys.modules` for the block.
    """

    module = types.ModuleType("gssapi")
    exceptions = types.ModuleType("gssapi.exceptions")
    raw = types.ModuleType("gssapi.raw")

    class GSSError(Exception):
        pass

    class NameType:
        kerberos_principal = "KERBEROS_PRINCIPAL"
        hostbased_service = "HOSTBASED_SERVICE"

    exceptions.GSSError = GSSError
    raw.NameType = NameType
    module.exceptions = exceptions
    module.raw = raw
    module.SecurityContext = mock.MagicMock(return_value=ctx)
    module.Name = mock.MagicMock()
    module.Credentials = mock.MagicMock()

    with mock.patch.dict(
        sys.modules,
        {"gssapi": module, "gssapi.exceptions": exceptions, "gssapi.raw": raw},
    ):
        yield module


@contextmanager
def fake_handshake(ctx):
    """`fake_gssapi`, plus a stubbed acceptor credential so no keytab is read.

    Yields:
        The stub `gssapi` module.
    """

    from token_service.auth.kerberos import KerberosAcceptor

    with mock.patch.object(KerberosAcceptor, "creds", new_callable=mock.PropertyMock):
        with fake_gssapi(ctx) as module:
            yield module
