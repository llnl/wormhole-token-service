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
