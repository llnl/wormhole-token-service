"""`POST /krb/token`: Kerberos-authenticated token creation.

Shares `create_token_for_user` with `POST /token`, so the two cannot drift apart.
"""

from fastapi import APIRouter, Depends, Form, status
from typing import Annotated

from ..dependencies import KerberosAuthenticator
from ..models import User
from ..pydantic_models import Token as PydanticToken
from ..service.uow import BaseUOW
from .shared import create_token_for_user


def make_krb_router(UOW: BaseUOW, krb_auth: KerberosAuthenticator) -> APIRouter:
    router = APIRouter(
        prefix="/krb/token",
        tags=["tokens"],
    )

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def create(
        user: Annotated[User, Depends(krb_auth)],
        token_data: Annotated[PydanticToken, Form()],
    ) -> str:
        return await create_token_for_user(UOW, user, token_data)

    return router
