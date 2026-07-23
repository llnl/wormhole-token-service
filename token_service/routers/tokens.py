from fastapi import APIRouter, Depends, Form, HTTPException, status, Query
from typing import Annotated

from token_service import adapter
from ..dependencies import BaseUserAuthDependency, TokenAuthenticator, TokenCredentials
from ..models import User
from ..pydantic_models import Token as PydanticToken
from ..pydantic_models import JWTResponse, TokenRotationRequest
from ..service.uow import BaseUOW
from ..services import (
    create_token,
    list_user_tokens,
    remove_token_by_value,
    remove_token_by_name,
    rotate_token,
    make_rotatable,
    ServiceException,
    AlreadyExists,
    NotFound,
    InvalidToken,
)


def make_router(
    UOW: BaseUOW,
    auth: BaseUserAuthDependency,
    token_auth: TokenAuthenticator,
    token_config: dict,
):
    router = APIRouter(
        prefix="/token",
        tags=["tokens"],
    )

    # Extract token settings
    max_lifetime_days = token_config["max_lifetime_days"]

    @router.get("/jwt", status_code=status.HTTP_200_OK)
    async def jwt(
        creds: Annotated[TokenCredentials, Depends(token_auth)],
    ) -> JWTResponse:
        return JWTResponse(jwt=creds.jwt)

    @router.get("", status_code=status.HTTP_200_OK)
    async def list_tokens(
        user: Annotated[User, Depends(auth)],
    ) -> list[PydanticToken]:
        try:
            return [adapter.from_token(t) for t in list_user_tokens(UOW, user.uid)]
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)

    # TODO List all tokens for admins

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def create(
        user: Annotated[User, Depends(auth)],
        token_data: Annotated[PydanticToken, Form()],
    ) -> str:
        token = adapter.to_token(token_data)
        token.user_uid = user.uid
        scopes = [_ for _ in token_data.scopes or [] if _]
        try:
            return create_token(UOW, token, scopes)
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e.msg)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        except ServiceException as e:
            # TODO add logging
            # log.error(f"failed creating token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
            )

    @router.put("/rotate", status_code=status.HTTP_200_OK)
    async def rotate(
        creds: Annotated[TokenCredentials, Depends(token_auth)],
        exp_days: int | None = Query(
            None,
            description="Requested token lifetime in days (max: configured max_lifetime)",
        ),
    ) -> str:
        try:
            # TODO create uow context before calling rotate_token
            return rotate_token(
                UOW,
                creds.token_id,
                exp_days=exp_days,
                max_lifetime_days=max_lifetime_days,
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
        except InvalidToken:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Token requires attestation before rotation",
            )
        except ServiceException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
            )

    @router.patch("/attestation", status_code=status.HTTP_204_NO_CONTENT)
    async def attestation(
        user: Annotated[User, Depends(auth)],
        req: TokenRotationRequest,
    ):
        try:
            make_rotatable(UOW, user.uid, [str(tid) for tid in req.ids])
        except NotFound as e:
            # log user tried rotating a token it does not own
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        except InvalidToken:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail="Cannot attest for invalid or expired tokens",
            )
        except ServiceException as e:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
            )

    @router.delete("/{token_value}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_by_value(
        user: Annotated[User, Depends(auth)],
        token_value: str,
    ):
        try:
            remove_token_by_value(UOW, token_value, user.uid)
        except NotFound:
            # Add logging to log e.msg
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Token not found"
            )  # Don't expose that the user does not have access to token
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.msg)
        return

    @router.delete("", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_by_name(
        user: Annotated[User, Depends(auth)],
        name: str = Query(..., description="Name of the token to delete"),
    ):
        try:
            remove_token_by_name(UOW, name, user.uid)
        except NotFound:
            # Add logging to log e.msg
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Token not found"
            )  # Don't expose that the user does not have access to token
        return

    return router
