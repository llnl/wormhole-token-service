import pendulum
from fastapi import APIRouter, Depends, status
from typing import Annotated

from ..dependencies import BaseUserAuthDependency
from ..models import User, Token, JWTConfig
from ..pydantic_models import JWTResponse
from ..service.uow import BaseUOW
from ..services import update_session, create_jwt_from_user


def make_router(
    UOW: BaseUOW,
    auth: BaseUserAuthDependency,
    jwt_config: JWTConfig,
    token_config: dict,
):
    router = APIRouter(
        prefix="/mfa",
        tags=["mfa"],
    )

    session_name = token_config["session_name"]
    session_lifetime_seconds = token_config["session_lifetime_seconds"]

    @router.get("/jwt", status_code=status.HTTP_200_OK, response_model=JWTResponse)
    async def jwt(user: Annotated[User, Depends(auth)]) -> JWTResponse:
        """Get a jwt for the user that authenticated via MFA and start a session.

        The session in this case is a special token roughly linked to an auth
        session. This session token is then used to generate subtokens that
        are linked to the lifetime of the auth session.

        The lifetime of this session token remains set from its initialization.
        If the session is expired when this API is called, it is refreshed.
        """

        now = pendulum.now()
        token = Token(
            name=session_name,
            user_uid=user.uid,
            iat=now,
            nbf=now,
            exp=now.add(seconds=session_lifetime_seconds),
            session=True,
        )
        token = update_session(UOW, user, token)

        return JWTResponse(
            jwt=create_jwt_from_user(
                UOW,
                user,
                token.id,
                jwt_config,
            )
        )

    return router
