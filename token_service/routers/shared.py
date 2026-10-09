from fastapi import HTTPException
from starlette import status

import logging
from .. import adapter
from ..models import User
from ..pydantic_models import Token as PydanticToken
from ..service.uow import BaseUOW
from ..services import create_token, AlreadyExists, NotFound, ServiceException


logger = logging.getLogger(__name__)


async def create_token_for_user(
    UOW: BaseUOW,
    user: User,
    token_data: PydanticToken,
) -> str:
    """Create a token for `user`, mapping service errors onto HTTP ones."""

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
        logger.exception("failed creating token")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
        )
