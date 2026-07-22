from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Annotated

from token_service import adapter
from ..dependencies import (
    BaseUserAuthDependency,
    AdminTokenAuthenticator,
    require_admin,
    require_admin_impersonation_role,
)
from ..pydantic_models import (
    CreateTokenRequest,
    CreateTokenResponse,
    AdminToken as PydanticAdminToken,
)
from ..models import User
from ..service.uow import BaseUOW
from ..services import (
    list_admin_tokens,
    remove_admin_token,
    create_token,
    get_subtoken,
    make_composite_token,
    create_admin_token,
    ServiceException,
    AlreadyExists,
    NotFound,
)


def make_router(
    UOW: BaseUOW,
    user_auth: BaseUserAuthDependency,
    admin_token_auth: AdminTokenAuthenticator,
):
    router = APIRouter(
        prefix="/admin/token",
        tags=["admin-token"],
    )

    @router.post("", status_code=status.HTTP_201_CREATED, response_model=str)
    async def create(
        user: Annotated[User, Depends(require_admin(user_auth))],
        admin_token_data: PydanticAdminToken,
    ) -> str:
        admin_token = adapter.to_admin_token(admin_token_data)
        try:
            return create_admin_token(UOW, admin_token)
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e.msg)
        except ServiceException as e:
            # TODO add logging
            # log.error(f"failed creating admin token: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
            )

    @router.post("/{user_uid}", status_code=status.HTTP_201_CREATED)
    async def create_token_for_user(
        _: Annotated[None, Depends(require_admin_impersonation_role(admin_token_auth))],
        user_uid: str,
        request_data: CreateTokenRequest,
    ) -> CreateTokenResponse:
        token = adapter.to_token(request_data.token)
        token.user_uid = user_uid
        scopes = [_ for _ in request_data.token.scopes or [] if _]
        try:
            token = create_token(
                UOW,
                token,
                scopes,
                parent_id=request_data.parent_id,
                external_id=request_data.external_id,
            )
            return CreateTokenResponse(token=token)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=e.msg)
        except AlreadyExists:
            existing_token = get_subtoken(
                UOW,
                request_data.token.name,
                request_data.parent_id,
                request_data.external_id,
            )

            return CreateTokenResponse(
                token=make_composite_token(existing_token.id, existing_token.value)
            )
        except ServiceException as e:
            # TODO add logging
            # log.error(f"failed creating token for user: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
            )

    @router.get(
        "", status_code=status.HTTP_200_OK, response_model=List[PydanticAdminToken]
    )
    async def list_tokens(
        user: Annotated[User, Depends(require_admin(user_auth))],
    ) -> List[PydanticAdminToken]:
        return [
            adapter.from_admin_token(admin_token)
            for admin_token in list_admin_tokens(UOW)
        ]

    @router.delete("/{admin_token_value}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete_by_value(
        user: Annotated[User, Depends(require_admin(user_auth))],
        admin_token_value: str,
    ):
        try:
            remove_admin_token(UOW, admin_token_value)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST)
        return

    return router
