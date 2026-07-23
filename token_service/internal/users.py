from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Annotated

from token_service import adapter
from ..dependencies import (
    AdminTokenAuthenticator,
    BaseUserAuthDependency,
    require_admin,
    require_admin_identity_role,
)
from ..pydantic_models import User as PydanticUser
from ..models import User
from ..service.uow import BaseUOW
from ..services import (
    create_user,
    remove_user,
    list_all_users,
    add_admin,
    remove_admin,
    ServiceException,
    NotFound,
    AlreadyExists,
)


def make_router(
    UOW: BaseUOW,
    user_auth: BaseUserAuthDependency,
    admin_token_auth: AdminTokenAuthenticator,
):
    router = APIRouter(
        prefix="/admin/users",
        tags=["admin-users"],
    )

    @router.get("", status_code=status.HTTP_200_OK)
    async def list_users(
        _: Annotated[None, Depends(require_admin_identity_role(admin_token_auth))],
    ) -> List[PydanticUser]:
        return [adapter.from_user(user) for user in list_all_users(UOW)]

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def create(
        _: Annotated[None, Depends(require_admin_identity_role(admin_token_auth))],
        user_data: PydanticUser,
    ) -> PydanticUser:
        user = adapter.to_user(user_data)
        try:
            return adapter.from_user(create_user(UOW, user))
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e.msg)
        except ServiceException as e:
            # TODO add logging
            # log.error(f"failed creating user: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
            )

    @router.delete("/{user_uid}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete(
        _: Annotated[None, Depends(require_admin_identity_role(admin_token_auth))],
        user_uid: str,
    ):
        try:
            remove_user(UOW, user_uid)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        return

    @router.put("/{user_uid}/admin", status_code=status.HTTP_204_NO_CONTENT)
    async def grant_admin_role(
        user: Annotated[User, Depends(require_admin(user_auth))], user_uid: str
    ):
        try:
            add_admin(UOW, user_uid)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        return

    @router.delete("/{user_uid}/admin", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_admin_role(
        user: Annotated[User, Depends(require_admin(user_auth))], user_uid: str
    ):
        try:
            remove_admin(UOW, user_uid)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        return

    return router
