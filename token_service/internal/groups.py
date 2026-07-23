from fastapi import APIRouter, Depends, HTTPException, status
from typing import List

from token_service import adapter
from ..dependencies import (
    AdminTokenAuthenticator,
    require_admin_identity_role,
)
from ..pydantic_models import (
    Group as PydanticGroup,
)
from ..service.uow import BaseUOW
from ..services import (
    create_group,
    remove_group,
    list_all_groups,
    add_user_to_group,
    remove_user_from_group,
    ServiceException,
    AlreadyExists,
    NotFound,
)


def make_router(
    UOW: BaseUOW,
    admin_token_auth: AdminTokenAuthenticator,
):
    router = APIRouter(
        prefix="/admin/groups",
        tags=["admin-groups"],
        dependencies=[Depends(require_admin_identity_role(admin_token_auth))],
    )

    @router.get("", status_code=status.HTTP_200_OK)
    async def list_groups() -> List[PydanticGroup]:
        return [adapter.from_group(group) for group in list_all_groups(UOW)]

    @router.post("", status_code=status.HTTP_201_CREATED)
    async def create(group_data: PydanticGroup) -> PydanticGroup:
        group = adapter.to_group(group_data)
        try:
            return create_group(UOW, group)
        except AlreadyExists as e:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=e.msg)
        except ServiceException as e:
            # TODO add logging
            # log.error(f"failed creating group: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=e.msg
            )

    @router.delete("/{group_name}", status_code=status.HTTP_204_NO_CONTENT)
    async def delete(group_name: str):
        try:
            remove_group(UOW, group_name)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)
        return

    @router.post(
        "/{group_name}/members/{user_uid}", status_code=status.HTTP_201_CREATED
    )
    async def add_member(group_name: str, user_uid: str):
        try:
            add_user_to_group(UOW, group_name, user_uid)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)

    @router.delete(
        "/{group_name}/members/{user_uid}", status_code=status.HTTP_204_NO_CONTENT
    )
    async def remove_member(group_name: str, user_uid: str):
        try:
            remove_user_from_group(UOW, group_name, user_uid)
        except NotFound as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=e.msg)

    return router
