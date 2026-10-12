from fastapi import APIRouter, Depends, status

from ..dependencies import BaseUserAuthDependency
from ..pydantic_models import ConfigResponse, TokenConfigResponse


def make_router(auth: BaseUserAuthDependency, config: dict):
    router = APIRouter(
        prefix="/config",
        tags=["config"],
    )

    # Settings are fixed for the life of the process, so build the response once
    config_response = ConfigResponse(
        token=TokenConfigResponse(
            max_lifetime_days=config["TOKEN"]["max_lifetime_days"],
        ),
    )

    @router.get(
        "",
        status_code=status.HTTP_200_OK,
        dependencies=[Depends(auth)],
    )
    async def get_config() -> ConfigResponse:
        """Get the service settings exposed to clients."""

        return config_response

    return router
