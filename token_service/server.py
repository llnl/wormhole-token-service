from attrs import define, field
import json
import uvicorn
from pathlib import Path
from fastapi_offline import FastAPIOffline
from fastapi import APIRouter
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi

from token_service import __version__
from .dependencies import (
    AuthenticatorFactory,
    JWTAuthenticator,
    TokenAuthenticator,
    AdminTokenAuthenticator,
)

from .models import JWTConfig
from .routers.tokens import make_router as make_token_router
from .internal.tokens import make_router as make_admin_token_router
from .internal.users import make_router as make_admin_user_router
from .internal.groups import make_router as make_admin_group_router
from .routers.well_known import make_router as make_well_known_router
from .routers.mfa import make_router as make_mfa_router
from .store.orm import make_engine
from .service.uow import make_sql_uow


@define
class Endpoint:
    current_version: str
    router: APIRouter
    public: bool = field(default=True)
    prefix: str = field(default="/api")
    versions: list = field(factory=lambda: ["stable", "latest"])


def bind_endpoint(app, endpoint, prefix, tags):
    app.include_router(
        endpoint.router, include_in_schema=endpoint.public, prefix=prefix, tags=tags
    )


def bind_endpoints(app, endpoints):
    for ep in endpoints:
        # Only apply versioning to routes with defined versions
        if ep.versions:
            for version in ep.versions:
                if version == "stable":
                    prefix = f"{ep.prefix}/{ep.current_version}"
                    tags = [ep.current_version]
                else:
                    prefix = f"{ep.prefix}/{version}"
                    tags = [version]

                bind_endpoint(app, ep, prefix, tags)
        else:
            bind_endpoint(app, ep, "", [])


def make_app(config: dict) -> FastAPIOffline:
    # set up uow
    engine = make_engine(config.get("DB"))
    UOW = make_sql_uow(engine)

    # init deps
    auth_config = config.get("AUTH", {})
    token_config = config.get("TOKEN")
    authenticator_factory = AuthenticatorFactory()
    auth = authenticator_factory.make_authenticator(UOW, auth_config)
    jwt_config = JWTConfig(auth_config["jwt"])
    token_auth = TokenAuthenticator(UOW, jwt_config)
    oauth_jwt_config = auth_config["oauth_jwt"]
    jwt_auth = JWTAuthenticator(oauth_jwt_config, UOW)
    admin_token_auth = AdminTokenAuthenticator(UOW)

    root_path = config.get("ROOT_PATH", "")
    app = FastAPIOffline(root_path=root_path)

    # import routers
    api_version = config["API_VERSION"]
    endpoints = [
        Endpoint(
            api_version, make_admin_user_router(UOW, auth, admin_token_auth), False
        ),
        Endpoint(api_version, make_admin_group_router(UOW, admin_token_auth), False),
        Endpoint(
            api_version, make_admin_token_router(UOW, auth, admin_token_auth), False
        ),
        Endpoint(api_version, make_token_router(UOW, auth, token_auth, token_config)),
        Endpoint(
            api_version, make_well_known_router(jwt_config.jwks), prefix="", versions=[]
        ),
        Endpoint(api_version, make_mfa_router(UOW, jwt_auth, jwt_config, token_config)),
    ]

    bind_endpoints(app, endpoints)

    # Add middleware if needed
    auth.setup(app)

    # Mount UI static asset files at /static
    try:
        app.mount(
            "/static",
            StaticFiles(directory=str(Path(__file__).parent / "static"), html=True),
        )
    except RuntimeError:
        # If static directory is missing in some environments, skip mounting
        pass

    @app.get("/")
    async def root_index():
        index_path = Path(__file__).parent / "static" / "index.html"
        return FileResponse(index_path)

    return app


def make_server(config: dict) -> uvicorn.Server:
    app = make_app(config)
    # TODO: abstract data type for config
    server_config = config.get("SERVER", {})

    uvicorn_config = uvicorn.Config(app, **server_config)
    return uvicorn.Server(uvicorn_config)


def custom_spec_generator(app) -> str:
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Token Service",
        version=__version__,
        summary="OpenAPI Spec for Token Service",
        description="Defines token auth, oidc auth and jwks validation endpoints",
        routes=app.routes,
    )

    return openapi_schema


def generate_openapi_spec(config: dict) -> str:
    app = make_app(config)
    schema = custom_spec_generator(app)

    with open("openapi.json", "w") as fh:
        fh.write(json.dumps(schema, indent=2))
