"""FastAPI Dependencies."""

import requests
from attrs import define, field
from functools import wraps

from fastapi import FastAPI, Request, HTTPException, Header, APIRouter, status
from fastapi.responses import RedirectResponse
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.errors import InvalidClaimError, MissingClaimError
from typing import Annotated
from types import MethodType
from authlib.integrations.starlette_client import StarletteOAuth2App, OAuth
from starlette.middleware.sessions import SessionMiddleware
from urllib.parse import unquote

from .models import User, AdminRole, JWTConfig
from .service.uow import BaseUOW
from .services import (
    authenticated,
    create_jwt_from_token,
    get_user,
    authenticate_admin_token,
    NotFound,
)
from .utils import timed_lru_cache
import logging

logger = logging.getLogger(__name__)


@define(frozen=True)
class TokenCredentials:
    """Authenticated token credentials with JWT and token ID."""

    jwt: str
    token_id: str


@define
class TokenAuthenticator:
    """Performs token authentication."""

    UOW: BaseUOW
    jwt_config: JWTConfig

    def __hash__(self):
        return hash(self.__class__.__name__)

    async def __call__(self, x_token: Annotated[str, Header()]) -> TokenCredentials:
        """Performs token authentication and returns jwt and token ID."""
        with self.UOW() as uow:
            if not authenticated(uow, x_token):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Token",
                )
            try:
                # Extract token_id from x_token (format: "token_id.plain_value")
                token_id = x_token.split(".")[0]

                jwt_value = create_jwt_from_token(
                    uow,
                    token_id,
                    self.jwt_config,
                )
            except KeyError:
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR)

            return TokenCredentials(jwt=jwt_value, token_id=token_id)


@define
class AdminTokenAuthenticator:
    """Performs Admin Token Authentication."""

    UOW: BaseUOW

    def __hash__(self):
        return hash(self.__class__.__name__)

    async def __call__(self, x_token: Annotated[str, Header()]) -> str:
        """Performs admin token authentication."""
        with self.UOW() as uow:
            admin_token = authenticate_admin_token(uow, x_token)
            if not admin_token:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid Token",
                )
            return admin_token


@define
class AuthenticatorFactoryException(Exception):
    """AuthenticatorFactory base exception."""

    msg: str


@define
class AuthenticatorNotFound(AuthenticatorFactoryException):
    """Authenticator not found exception."""

    pass


@define
class BaseUserAuthDependency:
    UOW: BaseUOW
    config: dict

    def __call__(*args, **kwargs) -> User:
        raise NotImplementedError()

    def setup(self, app: FastAPI) -> None:
        """Apply additional setup required for the authenticator to work.

        This hook allows for configuring middleware, routing or exception handlers
        that cannot otherwise be performed on initializing the class.
        """
        pass


@define
class AuthenticatorFactory:
    """Factory for creating Authenticators."""

    authenticators: dict = field()

    @authenticators.default
    def _authenticators(self):
        return {
            "base_auth": BaseUserAuthDependency,
            "authlib_oidc": AuthLibOIDCAuthenticator,
        }

    def make_authenticator(self, uow, config):
        """Initialize authenticator by name."""
        authenticator = config["auth_name"]
        return self.authenticators[authenticator](UOW=uow, config=config[authenticator])


@define
class AuthLibOIDCAuthenticator(BaseUserAuthDependency):
    UOW: BaseUOW
    config: dict
    oauth_client: StarletteOAuth2App = field()
    url: str = field()
    redirect_uri: str = field()

    def __hash__(self):
        return hash(self.__class__.__name__)

    @oauth_client.default
    def _oauth_client(self):
        oauth = OAuth()
        oauth.register(
            name=self.config["strategy_name"],
            client_id=self.config["client_id"],
            client_secret=self.config["client_secret"],
            server_metadata_url=self.config["discovery_url"],
            client_kwargs=self.config.get(
                "client_kwargs",
                {"scope": "openid email profile"},
            ),
        )
        return oauth.create_client(self.config["strategy_name"])

    @url.default
    def _url(self):
        return self.config["url"]

    @redirect_uri.default
    def _redirect_uri(self):
        return f"{self.url}{self.config['redirect_uri']}"

    async def __call__(self, request: Request) -> User:
        session_user = request.session.get("user")
        x_target = request.headers.get("X-Target", "")
        next_url = ""
        if x_target:
            next_url = x_target
        else:
            path = request.scope["route"].path
            next_url = f"{self.url}{path}"

        if not session_user:
            raise HTTPException(
                status_code=status.HTTP_307_TEMPORARY_REDIRECT,
                headers={"Location": f"{self.url}/auth/login?next={next_url}"},
            )
        with self.UOW() as uow:
            try:
                return get_user(uow, session_user["sub"])
            except NotFound as e:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=e,
                )

    def make_router(self) -> APIRouter:
        router = APIRouter(
            prefix="/auth",
            tags=["auth"],
        )

        @router.get("/login")
        async def login(request: Request):
            next_url = request.query_params.get("next", "/")
            # Store "next" in the session so it's available after the callback
            request.session["next"] = unquote(next_url)
            return await self.oauth_client.authorize_redirect(
                request, self.redirect_uri
            )

        @router.get("/callback", status_code=status.HTTP_200_OK)
        async def auth_callback(request: Request):
            token = await self.oauth_client.authorize_access_token(request)
            user_info = token["userinfo"]
            request.session["user"] = dict(user_info)
            next_url = request.session.pop("next", "/")
            return RedirectResponse(url=next_url)

        return router

    def setup(self, app: FastAPI) -> None:
        # only OIDC needs session-based state
        session_config = self.config.get("session_config", {})
        if session_config:
            app.add_middleware(SessionMiddleware, **session_config)

        auth_router = self.make_router()
        if auth_router:
            app.include_router(auth_router)


def require_admin(user_auth: BaseUserAuthDependency) -> User:
    @wraps(user_auth)
    async def wrapper(*args, **kwargs) -> User:
        user = await user_auth(*args, **kwargs)
        if not user.is_admin:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        return user

    return wrapper


def require_admin_impersonation_role(admin_token_auth: AdminTokenAuthenticator):
    @wraps(admin_token_auth)
    async def wrapper(*args, **kwargs):
        admin_token = await admin_token_auth(*args, **kwargs)
        if admin_token.role not in (AdminRole.IMPERSONATION, AdminRole.ANY):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return wrapper


def require_admin_identity_role(admin_token_auth: AdminTokenAuthenticator):
    @wraps(admin_token_auth)
    async def wrapper(*args, **kwargs):
        admin_token = await admin_token_auth(*args, **kwargs)
        if admin_token.role not in (AdminRole.IDENTITY, AdminRole.ANY):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)

    return wrapper


@define(slots=False)
class JWTAuthenticator:
    config: dict
    UOW: BaseUOW
    jwks_url: str = field()
    jwks_cache_ttl: int = field()
    leeway: int = field()
    claims_registry: jwt.JWTClaimsRegistry = field()

    def __hash__(self):
        return hash(self.__class__.__name__)

    @jwks_url.default
    def _jwks_url(self):
        return self.config["jwks_url"]

    @jwks_cache_ttl.default
    def _jwks_cache_ttl(self):
        """Cache lifetime in seconds."""

        return self.config.get("jwks_cache_ttl", 300)

    @leeway.default
    def _leeway(self):
        return self.config.get("leeway", 43_200)

    @claims_registry.default
    def _claims_registry(self):
        return jwt.JWTClaimsRegistry(
            sub={"essential": True},
            leeway=self.leeway,
        )

    def __attrs_post_init__(self):
        """Attrs post init.

        Wrap the existing get_jwks method in a timed cache
        """

        wrapped = MethodType(
            timed_lru_cache(self.jwks_cache_ttl)(JWTAuthenticator.get_jwks), self
        )
        object.__setattr__(self, "get_jwks", wrapped)

    def get_jwks(self) -> KeySet:
        # TODO make timeout configurable
        resp = requests.get(f"{self.jwks_url}", timeout=5)
        try:
            resp.raise_for_status()
        except requests.exceptions.HTTPException:
            logger.error(f"Failed fetching jwks.json from {self.jwks_url}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return KeySet.import_key_set(resp.json())

    async def __call__(
        self, x_auth_request_access_token: Annotated[str, Header()]
    ) -> User:
        """Performs jwt authentication."""

        token = jwt.decode(x_auth_request_access_token, self.get_jwks())

        try:
            self.claims_registry.validate(token.claims)
        except InvalidClaimError as e:
            logger.error(f"Invalid claim: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except MissingClaimError as e:
            logger.error(f"Missing claim: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        with self.UOW() as uow:
            try:
                return get_user(uow, token.claims["sub"])
            except NotFound:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
