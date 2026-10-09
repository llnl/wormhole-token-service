"""Kerberos (SPNEGO/GSSAPI) authentication.

Reads the kerberos configuration, acquires an acceptor credential,
drives the GSSAPI handshake and decides which authenticated principal
is allowed to become which local uid.

`gssapi` is imported lazily throughout, so this module stays importable --
and `KerberosConfig` stays testable -- without the optional `kerberos`
extra installed.
"""

import logging
import os

from attrs import define, field

from ..utils import expand_path

logger = logging.getLogger(__name__)


class KerberosAuthError(Exception):
    """The caller did not prove an acceptable identity.

    Every rejection raises this. A mech-level failure, an unparseable
    principal, a realm outside the allow-list and an instance principal
    are the same answer to the caller ("authenticate again"). Callers must
    not echo `args` back to the client, since the mech detail is
    diagnostic, not public.
    """


class KerberosConfigError(ValueError):
    """`AUTH.kerberos` is configured in a way the service refuses to run with.

    Raised while the app is being built, so a bad configuration stops startup
    instead of surfacing as rejected logins later.
    """


def gss_name(service_name: str):
    """Build a `gssapi.Name`, choosing the name type from the spelling.

    - `HTTP/tokens.example.gov@REALM` -- a Kerberos principal. The `@`
      separates the realm.
    - `HTTP@tokens.example.gov` -- a host-based service. The `@` separates
      the hostname.

    The discriminator is whether the part before the first `@` contains a
    `/`: only the principal form does.
    """

    import gssapi
    from gssapi import raw as gb

    local = service_name.split("@", 1)[0]
    name_type = (
        gb.NameType.kerberos_principal
        if "/" in local
        else gb.NameType.hostbased_service
    )
    return gssapi.Name(service_name, name_type)


def as_realm_tuple(value) -> tuple[str, ...]:
    if not value:
        return ()
    if isinstance(value, str):
        return tuple(item.strip() for item in value.split(",") if item.strip())
    return tuple(str(item) for item in value)


@define(frozen=True)
class KerberosConfig:
    """The resolved, normalized contents of `AUTH.kerberos`."""

    CONSUMED_CONFIG_KEYS = frozenset(
        {"enabled", "service_name", "keytab", "krb5_config", "allowed_realms"}
    )

    service_name: str = ""
    keytab: str = ""
    krb5_config: str = ""
    allowed_realms: tuple[str, ...] = ()

    @classmethod
    def from_mapping(cls, config: dict) -> "KerberosConfig":
        return cls(
            service_name=config.get("service_name", "") or "",
            keytab=expand_path(config.get("keytab")),
            krb5_config=expand_path(config.get("krb5_config")),
            allowed_realms=as_realm_tuple(config.get("allowed_realms")),
        )

    def apply_to_environment(self) -> None:
        """Export both settings to the environment the krb5 library reads.

        Only set when configured: an empty value must not clobber an
        environment that was deliberately set outside the app.
        """

        if self.keytab:
            os.environ["KRB5_KTNAME"] = self.keytab
        if self.krb5_config:
            os.environ["KRB5_CONFIG"] = self.krb5_config


@define(frozen=True)
class AcceptResult:
    """One leg of an accept-side handshake.

    Attributes:
        principal: The initiator's principal, e.g. `alice@EXAMPLE.GOV`. Set
            only when `complete` -- an unfinished context has not proven a
            name yet.
    """

    complete: bool
    token: bytes | None = None
    principal: str | None = None


@define(slots=False)
class KerberosAcceptor:
    """Accept side of a GSSAPI exchange, plus the principal-to-uid policy.

    Long-lived: one per application, holding the acceptor credential. The
    per-request `SecurityContext` is built inside `step`.
    """

    config: KerberosConfig = field()

    def __attrs_post_init__(self):
        object.__setattr__(self, "_creds", None)

        # Exactly one realm, for now. More than one is refused because
        # `principal_to_uid` strips the realm, so `alice@A` and `alice@B`
        # would become the same uid. `allowed_realms` stays a list so
        # multiple realms can be supported later, once principals are mapped
        # to users without that collision.
        realms = self.config.allowed_realms
        if len(realms) != 1:
            raise KerberosConfigError(
                "allowed_realms must name exactly one realm, "
                f"got {len(realms)}: {list(realms)}. multiple realms "
                "currently  not supported "
            )

    @property
    def creds(self):
        """The acceptor credential, built on first use.

        Lazy on purpose: a missing or unreadable keytab must fail this one
        endpoint rather than prevent the whole service from starting.
        """

        import gssapi

        if self._creds is None:
            service_name = self.config.service_name
            name = gss_name(service_name) if service_name else None
            object.__setattr__(
                self, "_creds", gssapi.Credentials(usage="accept", name=name)
            )
        return self._creds

    def step(self, client_token: bytes) -> AcceptResult:
        """Advance the handshake by one leg.

        Returns:
            The `AcceptResult`: incomplete with a continuation token if the
            mechanism wants another round, otherwise complete with the
            initiator's principal.

        Raises:
            KerberosAuthError: If the mechanism rejects the token.
        """

        import gssapi

        ctx = gssapi.SecurityContext(creds=self.creds)
        try:
            server_token = ctx.step(client_token)
        except gssapi.exceptions.GSSError as e:
            logger.warning(f"GSSAPI handshake failed: {e}")
            raise KerberosAuthError("handshake failed") from e

        if not ctx.complete:
            return AcceptResult(complete=False, token=server_token)

        return AcceptResult(
            complete=True,
            token=server_token,
            principal=str(ctx.initiator_name),
        )

    def principal_to_uid(self, principal: str) -> str:
        """Map a completed handshake's initiator name onto a `User.uid`."""

        local, sep, realm = principal.rpartition("@")
        if not sep:
            logger.warning(f"Kerberos principal has no realm: {principal!r}")
            raise KerberosAuthError("principal has no realm")

        if realm not in self.config.allowed_realms:
            logger.warning(
                f"Kerberos realm {realm!r} is not in allowed_realms "
                f"{list(self.config.allowed_realms)}; rejecting {principal!r}"
            )
            raise KerberosAuthError("realm not allowed")

        if "/" in local:
            logger.warning(
                f"Rejecting instance principal {principal!r}: only bare "
                "user principals may authenticate"
            )
            raise KerberosAuthError("instance principal")

        return local


__all__ = [
    "AcceptResult",
    "KerberosAcceptor",
    "KerberosAuthError",
    "KerberosConfig",
    "KerberosConfigError",
    "as_realm_tuple",
    "gss_name",
]
