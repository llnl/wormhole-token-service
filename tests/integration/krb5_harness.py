"""Kerberos test harness: k5test and live environments for the Kerberos tests.

`TEST.KERBEROS` comes from `tests/config/test_settings.toml`.
"""

__all__ = [
    "Krb5Env",
    "initiate",
    "k5test_env",
    "live_env",
    "load_test_config",
    "negotiate_header",
]

import base64
import os
import random
import shutil
import subprocess
from dataclasses import dataclass
from unittest import mock

import pytest

from token_service.auth.kerberos import KerberosConfig, as_realm_tuple
from token_service.utils import expand_path
from token_service.config import settings

# k5test drives the MIT krb5 CLI (krb5kdc, kdb5_util, kadmin.local). macOS
# ships Heimdal, whose binaries are either absent or not interchangeable, so
# the MIT ones must be found and put ahead of the system versions on PATH.
# Homebrew installs krb5 keg-only, which is why it is not there already.
MIT_KRB5_PREFIXES = (
    "/opt/homebrew/opt/krb5",  # Homebrew, Apple silicon
    "/usr/local/opt/krb5",  # Homebrew, Intel
    "/usr",  # Linux distro packages
)


@dataclass(frozen=True)
class Krb5TestConfig:
    """Resolved TEST.KERBEROS settings."""

    mode: str
    service_name: str | None
    keytab: str
    krb5_config: str
    client_principal: str | None
    client_keytab: str
    allowed_realms: tuple[str, ...]


@dataclass(frozen=True)
class Krb5Env:
    realm: str
    user_princ: str
    service_name: str

    @property
    def uid(self) -> str:
        """The uid `user_princ` maps onto, i.e. the realm stripped off."""

        return self.user_princ.rsplit("@", 1)[0]


def mit_krb5_bin_dirs() -> list[str] | None:
    """Return bin/sbin dirs of an MIT krb5 install, or None if there isn't one."""

    for prefix in MIT_KRB5_PREFIXES:
        bin_dir, sbin_dir = f"{prefix}/bin", f"{prefix}/sbin"
        krb5kdc = shutil.which("krb5kdc", path=sbin_dir)
        krb5_config = shutil.which("krb5-config", path=bin_dir)
        if not (krb5kdc and krb5_config):
            continue
        # Heimdal ships a krb5-config too, so check the vendor before trusting it.
        version = subprocess.run(
            [krb5_config, "--version"], capture_output=True, text=True
        ).stdout
        if "Kerberos 5" in version:
            return [bin_dir, sbin_dir]
    return None


def unresolved_vars(path: str) -> bool:
    """True if a path still holds an unexpanded `$VAR` after expansion."""

    return "$" in path


def load_test_config() -> Krb5TestConfig:
    kerberos = settings.TEST.KERBEROS
    return Krb5TestConfig(
        mode=str(kerberos.mode).lower(),
        service_name=kerberos.service_name or None,
        keytab=expand_path(kerberos.keytab),
        krb5_config=expand_path(kerberos.krb5_config),
        client_principal=kerberos.client_principal or None,
        client_keytab=expand_path(kerberos.client_keytab),
        allowed_realms=as_realm_tuple(kerberos.allowed_realms),
    )


def k5test_env():
    """A single-realm MIT KDC, booted once per session by `krb5_env`.

    `k5test` writes a krb5.conf, boots a KDC on a loopback port and hands
    back the env vars (KRB5_CONFIG, KRB5CCNAME, KRB5_KTNAME, ...) that point
    the GSSAPI library at it. The realm seeds a `user` principal with a
    ready credential cache, so the client side needs no explicit kinit.
    """

    bin_dirs = mit_krb5_bin_dirs()
    if bin_dirs is None:
        pytest.skip("MIT krb5 not found. Install MIT krb5.")

    from k5test.realm import K5Realm

    with mock.patch.dict(os.environ):
        os.environ["PATH"] = os.pathsep.join([*bin_dirs, os.environ["PATH"]])
        realm = K5Realm(
            krb5_conf={"libdefaults": {"rdns": "false"}},
            # Randomised so parallel runs do not fight over KDC ports.
            portbase=random.randint(2000, 6000) * 10,
        )
        os.environ.update(realm.env)

        # K5Realm provisions host/<hostname> into the default keytab during
        # setup, so it is usable as an acceptor credential with no extra work.
        yield Krb5Env(
            realm=realm.realm,
            user_princ=realm.user_princ,
            service_name=f"host/{realm.hostname}",
        )
    realm.stop()


def live_env(cfg: Krb5TestConfig, tmp_path_factory):
    """Point the GSSAPI library at a real realm.

    Raises:
        pytest.skip.Exception: If a required setting or file is missing or
            unreadable.
    """

    if not cfg.service_name:
        pytest.skip(
            "live mode needs TEST.KERBEROS.service_name "
            "(e.g. DYNACONF_TEST__KERBEROS__service_name=HTTP/tokens.example.gov@REALM)"
        )
    if not cfg.keytab:
        pytest.skip(
            "live mode needs TEST.KERBEROS.keytab -- the acceptor keytab for "
            f"{cfg.service_name}"
        )
    for label, path in (
        ("acceptor keytab (TEST.KERBEROS.keytab)", cfg.keytab),
        ("krb5.conf (TEST.KERBEROS.krb5_config)", cfg.krb5_config),
        ("client keytab (TEST.KERBEROS.client_keytab)", cfg.client_keytab),
    ):
        if not path:
            continue
        if unresolved_vars(path):
            pytest.skip(
                f"{label} still contains an unexpanded variable after "
                f"expansion. Is it set in this environment? {path}"
            )
        if not os.access(path, os.R_OK):
            pytest.skip(f"{label} is not readable: {path}")
    if not (cfg.client_keytab and cfg.client_principal):
        pytest.skip(
            "live mode needs TEST.KERBEROS.client_keytab and client_principal "
            "(the test client runs `kinit -kt`)"
        )

    # Restores os.environ on exit, including apply_to_environment's direct writes.
    with mock.patch.dict(os.environ):
        # Prefer MIT's kinit when present so the CLI and the KDC agree; unlike
        # k5test, live mode doesn't require it.
        bin_dirs = mit_krb5_bin_dirs()
        if bin_dirs:
            os.environ["PATH"] = os.pathsep.join([*bin_dirs, os.environ["PATH"]])

        KerberosConfig(
            keytab=cfg.keytab, krb5_config=cfg.krb5_config
        ).apply_to_environment()

        kinit = shutil.which("kinit")
        if kinit is None:
            pytest.skip("live mode needs `kinit` on PATH to use a client keytab")

        # Never kinit into the developer's own cache: that silently overwrites
        # whatever ticket they were using.
        ccache_path = tmp_path_factory.mktemp("krb5cc") / "ccache"
        os.environ["KRB5CCNAME"] = f"FILE:{ccache_path}"
        try:
            result = subprocess.run(
                [kinit, "-kt", cfg.client_keytab, cfg.client_principal],
                capture_output=True,
                text=True,
                env=os.environ,
            )
            if result.returncode != 0:
                pytest.skip(
                    f"kinit -kt {cfg.client_keytab} {cfg.client_principal} "
                    f"failed: {(result.stderr or result.stdout).strip()}"
                )
            yield Krb5Env(
                realm=cfg.client_principal.rsplit("@", 1)[-1],
                user_princ=cfg.client_principal,
                service_name=cfg.service_name,
            )
        finally:
            # The cache is the file, so removing it destroys the tickets.
            ccache_path.unlink(missing_ok=True)


def initiate(service_name) -> tuple[object, bytes]:
    """Start a client-side context and return it with its first output token."""

    import gssapi

    ctx = gssapi.SecurityContext(name=service_name, usage="initiate")
    token = ctx.step()
    assert token is not None, "the first initiator step always yields a token"

    return ctx, token


def negotiate_header(token: bytes) -> str:
    return f"Negotiate {base64.b64encode(token).decode()}"
