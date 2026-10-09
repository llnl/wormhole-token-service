"""Kerberos test harness: an ephemeral k5test realm for the Kerberos tests."""

import base64
import os
import random
import shutil
import subprocess
from dataclasses import dataclass

import pytest

from token_service.auth.kerberos import gss_name

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
class Krb5Env:
    """What the `krb5_env` fixture yields."""

    mode: str
    realm: str
    user_princ: str
    hostname: str
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
        # Heimdal ships a krb5-config too, so presence is not enough --
        # confirm the vendor before trusting this prefix.
        version = subprocess.run(
            [krb5_config, "--version"], capture_output=True, text=True
        ).stdout
        if "Kerberos 5" in version:
            return [bin_dir, sbin_dir]
    return None


def k5test_env():
    """A single-realm MIT KDC, booted once per session by `krb5_env`.

    `k5test` writes a krb5.conf, boots a KDC on a loopback port and hands
    back the env vars (KRB5_CONFIG, KRB5CCNAME, KRB5_KTNAME, ...) that point
    the GSSAPI library at it. The realm seeds a `user` principal with a
    ready credential cache, so the client side needs no explicit kinit.
    """

    bin_dirs = mit_krb5_bin_dirs()
    if bin_dirs is None:
        pytest.skip(
            "MIT krb5 not found. macOS ships Heimdal, which k5test cannot "
            "drive -- install MIT krb5 with `brew install krb5`."
        )

    original_path = os.environ["PATH"]
    os.environ["PATH"] = os.pathsep.join([*bin_dirs, original_path])

    from k5test.realm import K5Realm

    realm = K5Realm(
        krb5_conf={"libdefaults": {"rdns": "false"}},
        # Randomised so parallel runs do not fight over KDC ports.
        portbase=random.randint(2000, 6000) * 10,
    )
    original_env = {k: os.environ.get(k) for k in realm.env}
    os.environ.update(realm.env)

    # K5Realm provisions host/<hostname> into the default keytab during setup,
    # so it is usable as an acceptor credential with no extra work.
    yield Krb5Env(
        mode="k5test",
        realm=realm.realm,
        user_princ=realm.user_princ,
        hostname=realm.hostname,
        service_name=f"host/{realm.hostname}",
    )

    for key, value in original_env.items():
        if value is None:
            del os.environ[key]
        else:
            os.environ[key] = value
    os.environ["PATH"] = original_path
    realm.stop()


def initiate(service_name) -> tuple[object, bytes]:
    """Start a client-side context and return it with its first output token."""

    import gssapi

    ctx = gssapi.SecurityContext(name=service_name, usage="initiate")
    return ctx, ctx.step()


def negotiate_header(token: bytes) -> str:
    return f"Negotiate {base64.b64encode(token).decode()}"


__all__ = [
    "Krb5Env",
    "gss_name",
    "initiate",
    "k5test_env",
    "negotiate_header",
]
