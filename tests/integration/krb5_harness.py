"""Kerberos test harness: k5test and live environments for the Kerberos tests.

Defaults live in `KRB5_TEST_DEFAULTS`, not `settings.toml`, so test-only keys
don't ship in the wheel.
"""

import base64
import os
import random
import shutil
import subprocess
from dataclasses import dataclass

import pytest

from token_service.auth.kerberos import KerberosConfig, as_realm_tuple, gss_name
from token_service.utils import expand_path

# k5test drives the MIT krb5 CLI (krb5kdc, kdb5_util, kadmin.local). macOS
# ships Heimdal, whose binaries are either absent or not interchangeable, so
# the MIT ones must be found and put ahead of the system versions on PATH.
# Homebrew installs krb5 keg-only, which is why it is not there already.
MIT_KRB5_PREFIXES = (
    "/opt/homebrew/opt/krb5",  # Homebrew, Apple silicon
    "/usr/local/opt/krb5",  # Homebrew, Intel
    "/usr",  # Linux distro packages
)

KRB5_TEST_DEFAULTS = {
    # "k5test" spins up an ephemeral KDC as a child process of pytest (needs
    # the MIT krb5 tools installed locally, no external realm).
    # "live" targets a real realm using the values below.
    "mode": "k5test",
    "service_name": "",  # e.g. "HTTP/tokens.example.gov@REALM" or "HTTP@tokens.example.gov"
    "keytab": "",  # acceptor keytab -> KRB5_KTNAME
    "krb5_config": "",  # -> KRB5_CONFIG; empty uses the system /etc/krb5.conf
    "client_principal": "",  # e.g. "svc-tokentest@REALM"
    "client_keytab": "",  # kinit -kt source; empty = use ambient ccache
    "allowed_realms": (),
}

# Environment variables the fixtures take over and must hand back untouched.
KRB5_ENV_KEYS = ("KRB5_CONFIG", "KRB5_KTNAME", "KRB5CCNAME")


@dataclass(frozen=True)
class Krb5TestConfig:
    """Resolved TEST.KERBEROS settings."""

    mode: str
    service_name: str
    keytab: str
    krb5_config: str
    client_principal: str
    client_keytab: str
    allowed_realms: tuple[str, ...]

    @property
    def uses_ambient_ccache(self) -> bool:
        """True when `client_keytab` is empty: use the developer's own ticket.

        `KRB5CCNAME` is then left alone rather than redirected at a temp file.
        """

        return not self.client_keytab


@dataclass(frozen=True)
class Krb5Env:
    """The small interface both modes yield, so test bodies do not branch."""

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


def split_spn(spn: str) -> tuple[str, bool]:
    """Return `(hostname, is_principal_form)` for a service name.

    `HTTP/tokens.example.gov@REALM` puts the host after the `/`;
    `HTTP@tokens.example.gov` puts it after the `@`. Only the principal
    form has a `/` before the first `@`.
    """

    local = spn.split("@", 1)[0]
    if "/" in local:
        return local.split("/", 1)[1], True
    _, _, host = spn.partition("@")
    return host, False


def unresolved_vars(path: str) -> bool:
    """True if a path still holds an unexpanded `$VAR` after expansion."""

    return "$" in path


def default_principal_from_ccache(env: dict) -> str | None:
    """Read the default principal out of the ambient credential cache."""

    klist = shutil.which("klist")
    if klist is None:
        return None
    result = subprocess.run([klist], capture_output=True, text=True, env=env)
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        # MIT: "Default principal: alice@REALM"
        # Heimdal: "Principal: alice@REALM"
        if "rincipal:" in line:
            candidate = line.split(":", 1)[1].strip()
            if "@" in candidate:
                return candidate
    return None


def resolve_config(settings) -> Krb5TestConfig:
    """TEST.KERBEROS settings layered over the in-code defaults."""

    raw = settings.get("TEST", {}).get("KERBEROS", {})
    # Dynaconf preserves the case it was given; normalise before merging.
    provided = {str(key).lower(): value for key, value in dict(raw).items()}
    merged = KRB5_TEST_DEFAULTS | provided
    return Krb5TestConfig(
        mode=str(merged["mode"]).lower(),
        service_name=str(merged["service_name"]),
        keytab=expand_path(merged["keytab"]),
        krb5_config=expand_path(merged["krb5_config"]),
        client_principal=str(merged["client_principal"]),
        client_keytab=expand_path(merged["client_keytab"]),
        allowed_realms=as_realm_tuple(merged["allowed_realms"]),
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
            # Reported separately from "not readable": the cause is an unset
            # environment variable, not a missing file, and the two need
            # different fixes.
            pytest.skip(
                f"{label} still contains an unexpanded variable after "
                f"expansion -- is it set in this environment? {path}"
            )
        if not os.access(path, os.R_OK):
            pytest.skip(f"{label} is not readable: {path}")
    if cfg.client_keytab and not cfg.client_principal:
        pytest.skip(
            "TEST.KERBEROS.client_keytab is set but client_principal is not; "
            "kinit -kt needs a principal to request"
        )

    # Prefer MIT's kinit/klist when present so the CLI and the KDC agree, but
    # do not require them: unlike k5test, live mode needs no krb5kdc/kdb5_util.
    original_path = os.environ["PATH"]
    bin_dirs = mit_krb5_bin_dirs()
    if bin_dirs:
        os.environ["PATH"] = os.pathsep.join([*bin_dirs, original_path])

    original_env = {key: os.environ.get(key) for key in KRB5_ENV_KEYS}
    ccache_path = None

    try:
        # The same export the service performs, so the harness cannot drift
        # from it.
        KerberosConfig(
            keytab=cfg.keytab, krb5_config=cfg.krb5_config
        ).apply_to_environment()

        if cfg.uses_ambient_ccache:
            # Deliberately using the developer's own ticket. Leave KRB5CCNAME
            # exactly as it is -- redirecting it here would hide the very
            # credential we were asked to test with.
            user_princ = default_principal_from_ccache(os.environ)
            if user_princ is None:
                pytest.skip(
                    "live mode with no TEST.KERBEROS.client_keytab uses your "
                    "ambient credential cache, but no valid ticket was found. "
                    "Run `kinit` first, or set client_keytab/client_principal "
                    "for an unattended run."
                )
        else:
            kinit = shutil.which("kinit")
            if kinit is None:
                pytest.skip("live mode needs `kinit` on PATH to use a client keytab")
            # Never kinit into the ambient cache: that silently overwrites
            # whatever ticket the developer was using.
            ccache_path = tmp_path_factory.mktemp("krb5cc") / "ccache"
            os.environ["KRB5CCNAME"] = f"FILE:{ccache_path}"
            result = subprocess.run(
                [kinit, "-kt", cfg.client_keytab, cfg.client_principal],
                capture_output=True,
                text=True,
                env=os.environ,
            )
            if result.returncode != 0:
                pytest.skip(
                    f"kinit -kt {cfg.client_keytab} {cfg.client_principal} failed: "
                    f"{(result.stderr or result.stdout).strip()}"
                )
            user_princ = cfg.client_principal

        hostname, _ = split_spn(cfg.service_name)
        yield Krb5Env(
            mode="live",
            realm=user_princ.rsplit("@", 1)[-1],
            user_princ=user_princ,
            hostname=hostname,
            service_name=cfg.service_name,
        )
    finally:
        if ccache_path is not None:
            kdestroy = shutil.which("kdestroy")
            if kdestroy is not None:
                subprocess.run(
                    [kdestroy, "-c", f"FILE:{ccache_path}"],
                    capture_output=True,
                    env=os.environ,
                )
            # kdestroy may be absent or may leave the file behind.
            if os.path.exists(ccache_path):
                os.unlink(ccache_path)
        for key, value in original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        os.environ["PATH"] = original_path


def initiate(service_name) -> tuple[object, bytes]:
    """Start a client-side context and return it with its first output token."""

    import gssapi

    ctx = gssapi.SecurityContext(name=service_name, usage="initiate")
    return ctx, ctx.step()


def negotiate_header(token: bytes) -> str:
    return f"Negotiate {base64.b64encode(token).decode()}"


__all__ = [
    "Krb5Env",
    "Krb5TestConfig",
    "gss_name",
    "initiate",
    "k5test_env",
    "live_env",
    "negotiate_header",
    "resolve_config",
    "split_spn",
    "unresolved_vars",
]
