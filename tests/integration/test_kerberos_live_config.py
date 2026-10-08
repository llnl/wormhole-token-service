"""Validate the live `TEST.KERBEROS` configuration against a real KDC.

Checks value formats, and that the configured files, keytabs and KDC are
usable; `test_kerberos.py` covers the endpoint itself. Skips unless
`TEST.KERBEROS.mode` is "live" (see docker/krb5/README.md).

Keytab and KDC checks shell out to `klist`/`kinit` rather than using
in-process GSSAPI, which caches keytab and config resolution process-wide.
"""

import os
import re
import socket
import subprocess

import pytest

from token_service.config import settings
from token_service.auth.kerberos import gss_name
from .krb5_harness import mit_krb5_bin_dirs, resolve_config, split_spn

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def cfg():
    """The resolved TEST.KERBEROS block, or skip if we are not in live mode."""

    resolved = resolve_config(settings)
    if resolved.mode != "live":
        pytest.skip(
            f"TEST.KERBEROS.mode is {resolved.mode!r}; this module validates "
            "live-realm configuration. Set mode='live' (or "
            "DYNACONF_TEST__KERBEROS__mode=live) with the KDC running."
        )
    return resolved


@pytest.fixture(scope="module")
def krb_env(cfg):
    """An environment pointing the krb5 CLI at the configured realm."""

    env = dict(os.environ)
    if cfg.krb5_config:
        env["KRB5_CONFIG"] = cfg.krb5_config
    bin_dirs = mit_krb5_bin_dirs()
    if bin_dirs:
        env["PATH"] = os.pathsep.join([*bin_dirs, env.get("PATH", "")])
    return env


def _tool(name, env):
    """Locate an MIT krb5 CLI tool, skipping if it is not installed."""

    import shutil

    path = shutil.which(name, path=env.get("PATH"))
    if path is None:
        pytest.skip(f"{name} not found on PATH; install MIT krb5")
    return path


def _keytab_principals(keytab, env):
    """Principals held in a keytab, via `klist -k`."""

    out = subprocess.run(
        [_tool("klist", env), "-k", keytab], capture_output=True, text=True, env=env
    )
    assert out.returncode == 0, (
        f"could not read keytab {keytab}: {(out.stderr or out.stdout).strip()}"
    )
    found = set()
    for line in out.stdout.splitlines():
        parts = line.split()
        # "KVNO Principal" rows only; skip the header and separator.
        if len(parts) >= 2 and parts[0].isdigit():
            found.add(parts[1])
    return found


# --- value format (no KDC needed) --------------------------------------------


def test_service_name_is_set(cfg):
    assert cfg.service_name, (
        "TEST.KERBEROS.service_name is empty; live mode needs the acceptor SPN, "
        "e.g. 'HTTP/localhost@WORMHOLE.TEST'"
    )


def test_service_name_is_a_recognised_spn_form(cfg):
    """Either 'SERVICE/host@REALM' or 'SERVICE@host'. Anything else is a typo."""

    hostname, is_principal = split_spn(cfg.service_name)

    assert hostname, (
        f"TEST.KERBEROS.service_name={cfg.service_name!r} has no hostname. "
        "Expected 'HTTP/<fqdn>@REALM' or 'HTTP@<fqdn>'."
    )
    if is_principal:
        assert "@" in cfg.service_name, (
            f"TEST.KERBEROS.service_name={cfg.service_name!r} uses the principal "
            "form but names no realm; expected 'HTTP/<fqdn>@REALM'."
        )


def test_service_name_realm_is_uppercase(cfg):
    """Realms are conventionally uppercase and are compared literally."""

    _, is_principal = split_spn(cfg.service_name)
    if not is_principal:
        pytest.skip("host-based form carries no realm")

    realm = cfg.service_name.rsplit("@", 1)[-1]
    assert realm == realm.upper(), (
        f"realm {realm!r} in TEST.KERBEROS.service_name is not uppercase; "
        "realm comparison is exact, so case matters"
    )


def test_client_principal_names_a_realm(cfg):
    if not cfg.client_principal:
        pytest.skip("no client_principal: ambient ccache mode")

    assert re.fullmatch(r"[^@\s]+@[^@\s]+", cfg.client_principal), (
        f"TEST.KERBEROS.client_principal={cfg.client_principal!r} should be "
        "'name@REALM'"
    )


def test_client_keytab_and_principal_are_set_together(cfg):
    """A keytab with no principal gives kinit nothing to request."""

    if cfg.client_keytab:
        assert cfg.client_principal, (
            "TEST.KERBEROS.client_keytab is set but client_principal is not; "
            "kinit -kt needs a principal"
        )


@pytest.mark.parametrize("key", ["keytab", "krb5_config", "client_keytab"])
def test_configured_paths_are_absolute_and_expanded(cfg, key):
    """`$HOME`/`~` must have been expanded, and a relative path is a mistake."""

    value = getattr(cfg, key)
    if not value:
        pytest.skip(f"{key} not set")

    assert "$" not in value, (
        f"TEST.KERBEROS.{key}={value!r} still contains an unexpanded variable; "
        "is it set in this environment?"
    )
    assert os.path.isabs(value), (
        f"TEST.KERBEROS.{key}={value!r} is not absolute; the krb5 library "
        "resolves it relative to the process working directory"
    )


def test_allowed_realms_entries_are_well_formed(cfg):
    for realm in cfg.allowed_realms:
        assert realm == realm.strip(), f"allowed_realms entry {realm!r} has whitespace"
        assert "@" not in realm, (
            f"allowed_realms entry {realm!r} looks like a principal; "
            "it should be a bare realm name"
        )


# --- configured resources exist and are usable ------------------------------


@pytest.mark.parametrize("key", ["keytab", "krb5_config", "client_keytab"])
def test_configured_files_are_readable(cfg, key):
    value = getattr(cfg, key)
    if not value:
        pytest.skip(f"{key} not set")

    assert os.path.isfile(value), f"TEST.KERBEROS.{key} does not exist: {value}"
    assert os.access(value, os.R_OK), (
        f"TEST.KERBEROS.{key} is not readable by this user: {value}"
    )
    assert os.path.getsize(value) > 0, f"TEST.KERBEROS.{key} is empty: {value}"


@pytest.mark.parametrize("key", ["keytab", "client_keytab"])
def test_keytabs_are_not_writable_by_others(cfg, key):
    """A keytab is a private key. World-writable means anyone can replace it."""

    value = getattr(cfg, key)
    if not value:
        pytest.skip(f"{key} not set")

    mode = os.stat(value).st_mode
    assert not mode & 0o022, (
        f"TEST.KERBEROS.{key} is group- or world-writable ({oct(mode & 0o777)}): "
        f"{value}"
    )


def test_acceptor_keytab_contains_the_configured_spn(cfg, krb_env):
    """The keytab must hold the configured `service_name`, or acquisition fails."""

    principals = _keytab_principals(cfg.keytab, krb_env)
    spn = cfg.service_name
    # klist prints fully-qualified principals; a host-based service_name
    # ("HTTP@host") is not what appears there, so compare on the service and
    # hostname rather than the raw string.
    hostname, is_principal = split_spn(spn)
    service = (
        spn.split("@", 1)[0].split("/", 1)[0] if is_principal else spn.split("@")[0]
    )
    expected_prefix = f"{service}/{hostname}"

    assert any(p.startswith(expected_prefix) for p in principals), (
        f"TEST.KERBEROS.keytab ({cfg.keytab}) holds {sorted(principals)}, none "
        f"matching the configured service_name {spn!r}. The SPN and the keytab "
        "must name the same principal."
    )


def test_client_keytab_contains_the_configured_principal(cfg, krb_env):
    if not cfg.client_keytab:
        pytest.skip("no client_keytab: ambient ccache mode")

    principals = _keytab_principals(cfg.client_keytab, krb_env)
    expected = cfg.client_principal.split("@", 1)[0]

    assert any(p.startswith(expected) for p in principals), (
        f"TEST.KERBEROS.client_keytab ({cfg.client_keytab}) holds "
        f"{sorted(principals)}, none matching client_principal "
        f"{cfg.client_principal!r}"
    )


def test_krb5_config_declares_the_configured_realm(cfg):
    """A krb5.conf with no entry for the realm cannot locate the KDC."""

    if not cfg.krb5_config:
        pytest.skip("krb5_config not set; the system /etc/krb5.conf is used")

    text = open(cfg.krb5_config).read()
    realms = set(cfg.allowed_realms)
    _, is_principal = split_spn(cfg.service_name)
    if is_principal:
        realms.add(cfg.service_name.rsplit("@", 1)[-1])

    for realm in realms:
        assert realm in text, (
            f"realm {realm!r} does not appear in {cfg.krb5_config}; the client "
            "will not know which KDC to ask"
        )


# --- the KDC is actually reachable ------------------------------------------


def _kdc_endpoints(krb5_config):
    """KDC host/port pairs declared in a krb5.conf."""

    found = []
    for line in open(krb5_config):
        match = re.match(r"\s*kdc\s*=\s*(\S+)", line)
        if match:
            host, _, port = match.group(1).partition(":")
            found.append((host, int(port) if port else 88))
    return found


def test_krb5_config_declares_at_least_one_kdc(cfg):
    if not cfg.krb5_config:
        pytest.skip("krb5_config not set")

    assert _kdc_endpoints(cfg.krb5_config), (
        f"no `kdc = ` entry in {cfg.krb5_config}. Either add one or enable SRV "
        "discovery with dns_lookup_kdc = true."
    )


def test_kdc_is_reachable_over_tcp(cfg):
    if not cfg.krb5_config:
        pytest.skip("krb5_config not set")

    for host, port in _kdc_endpoints(cfg.krb5_config):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            assert sock.connect_ex((host, port)) == 0, (
                f"cannot reach KDC {host}:{port}/tcp declared in "
                f"{cfg.krb5_config}. Is the container running, and is the port "
                "published?"
            )


def test_client_credentials_obtain_a_ticket(cfg, krb_env, tmp_path):
    """`kinit` with the client keytab obtains a ticket from the configured realm."""

    if not cfg.client_keytab:
        pytest.skip("no client_keytab: ambient ccache mode")

    env = dict(krb_env)
    # A temp cache, so a developer's own ticket is never touched or destroyed.
    env["KRB5CCNAME"] = f"FILE:{tmp_path / 'ccache'}"

    result = subprocess.run(
        [_tool("kinit", env), "-kt", cfg.client_keytab, cfg.client_principal],
        capture_output=True,
        text=True,
        env=env,
    )

    assert result.returncode == 0, (
        f"kinit -kt {cfg.client_keytab} {cfg.client_principal} failed: "
        f"{(result.stderr or result.stdout).strip()}"
    )

    listed = subprocess.run(
        [_tool("klist", env)], capture_output=True, text=True, env=env
    )
    assert cfg.client_principal in listed.stdout, (
        f"kinit reported success but the cache holds no ticket for "
        f"{cfg.client_principal}: {listed.stdout}"
    )


def test_acceptor_credential_can_be_acquired(cfg, krb5_env, service_name):
    """The service can acquire a credential as the configured SPN."""

    import gssapi

    try:
        creds = gssapi.Credentials(usage="accept", name=service_name)
    except gssapi.exceptions.GSSError as error:
        pytest.fail(
            f"could not acquire an acceptor credential for "
            f"{cfg.service_name!r} from {cfg.keytab}: {error}"
        )

    assert creds is not None


def test_a_full_handshake_completes_against_the_configured_realm(cfg, service_name):
    """A client ticket is accepted by the server: the configuration works end to end."""

    import gssapi

    client_ctx = gssapi.SecurityContext(
        name=gss_name(cfg.service_name), usage="initiate"
    )
    token = client_ctx.step()

    server_ctx = gssapi.SecurityContext(
        creds=gssapi.Credentials(usage="accept", name=service_name)
    )
    server_ctx.step(token)

    assert server_ctx.complete, (
        "handshake did not complete against the configured realm"
    )
    assert str(server_ctx.initiator_name).endswith(
        f"@{cfg.service_name.rsplit('@', 1)[-1]}" if "@" in cfg.service_name else ""
    )
