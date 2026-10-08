"""Tests for the harness's `live_env` and `resolve_config`; no KDC, no gssapi."""

import os
import subprocess
from unittest import mock

import pytest

from token_service.utils import expand_path
from tests.integration.krb5_harness import Krb5TestConfig, live_env, resolve_config


def make_cfg(**overrides) -> Krb5TestConfig:
    defaults = {
        "mode": "live",
        "service_name": "HTTP/tokens.example.gov@EXAMPLE.GOV",
        "keytab": "",
        "krb5_config": "",
        "client_principal": "",
        "client_keytab": "",
        "allowed_realms": ("EXAMPLE.GOV",),
    }
    return Krb5TestConfig(**(defaults | overrides))


@pytest.fixture
def keytab_file(tmp_path):
    path = tmp_path / "service.keytab"
    path.write_bytes(b"not-a-real-keytab")
    return str(path)


@pytest.fixture
def ambient_ticket():
    """Pretend the developer has a valid ticket, so live_env does not skip."""
    with mock.patch(
        "tests.integration.krb5_harness.default_principal_from_ccache",
        return_value="alice@EXAMPLE.GOV",
    ):
        yield


def test_settings_are_exported_and_restored_on_teardown(
    keytab_file, tmp_path, tmp_path_factory, ambient_ticket, monkeypatch
):
    """`live_env` exports both settings, then puts the originals back.

    The export itself is `KerberosConfig.apply_to_environment`, tested in
    `test_auth_kerberos.py`; this checks the harness calls it and undoes it.
    A leaked KRB5_KTNAME would silently change later tests' behaviour.
    """

    conf = tmp_path / "krb5.conf"
    conf.write_text("[libdefaults]\n")
    monkeypatch.setenv("KRB5_KTNAME", "/original/value.keytab")
    monkeypatch.setenv("KRB5_CONFIG", "/original/krb5.conf")
    gen = live_env(
        make_cfg(keytab=keytab_file, krb5_config=str(conf)), tmp_path_factory
    )

    next(gen)
    assert os.environ["KRB5_KTNAME"] == keytab_file
    assert os.environ["KRB5_CONFIG"] == str(conf)
    gen.close()

    assert os.environ["KRB5_KTNAME"] == "/original/value.keytab"
    assert os.environ["KRB5_CONFIG"] == "/original/krb5.conf"


def test_ambient_mode_leaves_the_developers_ccache_alone(
    keytab_file, tmp_path_factory, ambient_ticket, monkeypatch
):
    """Empty client_keytab means "use my ticket" -- never redirect KRB5CCNAME."""

    monkeypatch.setenv("KRB5CCNAME", "FILE:/my/own/ccache")

    gen = live_env(make_cfg(keytab=keytab_file, client_keytab=""), tmp_path_factory)
    env = next(gen)

    assert os.environ["KRB5CCNAME"] == "FILE:/my/own/ccache"
    assert env.user_princ == "alice@EXAMPLE.GOV"
    assert env.realm == "EXAMPLE.GOV"

    gen.close()


def test_client_credentials_are_passed_to_kinit(
    keytab_file, tmp_path, tmp_path_factory, monkeypatch
):
    """client_principal and client_keytab must reach the kinit argv."""

    client_keytab = tmp_path / "client.keytab"
    client_keytab.write_bytes(b"not-a-real-keytab")

    completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
    with mock.patch(
        "tests.integration.krb5_harness.subprocess.run", return_value=completed
    ) as run:
        with mock.patch(
            "tests.integration.krb5_harness.shutil.which", return_value="/usr/bin/kinit"
        ):
            gen = live_env(
                make_cfg(
                    keytab=keytab_file,
                    client_keytab=str(client_keytab),
                    client_principal="svc-tokentest@EXAMPLE.GOV",
                ),
                tmp_path_factory,
            )
            env = next(gen)

            argv = run.call_args[0][0]
            assert argv[:2] == ["/usr/bin/kinit", "-kt"]
            assert argv[2] == str(client_keytab)
            assert argv[3] == "svc-tokentest@EXAMPLE.GOV"

            # Keytab mode must never kinit into the ambient cache.
            assert os.environ["KRB5CCNAME"].startswith("FILE:")
            assert "krb5cc" in os.environ["KRB5CCNAME"]
            assert env.user_princ == "svc-tokentest@EXAMPLE.GOV"

            gen.close()


def test_service_name_reaches_the_yielded_environment(
    keytab_file, tmp_path_factory, ambient_ticket
):
    """The SPN the tests target comes from config."""

    gen = live_env(
        make_cfg(keytab=keytab_file, service_name="HTTP@tokens.example.gov"),
        tmp_path_factory,
    )
    env = next(gen)

    assert env.service_name == "HTTP@tokens.example.gov"
    assert env.hostname == "tokens.example.gov"

    gen.close()


def test_unreadable_keytab_skips_rather_than_fails(tmp_path_factory):
    """Tests a credential that is not provisioned yet."""

    gen = live_env(make_cfg(keytab="/nonexistent/service.keytab"), tmp_path_factory)

    with pytest.raises(pytest.skip.Exception, match="not readable"):
        next(gen)


def test_unexpanded_variable_is_reported_separately_from_a_missing_file(
    tmp_path_factory,
):
    """An unset variable is reported as such, not as a missing file."""

    gen = live_env(make_cfg(keytab="$NOPE_UNSET/service.keytab"), tmp_path_factory)

    with pytest.raises(pytest.skip.Exception, match="unexpanded variable"):
        next(gen)


def test_resolve_config_expands_paths_like_the_runtime_does(monkeypatch):
    """The harness and the authenticator must agree on path handling."""

    class FakeSettings:
        def get(self, key, default=None):
            if key == "TEST":
                return {"KERBEROS": {"mode": "live", "keytab": "$HOME/x.keytab"}}
            return default

    cfg = resolve_config(FakeSettings())

    assert cfg.keytab == expand_path("$HOME/x.keytab")
    assert "$" not in cfg.keytab
    # Unset keys fall back to KRB5_TEST_DEFAULTS rather than raising.
    assert cfg.client_keytab == ""
    assert cfg.uses_ambient_ccache is True
