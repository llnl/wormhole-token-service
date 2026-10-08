"""Tests for the harness's `live_env`; no KDC, no gssapi.

Real live runs (`make test-krb5`) cover the happy path. These cover what those
runs never exercise: the developer's own ticket cache is left alone, and
misconfiguration skips with a clear message.
"""

import os
import subprocess
from unittest import mock

import pytest

from tests.integration.krb5_harness import Krb5TestConfig, live_env


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


@pytest.mark.parametrize(
    "keytab,message",
    [
        pytest.param("/nonexistent/service.keytab", "not readable", id="missing"),
        pytest.param(
            "$NOPE_UNSET/service.keytab", "unexpanded variable", id="unset_var"
        ),
    ],
)
def test_bad_keytab_path_skips_with_a_specific_message(
    tmp_path_factory, keytab, message
):
    """A missing file and an unset variable each skip, and say which it was."""

    gen = live_env(make_cfg(keytab=keytab), tmp_path_factory)

    with pytest.raises(pytest.skip.Exception, match=message):
        next(gen)
