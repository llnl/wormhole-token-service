import os
import pytest
from unittest import mock

from token_service.auth.kerberos import (
    KerberosAcceptor,
    KerberosAuthError,
    KerberosConfig,
    KerberosConfigError,
    as_realm_tuple,
    gss_name,
)
from tests.helpers.fake_deps import fake_gssapi, fake_handshake
from token_service.config import settings


def make_acceptor(**config):
    defaults = {"enabled": True, "allowed_realms": ["EXAMPLE.GOV"]}
    return KerberosAcceptor(KerberosConfig.from_mapping({**defaults, **config}))


@pytest.mark.parametrize(
    "spn,expect_principal_form",
    [
        pytest.param("HTTP/tokens.example.gov@EXAMPLE.GOV", True, id="principal"),
        pytest.param("HTTP@tokens.example.gov", False, id="hostbased"),
        pytest.param("host/myhost.local", True, id="bare_principal"),
        pytest.param("HTTP/a.b.gov@REALM.WITH.DOTS", True, id="dotted_realm"),
    ],
)
def test_gss_name_picks_the_type_from_the_spelling(spn, expect_principal_form):
    """Both GSSAPI name forms are accepted; the type follows the spelling."""

    with fake_gssapi() as gssapi:
        gss_name(spn)

    name_type = gssapi.raw.NameType
    expected = (
        name_type.kerberos_principal
        if expect_principal_form
        else name_type.hostbased_service
    )
    gssapi.Name.assert_called_once_with(spn, expected)


@pytest.mark.parametrize(
    "value,expected",
    [
        pytest.param(["A.GOV", "B.GOV"], ("A.GOV", "B.GOV"), id="toml_list"),
        pytest.param("A.GOV, B.GOV", ("A.GOV", "B.GOV"), id="env_csv"),
        pytest.param("", (), id="empty_string"),
        pytest.param(None, (), id="none"),
        pytest.param([], (), id="empty_list"),
    ],
)
def test_as_realm_tuple_normalises_both_config_shapes(value, expected):
    assert as_realm_tuple(value) == expected


def test_principal_to_uid_strips_the_realm():
    acceptor = make_acceptor(allowed_realms=["EXAMPLE.GOV"])

    assert acceptor.principal_to_uid("alice@EXAMPLE.GOV") == "alice"


def test_principal_to_uid_rejects_a_realm_outside_the_allow_list():
    acceptor = make_acceptor(allowed_realms=["EXAMPLE.GOV"])

    with pytest.raises(KerberosAuthError):
        acceptor.principal_to_uid("alice@TRUSTED.PARTNER.GOV")


def test_realm_comparison_is_exact_not_suffix_matching():
    acceptor = make_acceptor(allowed_realms=["EXAMPLE.GOV"])

    for hostile in ("alice@OTHER-EXAMPLE.GOV", "alice@example.gov"):
        with pytest.raises(KerberosAuthError):
            acceptor.principal_to_uid(hostile)


def test_empty_allowed_realms_refuses_to_start():
    with pytest.raises(KerberosConfigError, match="exactly one realm"):
        make_acceptor(allowed_realms=[])


def test_multiple_allowed_realms_refuse_to_start():
    with pytest.raises(KerberosConfigError, match="exactly one realm"):
        make_acceptor(allowed_realms=["A.EXAMPLE.GOV", "B.EXAMPLE.GOV"])


def test_a_single_realm_from_an_env_var_string_is_accepted():
    acceptor = make_acceptor(allowed_realms="EXAMPLE.GOV")

    assert acceptor.principal_to_uid("alice@EXAMPLE.GOV") == "alice"


def test_multiple_realms_from_an_env_var_string_refuse_to_start():
    with pytest.raises(KerberosConfigError, match="exactly one realm"):
        make_acceptor(allowed_realms="A.EXAMPLE.GOV,B.EXAMPLE.GOV")


@pytest.mark.parametrize(
    "principal",
    [
        pytest.param("alice/admin@EXAMPLE.GOV", id="human_instance"),
        pytest.param("host/box.example.gov@EXAMPLE.GOV", id="host_principal"),
        pytest.param("nfs/box.example.gov@EXAMPLE.GOV", id="service_principal"),
    ],
)
def test_instance_principals_are_rejected(principal):
    """Only bare user principals authenticate."""

    acceptor = make_acceptor(allowed_realms=["EXAMPLE.GOV"])

    with pytest.raises(KerberosAuthError):
        acceptor.principal_to_uid(principal)


def test_principal_without_a_realm_is_rejected():
    acceptor = make_acceptor(allowed_realms=["EXAMPLE.GOV"])

    with pytest.raises(KerberosAuthError):
        acceptor.principal_to_uid("alice")


def test_a_rejected_token_becomes_a_kerberos_auth_error():
    acceptor = make_acceptor()
    ctx = mock.MagicMock()

    with fake_handshake(ctx) as gssapi:
        ctx.step.side_effect = gssapi.exceptions.GSSError("rejected")
        with pytest.raises(KerberosAuthError):
            acceptor.step(b"garbage")


def test_an_incomplete_context_is_a_result_not_an_error():
    """Multi-leg negotiation is a normal outcome needing another round trip."""

    acceptor = make_acceptor()
    ctx = mock.MagicMock()
    ctx.step.return_value = b"continue-me"
    ctx.complete = False

    with fake_handshake(ctx):
        result = acceptor.step(b"garbage")

    assert result.complete is False
    assert result.token == b"continue-me"
    assert result.principal is None


def test_a_completed_context_carries_the_initiator_principal():
    acceptor = make_acceptor()
    ctx = mock.MagicMock()
    ctx.step.return_value = b"server-token"
    ctx.complete = True
    ctx.initiator_name = "alice@EXAMPLE.GOV"

    with fake_handshake(ctx):
        result = acceptor.step(b"garbage")

    assert result.complete is True
    assert result.token == b"server-token"
    assert result.principal == "alice@EXAMPLE.GOV"


def test_every_documented_config_key_is_consumed():
    """The schema in settings.toml and the keys the code reads must match."""

    documented = set(settings.to_dict()["AUTH"]["kerberos"])
    consumed = set(KerberosConfig.CONSUMED_CONFIG_KEYS)
    assert documented == consumed, (
        f"declared but never read: {sorted(documented - consumed)}; "
        f"read but undocumented: {sorted(consumed - documented)}"
    )


def test_building_a_config_does_not_touch_the_environment(monkeypatch):
    monkeypatch.delenv("KRB5_KTNAME", raising=False)

    KerberosConfig.from_mapping({"keytab": "/tmp/some-service.keytab"})
    assert "KRB5_KTNAME" not in os.environ


@pytest.mark.parametrize(
    "key,env_var",
    [("keytab", "KRB5_KTNAME"), ("krb5_config", "KRB5_CONFIG")],
)
def test_setting_is_exported_to_its_env_var(monkeypatch, key, env_var):
    """Each setting must actually reach GSSAPI, which reads the env var."""

    monkeypatch.delenv(env_var, raising=False)

    KerberosConfig.from_mapping({key: "/tmp/some-file"}).apply_to_environment()
    assert os.environ[env_var] == "/tmp/some-file"


def test_keytab_path_is_expanded_before_export(monkeypatch, tmp_path):
    """An unexpanded path would reach the krb5 library as a relative path.

    The path forms themselves are covered in `test_utils.py`.
    """

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("KRB5_KTNAME", raising=False)

    KerberosConfig.from_mapping({"keytab": "$HOME/x.keytab"}).apply_to_environment()
    assert os.environ["KRB5_KTNAME"] == f"{tmp_path}/x.keytab"


def test_empty_keytab_does_not_clobber_the_ambient_environment(monkeypatch):
    """Empty means "leave it alone", not "unset whatever was deliberately set"."""

    monkeypatch.setenv("KRB5_KTNAME", "/set/by/the/deployment.keytab")

    KerberosConfig.from_mapping({"keytab": ""}).apply_to_environment()
    assert os.environ["KRB5_KTNAME"] == "/set/by/the/deployment.keytab"


def test_service_name_reaches_the_acceptor_credential():
    acceptor = make_acceptor(service_name="HTTP/tokens.example.gov@EXAMPLE.GOV")

    with fake_gssapi() as gssapi:
        acceptor.creds

    gssapi.Name.assert_called_once_with(
        "HTTP/tokens.example.gov@EXAMPLE.GOV", gssapi.raw.NameType.kerberos_principal
    )
    gssapi.Credentials.assert_called_once_with(
        usage="accept", name=gssapi.Name.return_value
    )


def test_empty_service_name_accepts_any_spn_in_the_keytab():
    """Documented behavior of an empty `service_name`, pinned deliberately."""

    acceptor = make_acceptor(service_name="")

    with fake_gssapi() as gssapi:
        acceptor.creds

    gssapi.Name.assert_not_called()
    gssapi.Credentials.assert_called_once_with(usage="accept", name=None)
