"""Raw GSSAPI handshake checks against a KDC, with no app or database.

Runs against k5test or a live realm, selected by `TEST.KERBEROS.mode`.
"""

import subprocess

import pytest

from .krb5_harness import initiate

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def clean_db():
    yield


def test_client_credential_is_usable(krb5_env):
    """A ticket for the expected realm exists before any handshake is attempted."""

    assert krb5_env.realm
    assert krb5_env.user_princ.endswith(f"@{krb5_env.realm}")
    klist = subprocess.run(["klist"], capture_output=True, text=True)
    assert krb5_env.realm in klist.stdout


def test_raw_handshake_completes(krb5_env, service_name):
    """A bare initiate/accept exchange completes and names the initiator."""

    import gssapi

    _, client_token = initiate(service_name)
    server_ctx = gssapi.SecurityContext(
        creds=gssapi.Credentials(usage="accept", name=service_name)
    )
    server_ctx.step(client_token)

    assert server_ctx.complete
    assert str(server_ctx.initiator_name) == krb5_env.user_princ


def test_mutual_auth_token_is_returned(krb5_env, service_name):
    """The acceptor emits a token the initiator can verify it with.

    This is the raw form of the `WWW-Authenticate: Negotiate <b64>` reply header.
    """

    import gssapi

    client_ctx, client_token = initiate(service_name)
    server_ctx = gssapi.SecurityContext(
        creds=gssapi.Credentials(usage="accept", name=service_name)
    )
    server_token = server_ctx.step(client_token)

    assert server_token
    client_ctx.step(server_token)
    assert client_ctx.complete


def test_a_garbage_token_raises_gsserror(service_name):
    """A non-GSS token fails at the Kerberos layer, not silently."""

    import gssapi

    server_ctx = gssapi.SecurityContext(
        creds=gssapi.Credentials(usage="accept", name=service_name)
    )

    with pytest.raises(gssapi.exceptions.GSSError):
        server_ctx.step(b"garbage")
