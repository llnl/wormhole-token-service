# Local KDC for configuration testing

A single-realm MIT KDC in a container, so `TEST.KERBEROS` and `AUTH.kerberos`
can point at a **real** KDC that survives across pytest runs and server
restarts.

It answers one question: **is our configuration correct?** Not whether the
business logic works — `tests/integration/test_kerberos.py` covers that, and
with the default `mode = "k5test"` it uses an ephemeral `k5test` realm and
needs none of this. With `mode = "live"` it runs against this KDC too.

This is a local development tool. It is not used by CI, is not a model of a
production realm, and nothing in `token_service/` depends on it.

## Why not k5test

`k5test` generates the realm, keytab and `krb5.conf` itself and hands you the
paths. You cannot point configuration at it, and it dies with the pytest
process. A fixture that supplies the configuration cannot also test the
configuration — hence a KDC that exists independently of the tests.

## Start it

```shell
docker compose -f docker-compose.krb5.yml up -d --build
```

Provisioning runs on every start — `down` then `up` gives the same realm,
principal names and file paths, but fresh random keys, so keytabs from a
previous start stop working. The keytabs in `./.krb5/` are rewritten at the
same time, so they can never silently disagree with the KDC.

Artifacts land in `./.krb5/` (already gitignored via `*.keytab` and
`krb5.conf`):

| File | What it is |
| --- | --- |
| `service.keytab` | acceptor keytab, holds `HTTP/localhost@WORMHOLE.TEST` |
| `client.keytab` | client keytab, holds `svc-tokentest@WORMHOLE.TEST` |
| `decoy.keytab` | a *valid* keytab holding `decoy/nowhere` — for proving a configured keytab is the one actually opened |
| `krb5.conf` | points at `localhost:8088`, `rdns = false` |

Check it came up:

```shell
docker compose -f docker-compose.krb5.yml logs kdc | grep '==>'
klist -k .krb5/service.keytab
```

## Configure the tests

`tests/config/test_settings.toml` already holds this KDC's values under
`[default.TEST.KERBEROS]`, with paths relative to the project folder. It
defaults to `mode = "k5test"`; to use this KDC, switch it to live in
`tests/config/test_settings.local.toml` (gitignored):

```toml
[default.TEST.KERBEROS]
mode = "live"
```

Or for one run, without touching the file: `DYNACONF_TEST__KERBEROS__mode=live`
(`make test-krb5` does this). To test against a different realm, override the
other keys the same way; paths must be absolute.

Check the settings against the files and KDC they name:

```shell
make check-krb5-config
```

Each check prints PASS, FAIL, WARN or SKIP with what was resolved (value
formats, files and permissions, each keytab holding its principal, the KDC
answering, `kinit` getting a ticket into a temporary cache), and the command
exits non-zero on any failure.

Or just print what the fixtures resolved:

```shell
uv run python -c 'from tests.integration.krb5_harness import load_test_config; c = load_test_config(); [print(f"{f:18}= {getattr(c,f)!r}") for f in c.__dataclass_fields__]'
```

## Run the tests against it

```shell
make test-krb5
```

Runs the endpoint and handshake tests (`test_kerberos.py`,
`test_gssapi_handshake.py`) in live mode against this KDC. With `mode = "live"`
set locally, a plain `uv run pytest tests -m integration` does the same.

## Configure the runtime too

To exercise the service itself against this realm:

```toml
[default.AUTH.kerberos]
enabled = true
service_name = "HTTP/localhost@WORMHOLE.TEST"
keytab = "@format {env[WORMHOLE_TOKEN_SVC_DIR]}/.krb5/service.keytab"
krb5_config = "@format {env[WORMHOLE_TOKEN_SVC_DIR]}/.krb5/krb5.conf"
allowed_realms = ["WORMHOLE.TEST"]
```

`make` and tox set `WORMHOLE_TOKEN_SVC_DIR` to the project folder; for other
runs, set it yourself.

Then seed a user matching the principal you will authenticate as, and drive the
endpoint with a real ticket:

```shell
uv run wormhole_token_service seed-dev-user --uid svc-tokentest
make run-dev
export KRB5_CONFIG=$PWD/.krb5/krb5.conf   # for kinit and curl alike
kinit -kt .krb5/client.keytab svc-tokentest@WORMHOLE.TEST
curl --negotiate -u : -d name=mytoken http://localhost:5000/api/v1/krb/token
```

Note `AUTH.kerberos.allowed_realms` must be exactly `["WORMHOLE.TEST"]` (empty or
more than one realm stops the app at startup), and the uid is
the principal with the realm stripped — instance principals such as
`alice/admin@REALM` are rejected outright.

## Stop it

```shell
docker compose -f docker-compose.krb5.yml down -v
rm -rf .krb5
```

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `bind: address already in use` on start | Something holds the host port. Override with `KRB5_HOST_PORT=9088 docker compose -f docker-compose.krb5.yml up -d`; the generated `krb5.conf` follows it automatically. |
| `Server not found in Kerberos database` | `service_name` names a principal the keytab does not hold. `klist -k .krb5/service.keytab` shows what is there. |
| `Cannot find KDC for realm` | `krb5_config` unset, or pointing at a file with no `[realms]` entry for the realm. |
| `Client not found in Kerberos database` | `client_principal` does not exist in this realm. |
| kinit hangs rather than failing | UDP 88 not published. Both mappings are required. |
| `KRB_AP_ERR_SKEW` | Container and host clocks disagree by more than 5 minutes. Restart Docker Desktop. |
