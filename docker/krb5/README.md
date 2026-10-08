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

Put this in `settings.local.toml` (gitignored). Paths must be **absolute** —
`$HOME`, `${HOME}` and `~` are expanded by the fixture, but a relative path is
resolved against the process working directory.

```toml
[default.TEST.KERBEROS]
mode = "live"
service_name = "HTTP/localhost@WORMHOLE.TEST"
keytab = "/absolute/path/to/repo/.krb5/service.keytab"
krb5_config = "/absolute/path/to/repo/.krb5/krb5.conf"
client_principal = "svc-tokentest@WORMHOLE.TEST"
client_keytab = "/absolute/path/to/repo/.krb5/client.keytab"
allowed_realms = ["WORMHOLE.TEST"]
```

Or without touching the file:

```shell
export DYNACONF_TEST__KERBEROS__mode=live
export DYNACONF_TEST__KERBEROS__service_name="HTTP/localhost@WORMHOLE.TEST"
export DYNACONF_TEST__KERBEROS__keytab="$PWD/.krb5/service.keytab"
export DYNACONF_TEST__KERBEROS__krb5_config="$PWD/.krb5/krb5.conf"
export DYNACONF_TEST__KERBEROS__client_principal="svc-tokentest@WORMHOLE.TEST"
export DYNACONF_TEST__KERBEROS__client_keytab="$PWD/.krb5/client.keytab"
export DYNACONF_TEST__KERBEROS__allowed_realms="WORMHOLE.TEST"
```

Confirm what the fixtures resolved before running anything:

```shell
uv run python -c 'from token_service.config import settings; from tests.integration.krb5_harness import resolve_config; c = resolve_config(settings); [print(f"{f:18}= {getattr(c,f)!r}") for f in c.__dataclass_fields__]'
```

## Run the validation suite

```shell
uv run pytest tests/integration/test_kerberos_live_config.py -m integration -v
```

22 checks, in two groups:

- **Value format** — SPN is a recognised form, realm is uppercase, paths are
  absolute and fully expanded, `client_keytab` and `client_principal` are set
  together, `allowed_realms` entries are bare realm names.
- **Configured resources are usable** — files exist, are readable and are not
  writable by others; the acceptor keytab actually holds the configured SPN;
  `krb5.conf` declares the realm and at least one KDC; the KDC answers on TCP;
  `kinit` obtains a ticket with the client keytab; an acceptor credential can be
  acquired; a full handshake completes.

With `mode = "k5test"` (the default) the whole module skips — those settings are
what it validates, and k5test ignores them.

## Configure the runtime too

To exercise the service itself against this realm:

```toml
[default.AUTH.kerberos]
enabled = true
service_name = "HTTP/localhost@WORMHOLE.TEST"
keytab = "@format {env[PWD]}/.krb5/service.keytab"
krb5_config = "@format {env[PWD]}/.krb5/krb5.conf"
allowed_realms = ["WORMHOLE.TEST"]
```

Then seed a user matching the principal you will authenticate as, and drive the
endpoint with a real ticket:

```shell
uv run wormhole_token_service seed-dev-user --uid svc-tokentest
make run-dev
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
