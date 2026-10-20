# Local KDC

A single-realm MIT KDC (`WORMHOLE.TEST`) in Docker, for running the Kerberos
tests and the service against a real KDC. Local development only.

## Start

```shell
make run-local-docker-krb
```

Writes `service.keytab` (`HTTP/localhost@WORMHOLE.TEST`), `client.keytab`
(`svc-tokentest@WORMHOLE.TEST`) and `krb5.conf` to `./.krb5/`. Every start
issues new keys and rewrites these files.

## Test against it

```shell
make test-live-krb
```

Or set it for every run in `tests/config/test_settings.local.toml`:

```toml
dynaconf_merge = true

[testing.TEST.KERBEROS]
mode = "live"
```

## Run the service against it

In `settings.local.toml`:

```toml
[default.AUTH.kerberos]
enabled = true
service_name = "HTTP/localhost@WORMHOLE.TEST"
keytab = "@format {env[WORMHOLE_TOKEN_SVC_DIR]}/.krb5/service.keytab"
krb5_config = "@format {env[WORMHOLE_TOKEN_SVC_DIR]}/.krb5/krb5.conf"
allowed_realms = ["WORMHOLE.TEST"]
```

```shell
uv run wormhole_token_service seed-dev-user --uid svc-tokentest
make run-dev
export KRB5_CONFIG=$PWD/.krb5/krb5.conf
kinit -kt .krb5/client.keytab svc-tokentest@WORMHOLE.TEST
curl --negotiate -u : -d name=mytoken http://localhost:5000/api/v1/krb/token
```

## Stop

```shell
docker compose -f docker-compose.krb5.yml down -v
rm -rf .krb5
```
