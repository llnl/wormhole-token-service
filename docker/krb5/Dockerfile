# Single-realm MIT KDC for local Kerberos testing.
FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        krb5-kdc krb5-admin-server \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=755 provision.sh /usr/local/bin/provision.sh

EXPOSE 88/tcp 88/udp

ENTRYPOINT ["/usr/local/bin/provision.sh"]
