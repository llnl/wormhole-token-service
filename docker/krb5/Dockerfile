# Single-realm MIT KDC for local Kerberos testing; not a production model.
FROM debian:bookworm-slim

ARG REALM=WORMHOLE.TEST

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        krb5-kdc krb5-admin-server krb5-user \
    && rm -rf /var/lib/apt/lists/*

COPY provision.sh /usr/local/bin/provision.sh
RUN chmod +x /usr/local/bin/provision.sh

ENV REALM=${REALM}

# 88 = KDC (TCP and UDP). 749 = kadmin, unused (provisioning uses kadmin.local).
EXPOSE 88/tcp 88/udp 749/tcp

ENTRYPOINT ["/usr/local/bin/provision.sh"]
