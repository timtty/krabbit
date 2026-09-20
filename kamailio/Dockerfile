# Kamailio SIP honeypot.
#   kamailio-extra-modules -> jansson    (safe JSON construction)
#   kamailio-utils-modules -> http_client (POST events to Elasticsearch)
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        kamailio \
        kamailio-extra-modules \
        kamailio-utils-modules \
        ca-certificates \
        netbase \
    && rm -rf /var/lib/apt/lists/*

# Default OpenSearch endpoint, read by kamailio.cfg via $env(). Compose
# overrides it per deployment; the default keeps the image usable on its own
# rather than starting with an empty URL and silently dropping every event.
ENV KRABBIT_ES_URL=http://opensearch:9200/sip-honeypot/_doc

# Default SIP listen target, read by kamailio.cfg via $env(). A bare interface
# name is what makes dst_ip meaningful (one socket per address), but interface
# names are host-specific, so the real deployment sets this in the compose
# overlay. 0.0.0.0 keeps the image runnable on its own and on Docker Desktop,
# where the container is bridge-networked and dst_ip is the container address
# anyway. Unset would be a hard parse error at startup, not a silent default.
ENV KRABBIT_SIP_LISTEN=0.0.0.0

COPY kamailio.cfg /etc/kamailio/kamailio.cfg

# Validate the config at build time so a syntax error fails the build, not runtime.
RUN kamailio -c -f /etc/kamailio/kamailio.cfg

EXPOSE 5060/udp 5060/tcp

# -DD: stay in foreground (don't daemonize) so the container stays up.
# -E:  log to stderr so `docker logs` / compose captures honeypot activity.
CMD ["kamailio", "-DD", "-E", "-f", "/etc/kamailio/kamailio.cfg"]
