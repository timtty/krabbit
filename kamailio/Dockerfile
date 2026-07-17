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

COPY kamailio.cfg /etc/kamailio/kamailio.cfg

# Validate the config at build time so a syntax error fails the build, not runtime.
RUN kamailio -c -f /etc/kamailio/kamailio.cfg

EXPOSE 5060/udp 5060/tcp

# -DD: stay in foreground (don't daemonize) so the container stays up.
# -E:  log to stderr so `docker logs` / compose captures honeypot activity.
CMD ["kamailio", "-DD", "-E", "-f", "/etc/kamailio/kamailio.cfg"]
