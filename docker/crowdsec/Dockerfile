# CrowdSec security engine + local API for docker-compose.crowdsec.yml.
#
# The upstream image (Alpine, entrypoint /docker_start.sh) plus jq for the
# Ingressi watcher, the PostgreSQL/LAPI/Prometheus settings, the Caddy
# access-log acquisition, and an entrypoint that registers the dashboard's
# machine account and starts the watcher (ingressi-sync.sh) next to CrowdSec.
FROM crowdsecurity/crowdsec:v1.8.2@sha256:65b74942f7e7ed5c60fde4ac15fc4ba715904c398c8b16dd451f4907d90347d4

RUN apk add --no-cache jq

# Copied over /etc/crowdsec (a volume) by the entrypoint on every start, so
# image updates of these files reach existing installs.
COPY docker/crowdsec/config.yaml.local docker/crowdsec/acquis.yaml /usr/local/share/ingressi/
COPY --chmod=0755 docker/crowdsec/ingressi-entrypoint.sh docker/crowdsec/ingressi-sync.sh /usr/local/bin/
# A Windows checkout (core.autocrlf) gives the scripts CRLF line endings.
RUN sed -i 's/\r$//' /usr/local/bin/ingressi-entrypoint.sh /usr/local/bin/ingressi-sync.sh \
      /usr/local/share/ingressi/config.yaml.local /usr/local/share/ingressi/acquis.yaml

ENTRYPOINT ["/bin/bash", "/usr/local/bin/ingressi-entrypoint.sh"]
