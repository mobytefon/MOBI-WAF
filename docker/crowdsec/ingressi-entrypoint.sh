#!/bin/bash
# Entrypoint of the Ingressi CrowdSec image (docker/crowdsec/Dockerfile).
#
# 1. Installs the Ingressi-owned configuration (config.yaml.local, acquis.yaml)
#    into /etc/crowdsec, a volume, so image updates reach existing installs.
# 2. In the background, once the local API answers: registers the dashboard's
#    machine account (CROWDSEC_MACHINE_ID, default ingressi-web) with
#    CROWDSEC_MACHINE_PASSWORD, then runs the watcher ingressi-sync.sh.
#    Registration has to wait: on the first start /etc/crowdsec is empty
#    until /docker_start.sh populates it, and docker_start.sh edits
#    config.yaml until it starts crowdsec.
# 3. Hands over to the image's own /docker_start.sh (COLLECTIONS, PARSERS,
#    BOUNCER_KEY_*, ENROLL_KEY, ... keep working as documented upstream).
set -euo pipefail

: "${CROWDSEC_DB_PASSWORD:?CROWDSEC_DB_PASSWORD is required}"
: "${CROWDSEC_MACHINE_PASSWORD:?CROWDSEC_MACHINE_PASSWORD is required}"
export CONFIG_FILE="${CONFIG_FILE:-/etc/crowdsec/config.yaml}"

share=/usr/local/share/ingressi
install -d -m 0755 /etc/crowdsec
install -m 0600 "$share/config.yaml.local" /etc/crowdsec/config.yaml.local
install -m 0644 "$share/acquis.yaml" /etc/crowdsec/acquis.yaml

bootstrap() {
  local machine="${CROWDSEC_MACHINE_ID:-ingressi-web}"
  until cscli -c "$CONFIG_FILE" lapi status >/dev/null 2>&1; do
    sleep 2
  done
  # --force re-registers on every start, so a changed password takes effect.
  until cscli -c "$CONFIG_FILE" machines add "$machine" \
      --password "$CROWDSEC_MACHINE_PASSWORD" -f /dev/null --force >/dev/null; do
    echo "ingressi: registering machine $machine failed, retrying" >&2
    sleep 5
  done
  echo "ingressi: machine $machine registered" >&2
  exec /usr/local/bin/ingressi-sync.sh
}

bootstrap &

exec /bin/bash /docker_start.sh "$@"
