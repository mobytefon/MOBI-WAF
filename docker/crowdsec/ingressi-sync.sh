#!/bin/bash
# Ingressi managed-state watcher, started by ingressi-entrypoint.sh once the
# local API is up. The dashboard cannot reach the Docker socket; it writes the
# desired state into the shared crowdsec-managed volume (/ingressi here,
# CROWDSEC_MANAGED_DIR in the web container) and this script applies it:
#
#   desired/generation                  integer, written last by the dashboard
#   desired/whitelists/zz-ingressi-*.yaml  parser whitelists (s02-enrich)
#   desired/allowlist.txt               one IP or CIDR per line -> allowlist "ingressi"
#   desired/collections.txt             one hub collection per line (optional)
#
#   status/result.json    {generation, ok, message, at} after each apply
#   status/snapshot.json  {at, bouncers, machines, hub} every 60 seconds
#
# Each new generation: back up the current zz-ingressi-*.yaml, replace them
# with the desired ones, install/remove collections by difference with the
# last applied set, then `crowdsec -t`. On success crowdsec gets SIGHUP and
# the allowlist is synced by difference; on failure everything is put back.
# A generation is applied once, whatever the outcome; the dashboard writes a
# new one to retry. Blank lines and lines starting with # are ignored in the
# .txt files.
set -uo pipefail
export LC_ALL=C

root="${INGRESSI_MANAGED_ROOT:-/ingressi}"
desired="$root/desired"
status="$root/status"
state="${INGRESSI_STATE_DIR:-/etc/crowdsec/ingressi-state}"
parser_dir="${INGRESSI_PARSER_DIR:-/etc/crowdsec/parsers/s02-enrich}"
config_file="${CONFIG_FILE:-/etc/crowdsec/config.yaml}"
allowlist="${INGRESSI_ALLOWLIST_NAME:-ingressi}"
poll_interval="${INGRESSI_SYNC_INTERVAL:-5}"
snapshot_interval="${INGRESSI_SNAPSHOT_INTERVAL:-60}"
# Collections installed by the container's own COLLECTIONS variable are never
# removed by the dashboard.
base_collections=" ${COLLECTIONS:-} "

whitelist_re='^zz-ingressi-[A-Za-z0-9_-]+\.yaml$'
collection_re='^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'
address_re='^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'

log() { echo "ingressi-sync: $*" >&2; }
cs() { cscli -c "$config_file" "$@"; }
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# write_json <target> <jq args...>: atomic write of `jq -n <args>`.
write_json() {
  local target="$1" tmp
  shift
  tmp="$(mktemp "$(dirname "$target")/.tmp.XXXXXX")" || return 1
  if jq -n "$@" >"$tmp"; then
    chmod 0644 "$tmp"
    mv -f "$tmp" "$target"
  else
    rm -f "$tmp"
    return 1
  fi
}

write_result() {
  local generation="$1" ok="$2" message="$3"
  write_json "$status/result.json" \
    --argjson generation "$generation" --argjson ok "$ok" \
    --arg message "$message" --arg at "$(now)" \
    '{generation: $generation, ok: $ok, message: $message, at: $at}' ||
    log "cannot write $status/result.json"
}

# read_list <file> <regex> <out>: the file's entries, trimmed, sorted, unique.
# Fails (with the offending line on stdout) if one does not match the regex.
read_list() {
  local file="$1" re="$2" out="$3" line
  : >"$out.raw"
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [ -z "$line" ] || [ "${line:0:1}" = "#" ] && continue
    if ! [[ $line =~ $re ]]; then
      printf '%s' "$line"
      rm -f "$out.raw"
      return 1
    fi
    printf '%s\n' "$line" >>"$out.raw"
  done <"$file"
  sort -u "$out.raw" >"$out"
  rm -f "$out.raw"
}

# in_list <word> <file>
in_list() { grep -qxF -- "$1" "$2"; }

hub_collection() {
  local action="$1" name="$2"
  if [ "$action" = install ]; then
    cs collections install "$name" >/dev/null 2>&1 && return 0
    # The hub index may be older than the collection; update once and retry.
    cs hub update >/dev/null 2>&1 || true
    cs collections install "$name" >/dev/null 2>&1
  else
    cs collections remove "$name" >/dev/null 2>&1
  fi
}

reload_crowdsec() {
  local pid
  pid="$(pgrep -o -x crowdsec 2>/dev/null)" || pid=""
  if [ -z "$pid" ]; then
    return 1
  fi
  kill -HUP "$pid"
}

# sync_allowlist <desired-list-file>: allowlist $allowlist := file, by difference.
sync_allowlist() {
  local want="$1" have="$work/allowlist.current" add="$work/allowlist.add" del="$work/allowlist.del"
  if cs allowlists inspect "$allowlist" -o json >"$work/allowlist.json" 2>/dev/null; then
    jq -r '.items[]?.value // empty' "$work/allowlist.json" | sort -u >"$have" || return 1
  else
    cs allowlists create "$allowlist" -d "Managed by Ingressi: edit it in the dashboard" >/dev/null 2>&1 || return 1
    : >"$have"
  fi
  comm -13 "$have" "$want" >"$add"
  comm -23 "$have" "$want" >"$del"
  if [ -s "$add" ]; then
    xargs -r -n 200 cscli -c "$config_file" allowlists add "$allowlist" -d "Ingressi whitelist" <"$add" >/dev/null 2>&1 || return 1
  fi
  if [ -s "$del" ]; then
    xargs -r -n 200 cscli -c "$config_file" allowlists remove "$allowlist" <"$del" >/dev/null 2>&1 || return 1
  fi
  log "allowlist $allowlist: +$(wc -l <"$add") -$(wc -l <"$del")"
}

# apply <generation>: one apply of the desired state; writes result.json.
apply() {
  local generation="$1" file name bad output rc
  work="$(mktemp -d)"
  local backup="$work/backup" files="$work/files"
  mkdir -p "$backup" "$files"

  # 1. Validate everything before touching anything.
  if [ -d "$desired/whitelists" ]; then
    # Dot files (editor or temporary files) are ignored.
    for file in "$desired/whitelists"/*; do
      [ -e "$file" ] || [ -L "$file" ] || continue
      name="$(basename "$file")"
      if ! [[ $name =~ $whitelist_re ]] || [ -L "$file" ] || [ ! -f "$file" ]; then
        write_result "$generation" false "Refused whitelists/$name: only regular files named zz-ingressi-<id>.yaml are allowed"
        rm -rf "$work"
        return
      fi
      cp "$file" "$files/$name"
    done
  fi
  local want_allow="" want_collections=""
  if [ -f "$desired/allowlist.txt" ]; then
    want_allow="$work/allowlist.want"
    if ! bad="$(read_list "$desired/allowlist.txt" "$address_re" "$want_allow")"; then
      write_result "$generation" false "Refused allowlist.txt: \"$bad\" is not an IP address or CIDR range"
      rm -rf "$work"
      return
    fi
  fi
  if [ -f "$desired/collections.txt" ]; then
    want_collections="$work/collections.want"
    if ! bad="$(read_list "$desired/collections.txt" "$collection_re" "$want_collections")"; then
      write_result "$generation" false "Refused collections.txt: \"$bad\" is not a hub collection name (author/name)"
      rm -rf "$work"
      return
    fi
  fi

  # 2. Back up and replace the parser whitelists.
  mkdir -p "$parser_dir"
  for file in "$parser_dir"/zz-ingressi-*.yaml; do
    [ -f "$file" ] && cp -p "$file" "$backup/"
  done
  rm -f "$parser_dir"/zz-ingressi-*.yaml
  for file in "$files"/*; do
    [ -f "$file" ] && install -m 0644 "$file" "$parser_dir/$(basename "$file")"
  done

  # 3. Collections, by difference with the last applied set.
  local applied="$state/collections.applied" installed="$work/installed" removed="$work/removed" failed=""
  : >"$installed"
  : >"$removed"
  [ -f "$applied" ] || : >"$applied"
  if [ -n "$want_collections" ]; then
    while IFS= read -r name; do
      in_list "$name" "$applied" && continue
      if hub_collection install "$name"; then
        echo "$name" >>"$installed"
      else
        failed="$failed $name"
      fi
    done <"$want_collections"
    while IFS= read -r name; do
      [ -n "$name" ] || continue
      in_list "$name" "$want_collections" && continue
      [[ $base_collections == *" $name "* ]] && continue
      hub_collection remove "$name" && echo "$name" >>"$removed"
    done <"$applied"
  fi

  # 4. Test the whole configuration, then reload or roll back.
  if [ -n "$failed" ]; then
    output="cannot install collection(s):$failed"
    rc=1
  else
    output="$(crowdsec -c "$config_file" -t 2>&1)"
    rc=$?
  fi
  if [ "$rc" -eq 0 ]; then
    if [ -n "$want_collections" ]; then
      cp "$want_collections" "$applied"
    fi
    local message="Applied" ok=true
    if ! reload_crowdsec; then
      message="Applied, but no crowdsec process was found to reload"
      ok=false
    fi
    if [ -n "$want_allow" ] && ! sync_allowlist "$want_allow"; then
      message="$message; syncing allowlist $allowlist failed"
      ok=false
    fi
    write_result "$generation" "$ok" "$message"
    log "generation $generation: $message"
  else
    rm -f "$parser_dir"/zz-ingressi-*.yaml
    for file in "$backup"/*; do
      [ -f "$file" ] && cp -p "$file" "$parser_dir/"
    done
    while IFS= read -r name; do
      [ -n "$name" ] && hub_collection remove "$name"
    done <"$installed"
    while IFS= read -r name; do
      [ -n "$name" ] && hub_collection install "$name"
    done <"$removed"
    # Keep the message short: crowdsec's fatal lines, else its error lines,
    # else the last lines.
    local errors
    errors="$(printf '%s\n' "$output" | grep -F 'level=fatal')" ||
      errors="$(printf '%s\n' "$output" | grep -F 'level=error')" ||
      errors="$(printf '%s\n' "$output" | tail -n 5)"
    output="$(printf '%s\n' "$errors" | tail -n 5 | cut -c1-1000)"
    write_result "$generation" false "Configuration test failed, previous configuration kept: $output"
    log "generation $generation: test failed, rolled back"
  fi
  rm -rf "$work"
}

# snapshot: what the dashboard's Settings page shows (bouncers' last pull,
# machines, installed hub items). Hashed keys and passwords are not in the
# JSON output of cscli.
snapshot() {
  local dir what
  dir="$(mktemp -d)"
  for what in bouncers machines hub; do
    if ! cs "$what" list -o json >"$dir/$what.json" 2>/dev/null || ! jq -e . "$dir/$what.json" >/dev/null 2>&1; then
      echo null >"$dir/$what.json"
    fi
  done
  write_json "$status/snapshot.json" --arg at "$(now)" \
    --slurpfile bouncers "$dir/bouncers.json" \
    --slurpfile machines "$dir/machines.json" \
    --slurpfile hub "$dir/hub.json" \
    '{at: $at, bouncers: $bouncers[0], machines: $machines[0], hub: $hub[0]}' ||
    log "cannot write $status/snapshot.json"
  rm -rf "$dir"
}

mkdir -p "$status" "$state"
chmod 0755 "$status"
log "watching $desired/generation every ${poll_interval}s"

last_snapshot=0
while true; do
  generation=""
  if [ -f "$desired/generation" ]; then
    generation="$(tr -d '[:space:]' <"$desired/generation" 2>/dev/null)"
  fi
  if [[ $generation =~ ^[0-9]{1,15}$ ]]; then
    generation=$((10#$generation))
    if [ "$generation" != "$(cat "$state/generation" 2>/dev/null)" ]; then
      log "applying generation $generation"
      apply "$generation"
      echo "$generation" >"$state/generation"
    fi
  elif [ -n "$generation" ]; then
    log "ignoring $desired/generation: not an integer"
  fi

  if [ $(($(date +%s) - last_snapshot)) -ge "$snapshot_interval" ]; then
    snapshot
    last_snapshot="$(date +%s)"
  fi
  sleep "$poll_interval"
done
