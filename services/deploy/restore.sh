#!/usr/bin/env bash
# Restores one service database from an encrypted dump. By default it restores into a database of
# its own beside the live one, <service>_restore, as the quarterly restore test does, and leaves the
# live database alone. To replace the live database, as after losing it, stop that service first
# and set TARGET=live.
#
#   NETWORK=testnet ASSET=xlm AGE_IDENTITY=~/.config/age/cyphras.key ./restore.sh indexer indexer.dump.age
set -euo pipefail
cd "$(dirname "$0")"
: "${NETWORK:?}" "${ASSET:?}" "${AGE_IDENTITY:?}"
service=${1:?service}
dump=${2:?dump}
project="cyphras-$NETWORK-$ASSET"
container="$project-${service}_db-1"
options=(--no-owner --username="$service")
case "${TARGET:-scratch}" in
  scratch)
    db="${service}_restore"
    docker exec "$container" dropdb --if-exists --username="$service" "$db"
    docker exec "$container" createdb --username="$service" "$db"
    ;;
  live)
    if docker ps --format '{{.Names}}' | grep -qx "$project-$service-1"; then
      echo "stop the $service service before restoring over its database" >&2
      exit 1
    fi
    db=$service
    options+=(--clean --if-exists)
    ;;
  *)
    echo "TARGET must be scratch or live" >&2
    exit 1
    ;;
esac
age --decrypt --identity "$AGE_IDENTITY" "$dump" \
  | docker exec -i "$container" pg_restore "${options[@]}" --dbname="$db"
echo "restored $dump into $db"
