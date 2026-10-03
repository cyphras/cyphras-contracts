#!/bin/sh
# Daily backup of one vault's stack: an encrypted dump of every service database, and the
# indexer's event archive, which holds public chain data only, copied off the host as it is.
#
#   NETWORK=testnet ASSET=xlm AGE_RECIPIENT=age1... BACKUP_REMOTE=backup@host:/srv/cyphras ./backup.sh
#
# Dumps are encrypted to the operator's age recipient before they touch the disk. The remote keeps
# them as long as the records require: five years for relay and decision records.
set -eu
cd "$(dirname "$0")"
: "${NETWORK:?}" "${ASSET:?}" "${AGE_RECIPIENT:?}" "${BACKUP_REMOTE:?}"
project="cyphras-$NETWORK-$ASSET"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="backups/$NETWORK/$ASSET/$stamp"
umask 077
mkdir -p "$out"
for service in indexer relayer keeper screening watcher; do
  docker exec "$project-${service}_db-1" pg_dump --format=custom --username="$service" "$service" \
    | age --recipient "$AGE_RECIPIENT" > "$out/$service.dump.age"
done
rsync -a "data/$NETWORK/$ASSET/archive/" "$BACKUP_REMOTE/$NETWORK/$ASSET/archive/"
rsync -a "$out" "$BACKUP_REMOTE/$NETWORK/$ASSET/dumps/"
find "backups/$NETWORK/$ASSET" -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} +
