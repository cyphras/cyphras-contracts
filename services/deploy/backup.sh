#!/usr/bin/env bash
# Daily backup of one vault's stack: an encrypted dump of every service database, and the
# indexer's event archive, which holds public chain data only, copied off the host as it is.
#
#   NETWORK=testnet ASSET=xlm AGE_RECIPIENT=age1... BACKUP_REMOTE=backup@host:/srv/cyphras ./backup.sh
#
# BACKUP_REMOTE is an rsync destination, or with BACKUP_TRANSPORT=rclone an rclone remote and path,
# such as offsite:cyphras, set up beforehand with `rclone config`.
#
# Dumps are encrypted to the operator's age recipient before they touch the disk. The remote keeps
# them as long as the records require: five years for relay and decision records.
# A failed dump must fail the backup, not leave an encrypted empty file that looks valid.
set -euo pipefail
cd "$(dirname "$0")"
: "${NETWORK:?}" "${ASSET:?}" "${AGE_RECIPIENT:?}" "${BACKUP_REMOTE:?}"
transport=${BACKUP_TRANSPORT:-rsync}
case "$transport" in
  rsync | rclone) ;;
  *)
    echo "BACKUP_TRANSPORT must be rsync or rclone" >&2
    exit 1
    ;;
esac
project="cyphras-$NETWORK-$ASSET"
stamp=$(date -u +%Y%m%dT%H%M%SZ)
out="backups/$NETWORK/$ASSET/$stamp"
remote="$BACKUP_REMOTE/$NETWORK/$ASSET"
umask 077
mkdir -p "$out"
for service in indexer relayer keeper screening watcher; do
  extra=()
  # The watcher's funder lookups are forgotten after a week, and must not outlive that in backups.
  if [ "$service" = watcher ]; then
    extra=(--exclude-table-data=watch_funders)
  fi
  docker exec "$project-${service}_db-1" pg_dump --format=custom --username="$service" ${extra[@]+"${extra[@]}"} "$service" \
    | age --recipient "$AGE_RECIPIENT" > "$out/$service.dump.age"
done
if [ "$transport" = rclone ]; then
  rclone copy "data/$NETWORK/$ASSET/archive/" "$remote/archive/"
  rclone copy "$out" "$remote/dumps/$stamp"
else
  rsync -a "data/$NETWORK/$ASSET/archive/" "$remote/archive/"
  rsync -a "$out" "$remote/dumps/"
fi
find "backups/$NETWORK/$ASSET" -mindepth 1 -maxdepth 1 -type d -mtime +7 -exec rm -rf {} +
echo "backup $NETWORK/$ASSET $stamp copied to $remote"
