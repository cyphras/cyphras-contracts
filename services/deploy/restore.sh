#!/usr/bin/env bash
# Restores one service database from an encrypted dump, for a rebuild or the quarterly restore
# test, which should restore into a scratch stack rather than a live one.
#
#   NETWORK=testnet ASSET=xlm AGE_IDENTITY=~/.config/age/cyphras.key ./restore.sh indexer indexer.dump.age
set -euo pipefail
cd "$(dirname "$0")"
: "${NETWORK:?}" "${ASSET:?}" "${AGE_IDENTITY:?}"
service=${1:?service}
dump=${2:?dump}
age --decrypt --identity "$AGE_IDENTITY" "$dump" \
  | docker exec -i "cyphras-$NETWORK-$ASSET-${service}_db-1" pg_restore --clean --if-exists --no-owner --username="$service" --dbname="$service"
