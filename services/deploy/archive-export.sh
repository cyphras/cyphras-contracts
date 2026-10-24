#!/usr/bin/env bash
# Daily export of one vault's published archive: runs the archive image's export over the indexer's
# raw event archive and writes the result to a directory a web server publishes, appending the
# windows that have closed since the last run. Run verify-images.sh with ARCHIVE_IMAGE first.
#
#   NETWORK=testnet ASSET=xlm ARCHIVE_IMAGE=ghcr.io/cyphras/cyphras-contracts/archive@sha256:... \
#   ARCHIVE_PUBLISH_DIR=/srv/archive/testnet/xlm ./archive-export.sh
#
# The event archive is mounted read only and the container has no network and no capabilities. It
# runs as ARCHIVE_UID (65532 unless set), which must own ARCHIVE_PUBLISH_DIR or be able to write to
# it. A published window is never rewritten with other bytes: if the event archive no longer gives
# a window it already published, the export fails and leaves the directory as it was. Set
# ARCHIVE_VAULT when the deployment file lists several vaults.
set -euo pipefail
cd "$(dirname "$0")"
: "${NETWORK:?}" "${ASSET:?}" "${ARCHIVE_IMAGE:?}" "${ARCHIVE_PUBLISH_DIR:?}"
if ! [[ "$NETWORK" =~ ^[a-z]+$ ]] || ! [[ "$ASSET" =~ ^[a-z0-9]+$ ]]; then
  echo "NETWORK and ASSET must be lowercase names" >&2
  exit 1
fi
if ! [[ "$ARCHIVE_IMAGE" =~ ^[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "ARCHIVE_IMAGE must name an image by its digest" >&2
  exit 1
fi
uid=${ARCHIVE_UID:-65532}
if ! [[ "$uid" =~ ^[0-9]+$ ]] || [ "$uid" -eq 0 ]; then
  echo "ARCHIVE_UID must be a user id other than root" >&2
  exit 1
fi
events="$PWD/data/$NETWORK/$ASSET/archive"
deployment="$(cd ../.. && pwd)/deployments/$NETWORK.json"
for path in "$events" "$ARCHIVE_PUBLISH_DIR"; do
  if ! [ -d "$path" ]; then
    echo "$path is not a directory" >&2
    exit 1
  fi
done
if ! [ -f "$deployment" ]; then
  echo "$deployment is not a file" >&2
  exit 1
fi
vault=()
if [ -n "${ARCHIVE_VAULT:-}" ]; then
  vault=(--vault "$ARCHIVE_VAULT")
fi
exec docker run --rm --pull never --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges:true --user "$uid:$uid" \
  --mount "type=bind,source=$events,target=/in,readonly" \
  --mount "type=bind,source=$deployment,target=/etc/cyphras/deployment.json,readonly" \
  --mount "type=bind,source=$(cd "$ARCHIVE_PUBLISH_DIR" && pwd),target=/out" \
  "$ARCHIVE_IMAGE" export --dir /in --deployment /etc/cyphras/deployment.json --out /out \
  --network "$NETWORK" ${vault[@]+"${vault[@]}"}
