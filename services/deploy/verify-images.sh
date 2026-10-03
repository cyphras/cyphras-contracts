#!/usr/bin/env bash
# Checks, before docker compose pull or up, that each image a stack runs was built and attested by
# this repository's services release workflow, from the release tag and commit the deployment file
# names. It needs the GitHub CLI, logged in, and read access to the registry the images are in.
#
#   RELEASE_TAG=services-v1.2.3 RELEASE_COMMIT=<commit> \
#   INDEXER_IMAGE=ghcr.io/cyphras/cyphras-contracts/indexer@sha256:... RELAYER_IMAGE=... \
#   KEEPER_IMAGE=... SCREENING_IMAGE=... WATCHER_IMAGE=... ./verify-images.sh
#
# An image variable left unset is skipped, so the host of the off-host watcher sets WATCHER_IMAGE
# only. Any failure stops the script before anything is pulled.
set -euo pipefail
repo=${REPO:-cyphras/cyphras-contracts}
: "${RELEASE_TAG:?}" "${RELEASE_COMMIT:?}"
if ! [[ "$RELEASE_TAG" =~ ^services-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "RELEASE_TAG must be services-vX.Y.Z" >&2
  exit 1
fi
if ! [[ "$RELEASE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "RELEASE_COMMIT must be a full commit hash" >&2
  exit 1
fi
checked=0
for name in INDEXER_IMAGE RELAYER_IMAGE KEEPER_IMAGE SCREENING_IMAGE WATCHER_IMAGE; do
  image=${!name:-}
  if [ -z "$image" ]; then
    continue
  fi
  if ! [[ "$image" =~ ^ghcr\.io/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$ ]]; then
    echo "$name must name a ghcr.io image by its digest" >&2
    exit 1
  fi
  gh attestation verify "oci://$image" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/services-release.yml" \
    --source-ref "refs/tags/$RELEASE_TAG" --source-digest "$RELEASE_COMMIT" \
    --deny-self-hosted-runners > /dev/null
  echo "$name: attested by the release of $RELEASE_TAG"
  checked=$((checked + 1))
done
if [ "$checked" -eq 0 ]; then
  echo "no image to verify" >&2
  exit 1
fi
