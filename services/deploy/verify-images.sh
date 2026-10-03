#!/usr/bin/env bash
# Checks, before docker compose pull or up, that the release tag the deployment file names is
# signed by a maintainer and points at the release commit, on dev or main, and that each image a
# stack runs was built and attested by this repository's services release workflow from that tag
# and commit. The tagged commit's own workflow is not trusted to have checked the tag: the
# signature is checked here, against the allowed_signers file committed next to this script, which
# must agree with the SERVICES_RELEASE_SIGNERS variable the release workflow checks with. It runs
# in a clone of the repository, and needs the GitHub CLI, logged in as a collaborator, and read
# access to the registry the images are in.
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
here=$(cd "$(dirname "$0")" && pwd)
signers="$here/allowed_signers"
pinned() {
  grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' || true
}
variable=$(gh variable get SERVICES_RELEASE_SIGNERS --repo "$repo")
if [ "$(pinned < "$signers")" != "$(printf '%s\n' "$variable" | pinned)" ]; then
  echo "the committed allowed_signers and the SERVICES_RELEASE_SIGNERS variable disagree" >&2
  exit 1
fi
git -C "$here" fetch --quiet --force origin "refs/tags/$RELEASE_TAG:refs/tags/$RELEASE_TAG" \
  "+refs/heads/dev:refs/remotes/origin/dev" "+refs/heads/main:refs/remotes/origin/main"
if [ "$(git -C "$here" cat-file -t "refs/tags/$RELEASE_TAG")" != tag ]; then
  echo "$RELEASE_TAG is not a signed tag" >&2
  exit 1
fi
git -C "$here" -c gpg.ssh.allowedSignersFile="$signers" verify-tag "refs/tags/$RELEASE_TAG"
# The signed tag must name itself, so a signed tag object of another release cannot stand in.
if ! git -C "$here" cat-file tag "refs/tags/$RELEASE_TAG" | grep -qx "tag $RELEASE_TAG"; then
  echo "$RELEASE_TAG is the signed tag of another release" >&2
  exit 1
fi
if [ "$(git -C "$here" rev-parse "refs/tags/$RELEASE_TAG^{commit}")" != "$RELEASE_COMMIT" ]; then
  echo "$RELEASE_TAG does not point at RELEASE_COMMIT" >&2
  exit 1
fi
if ! git -C "$here" merge-base --is-ancestor "$RELEASE_COMMIT" origin/dev &&
  ! git -C "$here" merge-base --is-ancestor "$RELEASE_COMMIT" origin/main; then
  echo "RELEASE_COMMIT is on neither dev nor main" >&2
  exit 1
fi
echo "$RELEASE_TAG: signed by a maintainer, at $RELEASE_COMMIT on dev or main"
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
