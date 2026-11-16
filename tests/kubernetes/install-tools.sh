#!/usr/bin/env bash
# Download pinned kind and kubectl into a new, empty directory and verify their SHA-256 digests.
# linux/amd64 only (the CI runner). Installs nothing globally; never run as root.
# Origins and licences: tests/kubernetes/README.md and provenance/register.json.
set -euo pipefail

KIND_VERSION=v0.33.0
KIND_SHA256=aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d
KUBECTL_VERSION=v1.37.0
KUBECTL_SHA256=6129359f4e1f3848a5572ccb0b26cf28b8ca08cef38c95a765b2f64a2c961a2f

dest="${1:?usage: install-tools.sh NEW_EMPTY_DIRECTORY}"
if [ "$(uname -s)/$(uname -m)" != "Linux/x86_64" ]; then
  echo "Pinned digests are recorded for linux/amd64 only." >&2
  exit 2
fi
if [ -e "$dest" ] && [ -n "$(ls -A "$dest")" ]; then
  echo "Refusing to write into non-empty $dest." >&2
  exit 2
fi
mkdir -p "$dest"

fetch() {
  local name="$1" url="$2" sha="$3"
  curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 --retry 3 \
    --output "$dest/$name.download" "$url"
  echo "$sha  $dest/$name.download" | sha256sum --check --strict --quiet -
  chmod 0755 "$dest/$name.download"
  mv "$dest/$name.download" "$dest/$name"
}

fetch kind "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-linux-amd64" "$KIND_SHA256"
fetch kubectl "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" "$KUBECTL_SHA256"
"$dest/kind" version
"$dest/kubectl" version --client
