#!/bin/bash
set -euo pipefail
base=/opt/codeql
cli="$base/codeql/codeql"
py="$base/python/bin/python3"
if [[ -x "$cli" && -x "$py" ]]; then
  exit 0
fi
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends ca-certificates curl
mkdir -p "$base"
# Download into the cache volume, not /tmp: /tmp in scanner containers is a 512 MB tmpfs
# and the CodeQL bundle is larger (curl then fails with "(23) Failure writing output").
# Leftovers of an interrupted download are removed first.
rm -rf "$base"/.download.* 2>/dev/null || true
tmp=$(mktemp -d "$base/.download.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
if [[ ! -x "$py" ]]; then
  curl -fsSL -o "$tmp/python.tar.gz" "https://github.com/astral-sh/python-build-standalone/releases/download/20261026/cpython-3.12.16%2B20261026-x86_64-unknown-linux-gnu-install_only.tar.gz"
  echo "6a79e922e50006b601f29e688407659da1c2b86ebcd4e9c7254cf234be8b89de  $tmp/python.tar.gz" | sha256sum -c -
  tar -xzf "$tmp/python.tar.gz" -C "$base"
fi
if [[ ! -x "$cli" ]]; then
  curl -fsSL -o "$tmp/codeql.tar.gz" "https://github.com/github/codeql-action/releases/download/codeql-bundle-v2.27.3/codeql-bundle-linux64.tar.gz"
  echo "64518dc413c8e7b5733fee2489e830a899bb1e3f28c8873b5869d5cc90164c5c  $tmp/codeql.tar.gz" | sha256sum -c -
  tar -xzf "$tmp/codeql.tar.gz" -C "$base"
fi
test -x "$cli"
test -x "$py"
