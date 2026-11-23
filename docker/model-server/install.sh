#!/bin/bash
# Copy one weights file into the veritas-models volume and verify it there: `install.sh <source> <dest> <sha256>`.
# The source directory is bind-mounted read-only at /src. The copy becomes visible only once its hash matches.
set -euo pipefail
src="/src/$1"
dest="/models/$2"
expected="$3"
cp -- "$src" "$dest.part"
actual="$(sha256sum -- "$dest.part" | cut -d' ' -f1)"
if [ "$actual" != "$expected" ]; then
  rm -f -- "$dest.part"
  echo "hash mismatch: expected $expected, got $actual" >&2
  exit 1
fi
chmod 0444 -- "$dest.part"
mv -- "$dest.part" "$dest"
echo "installed $2"
