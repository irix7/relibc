#!/bin/sh
# Apply the n32 port to a fresh relibc checkout.
#
# Prerequisite: relibc/ is a clone of
#   https://gitlab.redox-os.org/redox-os/relibc.git at 841d29c0c16dfa5c170f9208e7a6f93696802726
# with submodules initialised.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ ! -d relibc/.git ]; then
    echo "error: $ROOT/relibc is not a git clone" >&2
    exit 1
fi

git -C relibc apply "$ROOT/patches/relibc-n32.patch"

if [ ! -d relibc/vendor/sc ]; then
    mkdir -p relibc/vendor
    cp -a "$ROOT/vendor/sc" relibc/vendor/sc
fi
(
    cd relibc/vendor/sc
    patch -p1 < "$ROOT/patches/sc-n32.patch"
)

echo "applied relibc-n32.patch and sc-n32.patch"
