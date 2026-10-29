#!/bin/sh
# Build a keelAuth image in the builder VM (docs/03 section 2) from the control machine.
#
#   vmbuild.sh [-k] OUTDIR
#
# The builder VM must be running with a fresh output disk as its vtbd1 and answer ssh on
# $KA_BUILDER (default "-p 2280 root@127.0.0.1", key $KA_KEY (default ~/.ssh/id_ed25519)). Takes keelauthd/keelauthd
# (from keelauthd/build.sh) when it exists, else the placeholder. -k: a test build (our ssh key
# for root, console password keel, version ends in -k). Writes OUTDIR/version; the image itself is
# the builder's output disk (copy it with cp --sparse=always).
set -eu
TEST=""
[ "${1:-}" = "-k" ] && { TEST=1; shift; }
OUT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
PORT=${KA_BUILDER_PORT:-2280}
KEY=${KA_KEY:-$HOME/.ssh/id_ed25519}
SSH="ssh -4 -p $PORT -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -q root@127.0.0.1"
SCP="scp -4 -P $PORT -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -q"

DIRTY=""
git -C "$REPO" diff --quiet HEAD -- tools/image keelauthd 2>/dev/null || DIRTY="+"
VER=$(git -C "$REPO" rev-parse --short HEAD)$DIRTY-$(date -u +%Y%m%dT%H%M%SZ)${TEST:+-k}
VER=$(echo "$VER" | tr -d +)   # the version is a name: no "+"; a dirty tree is only reported
[ -n "$DIRTY" ] && echo "note: uncommitted changes in tools/image or keelauthd"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir -p "$W/img"
cp "$HERE/build.sh" "$W/img/"
cp -R "$HERE/files" "$W/img/files"
rm -f "$W/img/files/keelauthd" "$W/img/files/kanidmd" "$W/img/files/kanidmd.version"
# the forked kanidmd (KA_KANIDMD: the binary from the Rust builder, KA_KANIDMD_VERSION: its commit)
if [ -n "${KA_KANIDMD:-}" ] && [ -x "$KA_KANIDMD" ]; then
    cp "$KA_KANIDMD" "$W/img/files/kanidmd"
    echo "${KA_KANIDMD_VERSION:-unknown}" > "$W/img/files/kanidmd.version"
    echo "kanidmd: $KA_KANIDMD (${KA_KANIDMD_VERSION:-unknown})"
elif [ -z "${KA_PORT_KANIDMD:-}" ]; then
    # the port's kanidmd refuses an IP origin (docs/02 section 7.14): an instance keel deployed
    # by address never comes up with it (seen 2026-10-28). Say so instead of building.
    echo "vmbuild.sh: KA_KANIDMD (the forked kanidmd binary) is not set; KA_PORT_KANIDMD=1 builds with the port's anyway" >&2
    exit 1
fi
if [ -x "$REPO/keelauthd/keelauthd" ]; then
    cp "$REPO/keelauthd/keelauthd" "$W/img/files/keelauthd"
    echo "keelauthd: $REPO/keelauthd/keelauthd"
else
    echo "keelauthd: none built, the placeholder goes in"
fi
$SSH 'rm -rf /root/img'
$SCP -r "$W/img" root@127.0.0.1:/root/img
KEYARG=""
if [ -n "$TEST" ]; then
    $SCP "$KEY.pub" root@127.0.0.1:/root/img/test-keys
    KEYARG=/root/img/test-keys
fi
mkdir -p "$OUT"
$SSH "sh /root/img/build.sh vtbd1 $VER $KEYARG" > "$OUT/build-$VER.log" 2>&1 || {
    tail -20 "$OUT/build-$VER.log"; echo "build failed: $OUT/build-$VER.log"; exit 1; }
grep '^== \|^files:' "$OUT/build-$VER.log" | tail -6
echo "$VER" > "$OUT/version"
# the image's package list for the source bundle (keelOS tools/licenses/sources.sh, docs/45 C)
sed -n '/^PACKAGES-BEGIN$/,/^PACKAGES-END$/p' "$OUT/build-$VER.log" | sed '1d;$d' | tr -d '\r' > "$OUT/keelauth-$VER.packages.txt"
echo "built $VER"
