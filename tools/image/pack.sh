#!/bin/sh
# Make a keelAuth package (.kimg, keelNAS docs/05) from a system disk made by build.sh (keelNAS's
# tools/image/pack.sh, adapted; docs/03 section 5). Runs on Linux or
# FreeBSD with zstd, openssl 3 and python3.
#
#   pack.sh RAW VERSION OUTDIR [KEY]
#
# RAW is the image (keelauth-VERSION.raw), VERSION its version (<commit>-<UTC time>[-k]; a
# trailing -k makes it a test package), KEY the ed25519 private key that signs the manifest
# (default ~/.keelos/sign/kimg-ed25519.pem). Writes OUTDIR/keelauth-VERSION.kimg: an uncompressed
# tar of manifest.json (first), manifest.sig and disks/system.raw.zst.
set -eu

RAW=$1
VER=$2
OUT=$3
KEY=${4:-$HOME/.keelos/sign/kimg-ed25519.pem}
[ -f "$KEY" ] || { echo "no signing key $KEY" >&2; exit 1; }
TEST=false
case $VER in *-k) TEST=true ;; esac

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
mkdir "$W/disks"
echo "== compress"
# Level 3: the system pool is zstd-compressed already, -19 saved 5 % and took 6x as long to make
# (docs/05 2.1); LEVEL= overrides.
# No --long: Go's zstd decoder (keel) reads a long-window stream at 1/15 of the speed.
# zstd's frame checksum (on by default) covers the uncompressed data.
LEVEL=${LEVEL:-3}
zstd -q -T0 -$LEVEL --check "$RAW" -o "$W/disks/system.raw.zst"
echo "== manifest"
SIZE=$(stat -c %s "$RAW" 2>/dev/null || stat -f %z "$RAW")
ZSHA=$(openssl dgst -sha256 -r "$W/disks/system.raw.zst" | cut -d' ' -f1)
python3 - "$W/manifest.json" "$VER" "$TEST" "$SIZE" "$ZSHA" <<'EOF'
import json, sys
out, ver, test, size, zsha = sys.argv[1:]
m = {
    "format": 1, "kind": "auth", "name": "keelauth", "version": ver, "test": test == "true",
    "os": {"family": "freebsd", "release": "15.1"}, "arch": "amd64",
    # the LAN NIC; keel adds the second one, its internal link (keelNAS docs/04 section 11)
    "machine": {"firmware": "uefi", "vcpus": {"default": 2, "min": 1},
                "ram_mib": {"default": 512, "min": 512}, "nics": [{"model": "virtio-net"}]},
    "disks": [{"role": "system", "file": "disks/system.raw.zst", "bus": "virtio-blk", "boot": True,
               "size": int(size), "grow": True, "sha256": zsha}],
    # the accounts live on the data disk (docs/03 section 2): not optional
    "user_disks": [{"role": "data", "default_gib": 4, "optional": False}],
    "title": {"en": "keelAuth", "zh": "keelAuth", "ja": "keelAuth"},
    "description": {"en": "The office's accounts in one place: LDAP, single sign-on (OIDC) and RADIUS (Wi-Fi), managed from keelOS.",
                    "zh": "办公室的统一账号：LDAP、单点登录（OIDC）、RADIUS（Wi-Fi），在 keelOS 里管理。",
                    "ja": "オフィスのアカウントを一か所に：LDAP、シングルサインオン（OIDC）、RADIUS（Wi-Fi）。keelOS から管理。"},
}
open(out, "w").write(json.dumps(m, indent=2, ensure_ascii=False) + "\n")
EOF
echo "== sign"
openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$W/manifest.json" -out "$W/manifest.sig"
mkdir -p "$OUT"
F="$OUT/keelauth-$VER.kimg"
tar -C "$W" --format=pax --owner=0 --group=0 --numeric-owner -cf "$F.part" manifest.json manifest.sig disks/system.raw.zst
mv "$F.part" "$F"
ls -l "$F"
