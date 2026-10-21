#!/bin/sh
# Make a keelAuth system disk. Runs as root on FreeBSD 15.x (keelNAS's tools/image/build.sh, adapted).
#
#   build.sh DISK VERSION [AUTHORIZED_KEYS]        (tools/image/files next to it as ./files)
#
# ./files/keelauthd, the binary from keelauthd/build.sh, becomes /usr/local/sbin/keelauthd; without
# it the placeholder ./files/keelauthd-placeholder.sh does (a shell script that only writes the
# Kanidm and FreeRADIUS configuration and starts them, docs/03 section 4), so a rebuild with the
# binary in ./files picks the real one.
#
# DISK is a whole disk (vtbd1) that becomes the image: an ESP, swap and a ZFS pool "kasys" with one
# boot environment per version (kasys/ROOT/VERSION). The data disk (Kanidm's database, keelauthd's
# data, the certificates) is not part of the image: rc.d/keelauth makes its pool "kadata" at the
# first boot and mounts it on /data (docs/03 section 2).
# With AUTHORIZED_KEYS it is a test build: root logs in over ssh with those keys and with the
# password "keel" on the console.
set -eu

DISK=$1
VER=$2
KEYS=${3:-}
POOL=kasys
MNT=/mnt/ka
FILES=$(dirname "$0")/files   # copied next to this script
# FreeBSD-flua: rc.d/keelauth reads the seed's JSON with flua's ucl module.
# FreeBSD-openssl: the openssl command (the placeholder makes the CA with it).
# FreeBSD-libexecinfo, FreeBSD-kerberos-lib: FreeRADIUS's libraries need them.
BASE="FreeBSD-set-minimal FreeBSD-kernel-generic FreeBSD-bootloader FreeBSD-zfs FreeBSD-ssh FreeBSD-flua FreeBSD-openssl FreeBSD-libexecinfo FreeBSD-kerberos-lib"
# No kanidm-client: keelauthd talks to Kanidm over REST and uses kanidmd's own recover-account.
PORTS="kanidm-server freeradius3"

say() { echo "== $*"; }
PKG="pkg --rootdir $MNT -o ASSUME_ALWAYS_YES=yes -o IGNORE_OSVERSION=yes -o REPOS_DIR=/etc/pkg,/usr/local/etc/pkg/repos"

say "partitions on $DISK"
zpool export $POOL 2>/dev/null || true
gpart destroy -F "$DISK" 2>/dev/null || true
# Old blocks of an earlier build would end up in the package (keelNAS docs/05 2.1): give the whole
# disk back first (works when the builder's output disk has discard=unmap; else start with a new disk).
trim -f "$DISK" >/dev/null 2>&1 || true
gpart create -s gpt "$DISK"
gpart add -t efi -s 260m -l kaefi "$DISK"
gpart add -t freebsd-swap -s 1g -l kaswap "$DISK"
gpart add -t freebsd-zfs -l kasys "$DISK"
newfs_msdos -F 32 -c 1 -L KAEFI "/dev/gpt/kaefi" >/dev/null

say "pool $POOL, boot environment $VER"
mkdir -p $MNT
zpool create -f -o ashift=12 -o altroot=$MNT -o cachefile=none \
    -O compression=zstd -O atime=off -O mountpoint=none $POOL gpt/kasys
zfs create -o mountpoint=none $POOL/ROOT
zfs create -o mountpoint=/ -o canmount=noauto "$POOL/ROOT/$VER"
zfs mount "$POOL/ROOT/$VER"
# Outside the boot environments: what must stay when the version changes. The accounts are on the
# data disk, not here.
zfs create -o mountpoint=/var/log $POOL/log
zpool set bootfs="$POOL/ROOT/$VER" $POOL

say "base system"
mkdir -p $MNT/usr/share/keys
cp -R /usr/share/keys/pkg* $MNT/usr/share/keys/
$PKG install -r FreeBSD-base $BASE
say "ports packages"
$PKG install -r FreeBSD-ports $PORTS
$PKG clean -a >/dev/null 2>&1 || true
rm -rf $MNT/var/cache/pkg/* $MNT/var/db/pkg/repos

say "shared libraries"
# ldd needs the run-time linker's hints, which rc.d/ldconfig makes at boot: make them here, for the check only.
chroot $MNT /bin/sh -c '/sbin/ldconfig -elf /lib /usr/lib /usr/local/lib $(cat /usr/local/libdata/ldconfig/* 2>/dev/null)'
MISSING=$(chroot $MNT /bin/sh -c 'find /usr/local/bin /usr/local/sbin /usr/local/lib /usr/local/libexec /usr/bin /usr/sbin /bin /sbin -type f \( -perm -u+x -o -name "*.so*" \) 2>/dev/null | xargs ldd 2>/dev/null' | grep "not found" | sed 's/ (.*//' | sort -u || true)
rm -f $MNT/var/run/ld-elf.so.hints
if [ -n "$MISSING" ]; then
    echo "missing shared libraries:"; echo "$MISSING"
    zpool export $POOL
    exit 1
fi

say "FreeRADIUS"
# keelauthd writes clients.conf and mods-config/files/authorize (docs/02 section 2) and starts
# radiusd; here only what does not change: EAP with keelAuth's own certificate (PEAP-MSCHAPv2 for
# Wi-Fi), and the package's test certificates out (every install of the package has the same kind).
RADDB=$MNT/usr/local/etc/raddb
TLS=/data/keelauth/tls
# Under --rootdir the package's install script neither copies the sample configuration nor sets
# the user: do both here. radiusd runs as freeradius and reads its own RSA certificate's key
# (radius.key, root:freeradius 0640, keelauthd's choice; docs/02 section 7.6). It reads the "use" copies
# (use-radius.key, use-radius-chain.pem): keelAuth's own or the office's certificate (docs/02 section 7.10).
[ -d $RADDB ] || cp -Rp $MNT/usr/local/share/examples/freeradius/raddb $RADDB
sed -i '' -e 's/^#*[[:space:]]*user = .*/user = freeradius/' -e 's/^#*[[:space:]]*group = .*/group = freeradius/' $RADDB/radiusd.conf
grep -q '^user = freeradius' $RADDB/radiusd.conf
mkdir -p $MNT/var/run/radiusd $MNT/var/log/radacct
touch $MNT/var/log/radius.log
chroot $MNT chown -R freeradius:freeradius /usr/local/etc/raddb /var/run/radiusd /var/log/radacct /var/log/radius.log
rm -f $RADDB/certs/*.pem $RADDB/certs/*.key $RADDB/certs/*.crt $RADDB/certs/*.csr $RADDB/certs/*.p12 \
    $RADDB/certs/*.der $RADDB/certs/*.crl $RADDB/certs/dh $RADDB/certs/index.txt* $RADDB/certs/serial*
sed -i '' \
    -e "1,40s|^\([[:space:]]*default_eap_type = \)md5|\1peap|" \
    -e "s|^\([[:space:]]*\)private_key_password = whatever|\1#private_key_password = whatever|" \
    -e "s|^\([[:space:]]*private_key_file = \).*|\1$TLS/use-radius.key|" \
    -e "s|^\([[:space:]]*certificate_file = \).*|\1$TLS/use-radius-chain.pem|" \
    -e "s|^\([[:space:]]*ca_file = \).*|\1$TLS/ca.crt|" \
    $RADDB/mods-available/eap
grep -q "default_eap_type = peap" $RADDB/mods-available/eap
grep -q "certificate_file = $TLS/use-radius-chain.pem" $RADDB/mods-available/eap
printf '# keelauthd writes this file (keelAuth docs/02).\n' > $RADDB/clients.conf
printf '# keelauthd writes this file (keelAuth docs/02).\n' > $RADDB/mods-config/files/authorize

say "trim"
# What nothing in the appliance uses (docs/03 section 2, "裁剪"); the library check below runs again.
# - Python: only talloc's Python bindings (pytalloc) want it; libtalloc itself (FreeRADIUS) does not.
# - Perl: only FreeRADIUS's rlm_perl (not enabled) and a few of its helper scripts (radsqlrelay,
#   rad_counter, radsecret) use it.
$PKG delete -f python312 perl5 >/dev/null
rm -f $MNT/usr/local/lib/libpytalloc-util* $MNT/usr/local/libdata/pkgconfig/pytalloc-util*
rm -rf $MNT/usr/local/lib/python3* $MNT/usr/local/lib/perl5 $MNT/usr/local/lib/freeradius-*/rlm_perl.so \
    $RADDB/mods-available/perl $RADDB/mods-config/perl \
    $MNT/usr/local/bin/radsqlrelay $MNT/usr/local/bin/rad_counter $MNT/usr/local/bin/radsecret
# documentation, manuals, headers, static libraries, examples (raddb is copied already), locales
rm -rf $MNT/usr/local/share/doc $MNT/usr/local/share/man $MNT/usr/local/man $MNT/usr/local/share/examples \
    $MNT/usr/local/include $MNT/usr/local/share/locale $MNT/usr/local/share/licenses \
    $MNT/usr/share/doc $MNT/usr/share/man $MNT/usr/share/examples $MNT/usr/share/games $MNT/usr/include \
    $MNT/usr/share/i18n $MNT/usr/lib/debug $MNT/usr/tests
find $MNT/usr/share/locale -mindepth 1 -maxdepth 1 ! -name C.UTF-8 ! -name 'en_US.UTF-8' -exec rm -rf {} + 2>/dev/null || true
find $MNT/usr/lib $MNT/lib $MNT/usr/local/lib -name '*.a' -delete
find $MNT/boot/kernel -name '*.symbols' -delete
chroot $MNT /bin/sh -c '/sbin/ldconfig -elf /lib /usr/lib /usr/local/lib $(cat /usr/local/libdata/ldconfig/* 2>/dev/null)'
MISSING=$(chroot $MNT /bin/sh -c 'find /usr/local/bin /usr/local/sbin /usr/local/lib /usr/local/libexec /usr/bin /usr/sbin /bin /sbin -type f \( -perm -u+x -o -name "*.so*" \) 2>/dev/null | xargs ldd 2>/dev/null' | grep "not found" | sed 's/ (.*//' | sort -u || true)
rm -f $MNT/var/run/ld-elf.so.hints
if [ -n "$MISSING" ]; then
    echo "missing shared libraries after the trim:"; echo "$MISSING"
    zpool export $POOL
    exit 1
fi
du -sh $MNT/usr/local $MNT/usr $MNT/boot 2>/dev/null

say "configuration"
echo "$VER" > $MNT/etc/keelauth-version
printf '%s\n' 'zfs_load="YES"' 'autoboot_delay="2"' 'boot_multicons="YES"' 'console="efi,comconsole"' \
    > $MNT/boot/loader.conf
cat > $MNT/etc/rc.conf <<'RC'
hostname="keelauth"
ifconfig_vtnet0="DHCP"   # the LAN NIC; rc.d/keelauth sets the seed's fixed address instead (docs/03 section 3)
background_dhclient="YES"   # the boot does not wait for the LAN's DHCP: keel's internal link comes first
# nor for a default route: rc.d/defaultroute reads ifconfig_vtnet0="DHCP" above (not rc.d/keelauth's
# rc.conf.d/netif) and waited 30 s at every boot with the seed's fixed address, before rc.d/routing sets it
defaultroute_delay="0"
zfs_enable="YES"
sshd_enable="YES"
sendmail_enable="NONE"
syslogd_flags="-ss"
dumpdev="NO"
clear_tmp_enable="YES"
keelauthd_enable="YES"
# kanidmd and radiusd are not enabled: keelauthd writes their configuration and starts them (docs/02 section 2).
RC
printf '%s\n' '/dev/gpt/kaswap  none  swap  sw  0  0' 'tmpfs            /tmp  tmpfs rw,mode=1777  0  0' \
    > $MNT/etc/fstab
# radtest and FreeRADIUS want the host's own name to resolve.
printf '127.0.0.1\t\tkeelauth\n' >> $MNT/etc/hosts
mkdir -p $MNT/data
install -m 555 "$FILES/rc.d-keelauth" $MNT/etc/rc.d/keelauth
install -m 555 "$FILES/rc.d-keelauthd" $MNT/usr/local/etc/rc.d/keelauthd
# keelauthd (built by keelauthd/build.sh, put next to this script as ./files/keelauthd).
if [ -f "$FILES/keelauthd" ]; then
    install -m 555 "$FILES/keelauthd" $MNT/usr/local/sbin/keelauthd
    say "keelauthd: $($MNT/usr/local/sbin/keelauthd version 2>/dev/null || echo installed)"
else
    install -m 555 "$FILES/keelauthd-placeholder.sh" $MNT/usr/local/sbin/keelauthd
    say "no ./files/keelauthd: the placeholder is /usr/local/sbin/keelauthd"
fi
if [ -n "$KEYS" ]; then
    mkdir -p $MNT/root/.ssh
    cp "$KEYS" $MNT/root/.ssh/authorized_keys
    chmod 700 $MNT/root/.ssh; chmod 600 $MNT/root/.ssh/authorized_keys
    echo "PermitRootLogin yes" >> $MNT/etc/ssh/sshd_config
    echo keel | pw -R $MNT usermod root -h 0
fi

say "boot loader"
mount -t msdosfs /dev/gpt/kaefi /media
mkdir -p /media/EFI/BOOT
cp $MNT/boot/loader.efi /media/EFI/BOOT/BOOTX64.EFI
umount /media

say "result"
du -sh $MNT 2>/dev/null | awk '{print "files: " $1}'
zfs list -o name,used,refer -r $POOL
# What the package cache and the like used is free now but still written on the disk: give it
# back too (holes in the image with discard=unmap), or it ends up in the package.
zpool trim -w $POOL 2>/dev/null || true
zpool export $POOL
say "done: $VER on $DISK"
