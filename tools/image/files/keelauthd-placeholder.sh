#!/bin/sh
# Stand-in for keelauthd while the real one (keelauthd/, docs/02) is not built: does only what the
# image needs to be tested (docs/03 section 4): the certificates, Kanidm's configuration, an empty
# FreeRADIUS configuration, and starts kanidmd and radiusd, with the paths of docs/02 section 2.
# No API, no accounts. tools/image/build.sh installs it as /usr/local/sbin/keelauthd when
# tools/image/files/keelauthd (the real binary) is missing.
set -u

D=/data/keelauth
TLS=$D/tls
RADDB=/usr/local/etc/raddb

say() { echo "keelauthd (placeholder): $*"; logger -t keelauthd "$*"; }

# the seed's "domain" (docs/02 section 4), or keelauth.internal
seed_domain()
{
	local d head
	for d in $(sysctl -n kern.disks); do
		head=$(dd if=/dev/$d bs=4096 count=1 2>/dev/null | tr -d '\000')
		case $head in *keelauth_seed*) ;; *) continue ;; esac
		echo "$head" | /usr/libexec/flua -e '
local ucl = require("ucl"); local p = ucl.parser()
if p:parse_string(io.read("a")) then
	local s = p:get_object()
	if type(s) == "table" and type(s.domain) == "string" and s.domain:match("^[%w][%w%.%-]*$") then print(s.domain) end
end'
		return
	done
}

addresses()
{
	ifconfig -a inet | awk '$1 == "inet" && $2 != "127.0.0.1" {print $2}'
}

make_tls()
{
	local domain=$1 san a
	[ -f $TLS/chain.pem ] && return 0
	mkdir -p $TLS
	san="DNS:$domain,DNS:keelauth"
	for a in $(addresses); do san="$san,IP:$a"; done
	openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/O=keelAuth/CN=keelAuth CA ($domain)" \
	    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" \
	    -keyout $TLS/ca.key -out $TLS/ca.crt 2>/dev/null || return 1
	openssl req -newkey rsa:3072 -nodes -subj "/O=keelAuth/CN=$domain" -keyout $TLS/server.key -out $TLS/server.csr 2>/dev/null || return 1
	printf '%s\n' "basicConstraints=critical,CA:FALSE" "keyUsage=critical,digitalSignature,keyEncipherment" \
	    "extendedKeyUsage=serverAuth" "subjectAltName=$san" > $TLS/server.ext
	openssl x509 -req -in $TLS/server.csr -CA $TLS/ca.crt -CAkey $TLS/ca.key -CAcreateserial -days 825 \
	    -extfile $TLS/server.ext -out $TLS/server.crt 2>/dev/null || return 1
	cat $TLS/server.crt $TLS/ca.crt > $TLS/chain.pem
	rm -f $TLS/server.csr $TLS/server.ext
	# FreeRADIUS's certificate (keelauthd makes a separate RSA 2048 one; here the same RSA pair)
	cp $TLS/server.key $TLS/radius.key; cp $TLS/chain.pem $TLS/radius-chain.pem
	chmod 755 $TLS
	chown root:kanidmd $TLS/server.key; chown root:freeradius $TLS/radius.key
	chmod 600 $TLS/ca.key; chmod 640 $TLS/server.key $TLS/radius.key
	say "made the CA and the server certificate ($san)."
}

serve()
{
	local domain
	if [ ! -d /data ] || ! mount | grep -q ' on /data '; then
		say "WARNING: /data is not a mount point."
	fi
	mkdir -p $D $D/kanidm $D/backups; chmod 700 $D
	chown kanidmd:kanidmd $D/kanidm; chmod 750 $D/kanidm
	# root's directory, but kanidmd must reach its database and certificate below it
	chmod 711 $D
	if [ -f $D/domain ]; then
		domain=$(cat $D/domain)
	else
		domain=$(seed_domain)
		domain=${domain:-keelauth.internal}
		echo "$domain" > $D/domain
	fi
	make_tls "$domain" || say "could not make the certificates."
	# LDAPS on 636 as the user kanidmd (docs/02 section 2)
	sysctl net.inet.ip.portrange.reservedhigh=0 >/dev/null
	cat > /usr/local/etc/kanidm/config.toml <<EOF
# Written by keelauthd (placeholder) at every start; do not edit.
version = "2"
bindaddress = "0.0.0.0:8443"
ldapbindaddress = "0.0.0.0:636"
db_path = "$D/kanidm/kanidm.db"
db_fs_type = "zfs"
tls_chain = "$TLS/chain.pem"
tls_key = "$TLS/server.key"
domain = "$domain"
origin = "https://$domain:8443"
EOF
	if [ ! -f $D/radius-localhost.secret ]; then
		openssl rand -hex 12 > $D/radius-localhost.secret; chmod 600 $D/radius-localhost.secret
	fi
	cat > $RADDB/clients.conf <<EOF
# Written by keelauthd (placeholder)
client localhost {
	ipaddr = 127.0.0.1
	secret = $(cat $D/radius-localhost.secret)
}
EOF
	[ -f $D/authorize ] || printf '# Written by keelauthd (placeholder)\n' > $D/authorize
	chmod 600 $D/authorize
	install -m 640 -o root -g freeradius $D/authorize $RADDB/mods-config/files/authorize   # NT hashes
	chown root:freeradius $RADDB/clients.conf; chmod 640 $RADDB/clients.conf   # shared secrets
	service kanidmd onestatus >/dev/null 2>&1 || service kanidmd onestart
	service radiusd onestatus >/dev/null 2>&1 || service radiusd onestart
	say "running (domain $domain)."
	trap 'exit 0' TERM INT
	while :; do sleep 3600 & wait $!; done
}

case ${1:-} in
serve) serve ;;
version) echo "placeholder" ;;
*) echo "usage: keelauthd serve|version (placeholder)" >&2; exit 2 ;;
esac
