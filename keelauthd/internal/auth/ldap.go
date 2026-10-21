package auth

import (
	"fmt"
	"net/http"
	"strings"
)

// LDAP (Kanidm's, read-only, LDAPS only): what a device needs to be told. Anonymous reads are
// off. Devices bind with a device account of their own (devices.go: bind DN "dn=token", a
// read-only token as the password; they see mail and the POSIX attributes); keelAuth's shared
// read-only account keelauth-ldap (a person whose password only keelauthd knows) is for
// devices that cannot take a long password and need no mail addresses. Users bind with their
// own name and password.

// DevicePasswordHolder stands in the examples where the device account's password goes; the
// page puts the real one in right after it was made (it is shown once).
const DevicePasswordHolder = "DEVICE-PASSWORD"

func (s *Server) ldapOut() (map[string]any, error) {
	st := s.State()
	pw, err := s.box.Open(st.BindPW)
	if err != nil {
		return nil, err
	}
	base := BaseDN(st.Domain)
	host := st.Domain
	addrs := s.addresses()
	// only the name: the certificate has no LAN address in it (it must not change with DHCP,
	// docs/02 section 7.6), so a device that checks the name must reach keelAuth by the domain
	urls := []string{fmt.Sprintf("ldaps://%s:%d", host, st.LDAPPort)}
	return map[string]any{
		"url":       urls[0],
		"urls":      urls,
		"host":      host,
		"addresses": addrs,
		"name_note": fmt.Sprintf("the certificate names %s, not an IP address: put %s in the office DNS (or the device's hosts file) "+
			"pointing at keelAuth's address, or have the device trust keelAuth's CA without checking the name", host, host),
		"port":           st.LDAPPort,
		"tls":            "LDAPS (TLS from the start; no StartTLS, no plain LDAP)",
		"base_dn":        base,
		"devices":        s.devicesOut(),
		"device_bind_dn": DeviceBindDN,
		// the shared account: no mail (Kanidm bounds password binds by the anonymous account's rights)
		"bind_dn":       "name=" + BindAccount + "," + base,
		"bind_password": pw,
		"user_dn":       "name={user}," + base,
		"user_filter":   "(&(class=person)(name={user}))",
		"users_filter":  "(class=person)",
		"group_filter":  "(class=group)",
		"anonymous":     false,
		"attributes": map[string]string{
			"user_name": "name", "display_name": "displayname", "mail": "mail", "member_of": "memberof",
			"group_name": "name", "group_member": "member", "uid_number": "uidnumber", "gid_number": "gidnumber",
			"home": "homedirectory", "object_class_user": "posixaccount", "object_class_group": "posixgroup",
		},
	}, nil
}

func (s *Server) getLDAP(r *http.Request) (any, error) { return s.ldapOut() }

func (s *Server) postLDAPBind(r *http.Request) (any, error) {
	var req struct {
		Reset bool `json:"reset"`
	}
	if err := decodeOpt(r, &req); err != nil {
		return nil, err
	}
	if req.Reset {
		if err := s.ensureBindAccount(true); err != nil {
			return nil, err
		}
	}
	return s.ldapOut()
}

// Example is one ready-to-paste configuration for a kind of LDAP client.
type Example struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	File  string `json:"file"` // where it goes ("" = settings in a web page)
	Text  string `json:"text"`
	Note  string `json:"note,omitempty"`
}

// LDAPExamples are the configurations for the clients an office has (keelOS docs/54 §3.6):
// Linux (sssd), a printer's address book, Dovecot (and Postfix through it), GitLab, Redmine.
// device: the device account's name ("" = a placeholder); the password is DevicePasswordHolder.
func LDAPExamples(domain string, port int, device string) []Example {
	base := BaseDN(domain)
	uri := fmt.Sprintf("ldaps://%s:%d", domain, port)
	pw := DevicePasswordHolder
	if device == "" {
		device = "DEVICE"
	}
	r := strings.NewReplacer("{URI}", uri, "{HOST}", domain, "{PORT}", fmt.Sprint(port), "{BASE}", base, "{BINDDN}", DeviceBindDN,
		"{PW}", pw, "{DEV}", device, "{DOMAIN}", domain)
	ex := []Example{
		{ID: "sssd", Title: "Linux (sssd)", File: "/etc/sssd/sssd.conf", Text: `# Linux logins with keelAuth accounts (Debian/Ubuntu: apt install sssd-ldap libpam-sss libnss-sss)
# device account: {DEV}; keelAuth's CA in /usr/local/share/ca-certificates/keelauth-ca.crt (then update-ca-certificates)
# chmod 600 /etc/sssd/sssd.conf; pam-auth-update --enable mkhomedir; systemctl restart sssd
[sssd]
services = nss, pam
domains = keelauth

[domain/keelauth]
id_provider = ldap
auth_provider = ldap
chpass_provider = none
ldap_uri = {URI}
ldap_search_base = {BASE}
ldap_default_bind_dn = {BINDDN}
ldap_default_authtok = {PW}
ldap_tls_reqcert = demand
ldap_tls_cacert = /etc/ssl/certs/ca-certificates.crt
ldap_schema = rfc2307bis
ldap_user_object_class = posixaccount
ldap_user_name = name
ldap_user_gecos = displayname
ldap_user_uid_number = uidnumber
ldap_user_gid_number = gidnumber
ldap_group_object_class = posixgroup
ldap_group_name = name
ldap_group_gid_number = gidnumber
ldap_group_member = member
override_homedir = /home/%u
default_shell = /bin/bash
cache_credentials = true
`, Note: "Users log in with their keelAuth name and password (ssh, the console). Changing the password on Linux does not work: users change it on keelAuth's page (it must also update the NT hash for Wi-Fi and shares)."},
		{ID: "printer", Title: "Printer / copier address book", Text: `Server (host)           {HOST}
Port                    {PORT}
Security                SSL/TLS (LDAPS)   - not StartTLS
Authentication          Simple
User name / login DN    {BINDDN}
Password                {PW}
Search base             {BASE}
Search filter           (class=person)
Name attribute          displayname
E-mail attribute        mail
Login name attribute    name
`, Note: "The password is a long token (over 300 characters). A device that takes only a short password can use keelAuth's shared read-only account (above) for logins, but then gets no e-mail addresses. Devices that check the certificate need keelAuth's CA and the name " + domain + " in the office DNS."},
		{ID: "dovecot", Title: "Dovecot 2.4 (IMAP logins)", File: "/etc/dovecot/conf.d/auth-ldap.conf.ext", Text: `# conf.d/10-auth.conf: !include auth-ldap.conf.ext (and #!include auth-system.conf.ext)
# users log in with their keelAuth name or their mail address; Dovecot finds them with the
# device account and checks the password by binding as them (ldap_bind = yes)
ldap_uris = {URI}
ldap_auth_dn = {BINDDN}
ldap_auth_dn_password = {PW}
ldap_base = {BASE}
ssl_client_ca_file = /etc/ssl/certs/ca-certificates.crt

passdb ldap {
  ldap_bind = yes
  ldap_filter = (&(class=person)(|(name=%{user | username})(mail=%{user})))
  fields {
    user = %{ldap:name}
  }
}
userdb ldap {
  ldap_filter = (&(class=person)(|(name=%{user | username})(mail=%{user})))
  fields {
    user = %{ldap:name}
    home = /var/vmail/%{user}
    uid = vmail
    gid = vmail
  }
}
`, Note: "Tested with Dovecot 2.4.1 (Debian 13). Dovecot 2.4.1 crashes its auth process when one fields block names the same %{ldap:…} twice: use %{user} for the second."},
		{ID: "dovecot23", Title: "Dovecot 2.3", File: "/etc/dovecot/dovecot-ldap.conf.ext", Text: `# conf.d/10-auth.conf: !include auth-ldap.conf.ext (and comment out auth-system.conf.ext)
uris = {URI}
tls_ca_cert_file = /etc/ssl/certs/ca-certificates.crt
tls_require_cert = demand
dn = {BINDDN}
dnpass = {PW}
auth_bind = yes
base = {BASE}
scope = subtree
pass_filter = (&(class=person)(|(name=%n)(mail=%u)))
pass_attrs = name=user
user_filter = (&(class=person)(|(name=%n)(mail=%u)))
user_attrs = name=user, =home=/var/vmail/%n, =uid=vmail, =gid=vmail
iterate_filter = (class=person)
iterate_attrs = name=user
`, Note: "The same settings in Dovecot 2.3's names (Debian 12, Ubuntu 24.04); not tested."},
		{ID: "postfix", Title: "Postfix (SMTP logins through Dovecot)", File: "/etc/postfix/main.cf", Text: `# Postfix asks Dovecot, Dovecot asks keelAuth: one place for the password.
# /etc/dovecot/conf.d/10-master.conf:
#   service auth {
#     unix_listener /var/spool/postfix/private/auth {
#       mode = 0660
#       user = postfix
#       group = postfix
#     }
#   }
smtpd_sasl_type = dovecot
smtpd_sasl_path = private/auth
smtpd_sasl_auth_enable = yes
smtpd_tls_auth_only = yes

# optional: which addresses exist (mail of keelAuth's users), /etc/postfix/keelauth-users.cf:
#   server_host = {URI}
#   version = 3
#   bind = yes
#   bind_dn = {BINDDN}
#   bind_pw = {PW}
#   search_base = {BASE}
#   query_filter = (&(class=person)(mail=%s))
#   result_attribute = name
#   tls_ca_cert_file = /etc/ssl/certs/ca-certificates.crt
# virtual_mailbox_maps = ldap:/etc/postfix/keelauth-users.cf
`},
		{ID: "gitlab", Title: "GitLab (LDAP)", File: "/etc/gitlab/gitlab.rb", Text: `# keelAuth's CA into /etc/gitlab/trusted-certs/keelauth-ca.crt, then gitlab-ctl reconfigure
gitlab_rails['ldap_enabled'] = true
gitlab_rails['ldap_servers'] = {
  'main' => {
    'label' => 'keelAuth',
    'host' => '{HOST}',
    'port' => {PORT},
    'uid' => 'name',
    'encryption' => 'simple_tls',
    'verify_certificates' => true,
    'bind_dn' => '{BINDDN}',
    'password' => '{PW}',
    'base' => '{BASE}',
    'user_filter' => '(class=person)',
    'active_directory' => false,
    'attributes' => {
      'username' => ['name'],
      'email' => ['mail'],
      'name' => 'displayname'
    }
  }
}
`, Note: "GitLab needs every user's mail address (that is why it uses a device account). For single sign-on instead of a password form, register GitLab under SSO and use its OpenID Connect settings."},
		{ID: "redmine", Title: "Redmine (LDAP)", Text: `Administration → LDAP authentication → New authentication mode
Name                    keelAuth
Host                    {HOST}
Port                    {PORT}     LDAPS (with certificate check)
Account                 {BINDDN}
Password                {PW}
Base DN                 {BASE}
LDAP filter             (class=person)
On-the-fly user creation   yes
Login attribute         name
Firstname attribute     displayname
Lastname attribute      name
Email attribute         mail
`, Note: "Kanidm has no separate first and last name: Redmine shows the display name and the login name. Redmine checks the certificate against the server's trust store: install keelAuth's CA there (update-ca-certificates)."},
	}
	for i := range ex {
		ex[i].Text = r.Replace(ex[i].Text)
	}
	return ex
}

func (s *Server) getLDAPExamples(r *http.Request) (any, error) {
	st := s.State()
	dev := r.URL.Query().Get("device")
	if dev != "" && st.device(dev) == nil {
		return nil, notFound("no device account %q", dev)
	}
	return map[string]any{"examples": LDAPExamples(st.Domain, st.LDAPPort, dev), "password_holder": DevicePasswordHolder}, nil
}
