# The keelAuth MCP tools

Arguments and a real answer for each tool (from a test keelAuth, shortened). Users and groups are
named by their short lower-case name. Errors come back as text that starts with `error:`.

## Contents

- status
- user_list, user_get
- user_add
- user_disable, user_enable
- user_reset_password
- group_list, group_add, group_members
- oidc_list, oidc_create
- radius_list, radius_client_add
- ldap_info
- ldap_device_add, ldap_device_password, ldap_device_delete
- ldap_examples
- cert_status
- backup_now

## status

No arguments.

```json
{
  "version": "f8c6dbc", "hostname": "keelauth", "domain": "keelauth.internal",
  "origin": "https://keelauth.internal:8443", "addresses": ["192.0.2.10"],
  "services": {"kanidmd": true, "radiusd": true}, "service_errors": {}, "managed_by_keel": true,
  "counts": {"users": 4, "groups": 2, "oidc": 1, "radius_clients": 0},
  "last_backup": "2026-10-03T07:05:17Z", "alerts": 0, "alert_list": [],
  "keel": {"registered": true, "url": "https://169.254.77.1:443", "time": "2026-10-03T07:12:04Z", "error": ""},
  "ldap_port": 636, "radius_port": 1812, "kanidm_port": 8443, "uptime_s": 103,
  "fingerprint": "C1:2C:1A:…:06:42"
}
```

| Field | Meaning |
|---|---|
| `services.kanidmd` | the account engine (Kanidm): LDAP, SSO and every password check. false = logins fail. |
| `services.radiusd` | FreeRADIUS: Wi-Fi and VPN logins. |
| `service_errors` | for a service that is false, why: its process is not running, or it runs but does not listen on its port. keelAuth starts a vanished service again within a minute. |
| `managed_by_keel` | false: keelAuth was started without keel's seed disk (standalone); keel cannot manage it. |
| `addresses` | keelAuth's addresses on the office network: what access points and devices use. |
| `domain`, `origin` | keelAuth's name; `origin` is the SSO login page. |
| `alert_list` | `[{code, level, object, text}]`. Codes: `engine`, `service_down`, `radius_behind`, `missing_nt` (object: the names), `no_admin`, `no_backup`, `old_backup`. |
| `keel` | only when keelAuth was made by a keelOS host: whether it is in contact. |

## user_list, user_get

`user_list`: no arguments. `user_get`: `name`.

```json
{"name": "bob", "display_name": "Bob Li", "mail": "bob@office.lan", "enabled": true,
 "groups": ["office"], "admin": false, "has_nt": true, "must_change": false,
 "password_set_at": "2026-10-03T07:02:25Z", "uid": 1890001271}
```

| Field | Meaning |
|---|---|
| `enabled` | false: disabled, no logins anywhere. |
| `admin` | member of `keelauth-admins`: manages keelAuth. |
| `has_nt` | false: Wi-Fi and shares do not work for this person until the password is set again in keelAuth. |
| `must_change` | the person must choose their own password at the next login on keelAuth's page. |
| `uid` | the POSIX user id that Linux machines and the NAS see. |

## user_add

`name` (required), `display_name`, `mail`, `groups` (list), `password`, `must_change`.

```json
{"name": "carol", "display_name": "Carol Zhang", "groups": ["office"], "enabled": true,
 "has_nt": true, "must_change": true, "password": "CgC4-WRPJ-8bW3-nCEm",
 "password_set_at": "2026-10-03T07:04:22Z"}
```

`password` is in the answer only when keelAuth made it: hand it over, it is not shown again. A
password given by the user that keelAuth refuses:

```
error: password refused: too short (at least 10 characters)
error: password refused: too easy to guess (a common password)
```

Other errors: `the name "x" is taken (a user or a group)`, `the name "admin" is reserved`,
`no group "y"`, `user name "Anna": lower-case letters, …`.

## user_disable, user_enable

`name`. The answer is the user (as user_get, without uid). Disabling the last administrator fails:
`error: anna is the last administrator: make another one first`.

## user_reset_password

`name` (required), `password`, `must_change` (default true).

```json
{"password": "9kmc-KqYG-EhCn-U9mj", "must_change": true}
```

`password` is empty when the user gave one.

## group_list, group_add, group_members

`group_list`: no arguments.

```json
{"groups": [
  {"name": "keelauth-admins", "description": "keelAuth administrators", "members": ["anna"], "gid": 1939151304, "builtin": true},
  {"name": "office", "description": "", "members": ["anna", "bob", "carol", "dave"], "gid": 1901619902, "builtin": false}]}
```

`group_add`: `name` (required), `description`, `members`. `group_members`: `group` (required),
`add`, `remove` (lists of user names). Both answer with the group:

```json
{"name": "sales", "description": "", "members": ["bob"], "gid": 2061111789, "builtin": false}
```

## oidc_list, oidc_create

`oidc_list`: no arguments.

```json
{"issuer_base": "https://keelauth.internal:8443/oauth2/openid/",
 "clients": [{"name": "gitlab", "client_id": "gitlab", "display_name": "GitLab",
   "landing_url": "https://gitlab.office.lan/",
   "redirect_urls": ["https://gitlab.office.lan/users/auth/openid_connect/callback"],
   "scope_group": "office", "scopes": ["email", "groups", "openid", "profile"], "pkce": true,
   "short_username": true,
   "issuer": "https://keelauth.internal:8443/oauth2/openid/gitlab",
   "discovery_url": "https://keelauth.internal:8443/oauth2/openid/gitlab/.well-known/openid-configuration"}]}
```

`oidc_create`: `name` and `redirect_urls` (required), `display_name`, `landing_url` (default: the
first redirect URL's origin), `scope_group` (default: everybody), `pkce` (default true),
`short_username` (default true: the ID token's `preferred_username` is `alice`; false: `alice@<domain>`).
The answer is the client as above plus `client_secret`.

A client that keelOS registered for its own login (`keel-<host>`, keelOS docs/54 §4.7) also has
`roles` (`{"keel-admins": "admin", "keel-operators": "operate"}`: what each group may do in keelOS),
`roles_by` (`"keelOS"`) and `missing_groups` (those groups keelAuth does not have yet). Do not
delete it or change its redirect URLs: keel keeps them itself. To let someone into keelOS, put them
into one of those groups (`group_members`).

## radius_list, radius_client_add

`radius_list`: no arguments.

```json
{"port": 1812, "addresses": ["192.0.2.10"], "group": "",
 "clients": [{"name": "ap-office", "address": "192.0.2.20", "secret": "0ff08fcfcdeffeb2a9da9457"}],
 "users": 4, "missing_nt": []}
```

`group`: only its members may use RADIUS ("" = every enabled user). `users`: how many can log in.
`missing_nt`: people without the hash Wi-Fi needs (set their password again). Also in the answer (D4):
`server_name` (the domain phones check, e.g. `auth.example.lan`), `eap` `PEAP`, `inner` `MSCHAPv2`,
`office_cert` (the office's own certificate is in use) and `ca` (the CA phones trust: `subject`,
`sha256`, `sha1`, `not_after`).

`radius_client_add`: `name` and `address` (an IP address or a network, required), `secret` (8 to 64
characters, no spaces or quotes; default: keelAuth makes one).

```json
{"name": "ap-office", "address": "192.0.2.20", "secret": "0ff08fcfcdeffeb2a9da9457"}
```

## ldap_info

No arguments. The shared account's password is left out (it is on the web page).

```json
{"host": "auth.example.lan", "url": "ldaps://auth.example.lan:636", "port": 636, "addresses": ["10.0.2.20"],
 "base_dn": "dc=auth,dc=example,dc=lan", "device_bind_dn": "dn=token",
 "devices": [{"name": "printer-2f", "description": "Copier, 2nd floor", "created": "2026-10-03T10:28:32Z",
              "password_set_at": "2026-10-03T10:28:46Z", "bind_dn": "dn=token"}],
 "bind_dn": "name=keelauth-ldap,dc=auth,dc=example,dc=lan", "users_filter": "(class=person)",
 "user_filter": "(&(class=person)(name={user}))", "group_filter": "(class=group)",
 "attributes": {"user_name": "name", "display_name": "displayname", "mail": "mail", "member_of": "memberof",
                "group_name": "name", "group_member": "member", "uid_number": "uidnumber", "gid_number": "gidnumber",
                "object_class_user": "posixaccount", "object_class_group": "posixgroup"},
 "name_note": "the certificate names auth.example.lan, not an IP address: …", "anonymous": false}
```

`bind_dn` is keelAuth's shared read-only account (short password, no mail addresses); devices
normally use a device account (`device_bind_dn` and its own password).

## ldap_device_add, ldap_device_password, ldap_device_delete

`ldap_device_add`: `name` (required, lower-case like a user name; not a user's or group's name),
`description`.

```json
{"name": "gitlab", "description": "GitLab server", "created": "2026-10-03T10:32:20Z",
 "password_set_at": "2026-10-03T10:32:20Z", "bind_dn": "dn=token",
 "password": "eyJhbGciOiJIUzI1NiIsImtpZCI6IjQ1ZjAwYTAy…(about 350 characters)"}
```

The password is shown only here. `ldap_device_password` (`name`) answers the same with a new
password; `ldap_device_delete` (`name`) answers `{}`. Errors: `there is a device account "gitlab"
already`, `the name "alice" is taken (a user, group or another account has it)`.

## ldap_examples

`device` (optional): a device account's name to write into the examples.

```json
{"password_holder": "DEVICE-PASSWORD",
 "examples": [{"id": "sssd", "title": "Linux (sssd)", "file": "/etc/sssd/sssd.conf", "text": "[sssd]\nservices = nss, pam\n…", "note": "…"},
              {"id": "printer", …}, {"id": "dovecot", "title": "Dovecot 2.4 (IMAP logins)", …}, {"id": "dovecot23", …},
              {"id": "postfix", …}, {"id": "gitlab", …}, {"id": "redmine", …}]}
```

Give the user the one they asked for, with `DEVICE-PASSWORD` left for them to fill in (or filled in
when the password came from `ldap_device_add` in this conversation).

## cert_status

No arguments.

```json
{"in_use": "own", "fingerprint": "4F:98:20:55:…",
 "anchor": {"subject": "CN=keelAuth CA auth.example.lan,O=keelAuth", "not_after": "2046-10-03T10:13:51Z", "days_left": 7304,
            "sha256": "92:3D:E7:97:…", "sha1": "4E:68:D0:6F:…", "key": "RSA 3072", "ca": true},
 "server": {"subject": "CN=auth.example.lan,O=keelAuth", "names": ["auth.example.lan", "keelauth", "localhost", "127.0.0.1", "169.254.77.5"],
            "not_after": "2028-10-03T10:13:51Z", "days_left": 730, "key": "ECDSA P-256", …},
 "radius": {"subject": "CN=auth.example.lan,O=keelAuth", "key": "RSA 2048", …},
 "own_ca": {…}}
```

`in_use` `office`: the office's own certificate (uploaded on the web page), with `office_uploaded`;
`anchor` is then the office's root. `fingerprint` is the web page's certificate (keel-mcp's
`--fingerprint`): it changes when the office's certificate is taken or given back.

## backup_now

No arguments.

```json
{"name": "keelauth-20261003T071249Z.tar.gz", "time": "2026-10-03T07:12:49Z", "size": 33399}
```
