---
name: keelauth
description: Manage an office's user accounts in keelAuth through its MCP tools (status, user_list, user_get, user_add, user_disable, user_enable, user_reset_password, group_list, group_add, group_members, oidc_list, oidc_create, radius_list, radius_client_add, ldap_info, ldap_device_add, ldap_device_password, ldap_device_delete, ldap_examples, cert_status, backup_now). Use this whenever the user mentions keelAuth, or asks to add, disable or remove an employee's account, reset somebody's password, put people into groups, connect an application to single sign-on (OIDC), let a Wi-Fi access point or VPN use RADIUS, connect a printer, a Linux machine, mail (Dovecot/Postfix), GitLab or Redmine over LDAP, or check whether the office's accounts server is healthy, even if they never say "MCP" and only ask something like "Anna starts on Monday, give her an account" or "Ben left, lock him out". Also use it to connect an assistant to keelAuth for the first time (keel-mcp, token, certificate fingerprint).
---

# keelAuth

keelAuth keeps a small office's user accounts and groups in one place and lets everything else use
them: devices and applications over **LDAP**, web applications over **single sign-on (OIDC)**, Wi-Fi
and VPN over **RADIUS**, and keelNAS's Windows shares. It is a small virtual machine on a keelOS host.
You reach it through MCP tools that keelAuth itself serves. This skill is what those tools cannot tell
you: what the answers mean and where to be careful.

Answer in the user's language. Lead with what they asked for; keep the raw JSON to yourself unless
they want it.

## First: are the tools there?

Look for tools named `status`, `user_list` and so on (usually prefixed by the server's name, for
example `mcp__keelauth__user_list`). If they are missing, the assistant is not connected yet: read
[references/setup.md](references/setup.md) and walk the user through it. Do not try ssh or the
keelAuth web page instead: the token is what the user chose to give you.

## One account, one password, everywhere

Each person has **one** user name and **one** password, and the same pair works for LDAP, SSO, Wi-Fi
and shares. Consequences:

- **Resetting a password changes it everywhere at once.** The person's phone drops off the Wi-Fi and
  their mail client stops until they enter the new one. Say so before you reset, unless the user asked
  for exactly that.
- **Passwords are set only through keelAuth.** Wi-Fi and shares need a special hash of the password
  that keelAuth computes at the moment the password is set. A user with `has_nt: false` was given a
  password some other way; Wi-Fi and shares do not work for them until their password is set again
  here (`user_reset_password`). When you see `has_nt: false`, mention it.
- **A password keelAuth makes is shown once.** `user_add` and `user_reset_password` without a password
  return a generated one (`"password": "Kq7m-…"`). Give it to the user in your answer, clearly, and
  say it is shown only now. With `must_change: true` (the default for a generated password) the person
  picks their own at the first login on keelAuth's page.
- Passwords must be at least 10 characters and not easy to guess. When the user dictates one and it is
  refused (`password refused: too easy to guess`), say why and suggest letting keelAuth make one.

## Names

User and group names are short, lower-case: letters, digits, `-` and `_`, a letter first (`anna`,
`ben-li`, `office`). They are what people type to log in. The full name goes in `display_name`.
Users and groups share one set of names: a group cannot be called like a user. `admin` and names
starting with `idm_` are reserved.

## Checking on keelAuth

For "is everything ok?": call `status`. Look at, most serious first:

| Look at | Worth telling the user when |
|---|---|
| `services.kanidmd` | false: logins over LDAP and SSO fail. Everything else follows from it. |
| `services.radiusd` | false: nobody can join the office Wi-Fi with their account. |
| `alert_list` | always, each in plain words. `missing_nt`: those people need their password set again for Wi-Fi and shares. `no_admin`: nobody can manage keelAuth on its own page. `old_backup` / `no_backup`: offer `backup_now`. |
| `last_backup` | older than two days. |
| `keel.registered` | false: the keelOS host lost contact with keelAuth (its "Accounts" tab will not work). |

```
keelAuth <domain>: <one-line verdict>
- Services: LDAP/SSO <ok|down>, RADIUS <ok|down>
- Accounts: <n> users, <n> groups, <n> SSO applications, <n> RADIUS clients
- Last backup: <time>
- Needs attention: <only if something does>
```

## Common requests

**A new employee.** `user_add` with `name`, `display_name`, `mail` and the `groups` they need (look
at `group_list` first and ask if it is unclear which). Return the generated password once.

**Somebody leaves.** `user_disable`, not deletion: logins stop everywhere at once, and the account
can be looked at or enabled again later. Disabling takes effect on LDAP, SSO and Wi-Fi immediately;
devices may keep an already open session (a Wi-Fi connection until it reconnects). Deleting a user is
not an MCP tool on purpose: point the user to keelAuth's web page if they really want it gone.

**Forgot the password.** `user_reset_password` without a password (keelAuth makes one, `must_change`
true). Hand it over once.

**Make somebody an administrator of keelAuth.** `group_members` on `keelauth-admins`. That gives full
control over every account, so confirm with the user first. The last administrator cannot be removed.

**Connect a web application (SSO).** `oidc_create` with a short `name` (it becomes the client id) and
the application's callback URL in `redirect_urls` (from the application's OIDC settings or docs; ask if
you do not know it). Optionally `scope_group`: only that group may log in. The answer has
`client_id`, `client_secret` and `discovery_url`: these go into the application. The secret is shown
here and on keelAuth's page; tell the user to put it only into the application. Give these settings
too: scopes `openid profile email groups`, client authentication `client_secret_basic`, PKCE S256,
user name claim `preferred_username`. The login page is keelAuth's own (port 8443): browsers must
reach it and trust keelAuth's certificate.

**Office Wi-Fi with personal logins (WPA2/WPA3-Enterprise).** `radius_client_add` with a name and the
access point's IP address (or a network like `192.168.1.0/24` for several). Tell the user what to enter
on the access point: RADIUS server = keelAuth's address (from `status.addresses`), port 1812, the
shared `secret` from the answer, security WPA2/WPA3-Enterprise, accounting off. On phones and laptops:
EAP method PEAP, phase 2 MSCHAPv2, their own keelAuth user name and password; the CA certificate and the
domain to check are in `radius_list` (`ca`, `server_name`): Android 11 and later wants both (install the
CA's `.cer` first), iPhones and Macs take the Apple profile (`https://<keelAuth>/ca/keelauth-ca.mobileconfig`).

**LDAP for a printer, Linux, mail or an application.** `ldap_device_add` with a short name per device
or application (`printer-2f`, `gitlab`): the answer has `bind_dn` (`dn=token`) and the `password`, a
long token shown only this once; it reads users, groups and mail addresses, nothing else. Then
`ldap_examples` with `device` gives ready configurations (Linux sssd, a printer's address book,
Dovecot 2.4 and 2.3, Postfix through Dovecot, GitLab, Redmine): put the password in where it says
`DEVICE-PASSWORD`. Server = keelAuth's domain (from `ldap_info`), port 636 with LDAPS (not StartTLS);
devices that check the certificate need the domain in the office DNS and keelAuth's CA. A device whose
password field is too short for the token can use keelAuth's shared read-only account (on the web page,
LDAP, "Shared read-only account"), but then gets no mail addresses. `ldap_device_password` replaces a
password (the old one stops reading at once, or five minutes after it was made if it is that new),
`ldap_device_delete` removes the account.

**Certificates.** `cert_status` says which certificate is in use (keelAuth's own CA, or the office's
uploaded one), the CA devices must trust with its fingerprints and end dates. Uploading the office's
own certificate and going back are on the web page (Settings, Certificates). Devices fetch the CA
without a login from `https://<keelAuth>/ca/keelauth-ca.crt` (`.cer` for Windows and Android,
`.mobileconfig` for Apple).

## Things to be careful with

- Disabling, resetting a password and admin membership affect real people at once. Do them when the
  user named the person in this conversation, and say what will happen.
- Never put a password, client secret or RADIUS secret anywhere but your answer to the user.
- `backup_now` is always safe. Restoring a backup is not a tool: it rolls every account back; that is
  done on the web page.

## What these tools cannot do

Deleting users or groups, editing SSO applications, the shared LDAP bind account, uploading certificates,
restoring backups, tokens and keelNAS sync keys are on keelAuth's web page (`https://<keelAuth>/`, or
the Accounts tab in keelOS). Say that plainly rather than approximating.

## Reference

- [references/setup.md](references/setup.md): connecting for the first time, the token, the
  fingerprint, keel-mcp's error messages.
- [references/tools.md](references/tools.md): every tool's arguments and a real example of its answer.
