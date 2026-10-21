# keelAuth

keelAuth is the office's account server as a small virtual machine on [keelOS](https://keelos.dev):
one place for people and groups, reachable the ways office things expect. LDAP (printers, Linux
machines, applications), single sign-on with OIDC (web applications, keelOS's own page), RADIUS
(Wi-Fi and VPN with PEAP-MSCHAPv2), and keelNAS's SMB shares. It is not a Windows domain
controller. The engine is [Kanidm](https://kanidm.com); `keelauthd` wraps it with a settings
file, an HTTP API, its own web page and an MCP endpoint, so an AI assistant can manage accounts
too.

Status: early. Deployed from keelOS's market and managed from the host's Accounts tab; expect
changes.

## What is here

| Path | What |
|---|---|
| `keelauthd/` | the management program (Go, standard library only): accounts, groups, OIDC clients, RADIUS clients, device (LDAP) accounts, certificates, backups, the web page, the API and `/mcp` |
| `tools/image/` | builds the system disk from FreeBSD packages (Kanidm, FreeRADIUS): a ZFS root with one boot environment per version |
| `tools/oidc-test/` | a minimal OIDC relying party to check a client registration |
| `skills/keelauth/` | the skill an AI assistant loads to manage keelAuth over MCP |

## The system

- FreeBSD 15.x on a virtual disk; ZFS root, one boot environment per version, so an upgrade is
  tried once and falls back by itself. Account data lives on a separate data disk.
- Kanidm for LDAP and OIDC, FreeRADIUS for RADIUS. Passwords change only through keelauthd,
  which keeps the NT hash (encrypted) that SMB and PEAP-MSCHAPv2 need.
- `keelauthd` owns the settings; Kanidm's and FreeRADIUS's configuration is generated from them.

## Releases

Each version is a signed package `keelauth-VERSION.kimg` under [Releases](../../releases). keelOS
lists the newest one in its Market and downloads it from there; a package can also be uploaded to a
keelOS host by hand. keelOS takes only packages signed with a key it trusts, so a package you build
yourself needs your own key in the host's `trusted_keys`.

## Building

`keelauthd/build.sh` builds the program (any machine with Go). `tools/image/build.sh DISK VERSION`
makes the system disk; it runs as root on FreeBSD 15.x and installs FreeBSD's base packages,
Kanidm and FreeRADIUS onto DISK.

## License

BSD 2-Clause, see [LICENSE](LICENSE). Kanidm (MPL 2.0) and FreeRADIUS (GPL) are separate programs
under their own licenses; the image takes them unmodified from FreeBSD's package repository.
