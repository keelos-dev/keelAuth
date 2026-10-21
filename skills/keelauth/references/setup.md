# Connecting an assistant to keelAuth

Read this when the keelAuth tools are missing or a connection fails. The user does these steps; you
explain and check.

## Contents

1. How the pieces fit
2. The token
3. The certificate fingerprint
4. keel-mcp
5. Adding it to the assistant
6. What the error messages mean

## 1. How the pieces fit

```
assistant  ──MCP on stdin/stdout──>  keel-mcp (on the user's computer)  ──HTTPS──>  keelAuth (POST /mcp)
```

keelAuth serves MCP itself. `keel-mcp` is keelOS's small bridge program (no dependencies, for
Windows, macOS and Linux, from the keelOS releases); it carries the messages to `<host>/mcp` and works
for keelAuth just as for a keelOS host. It needs keelAuth's address, a token and the fingerprint of
keelAuth's certificate.

The assistant must run where keelAuth is reachable: on a computer in the office network (or with a
VPN into it), not in the cloud.

## 2. The token

On keelAuth's web page (`https://<keelAuth address>/`, or the Accounts tab in keelOS): Settings,
AI management, New token. Give it a name that says who uses it ("Claude on Anna's laptop"). The token
(`kat_…`) is shown once; the page also shows the whole keel-mcp command to copy.

A token manages everything an administrator can on keelAuth (users, passwords, groups, SSO
applications, RADIUS clients, backups). Treat it like an administrator's password: it goes into the
assistant's configuration as an environment variable, not into a chat or a document. Revoke it on the
same page; that takes effect at once.

## 3. The certificate fingerprint

keelAuth has its own certificate authority, so keel-mcp checks the certificate's SHA-256 fingerprint.
It is on the web page (Settings, Certificate, and in the AI management command), and
`keel-mcp --host https://<keelAuth address> --show-fingerprint` prints what keelAuth presents now. The
two must be the same; if they differ, stop. The fingerprint stays the same when keelAuth's office
address changes (the certificate holds its name, not its LAN address); it changes only when the
domain changes or the certificate is renewed near its end (every two years).

## 4. keel-mcp

```sh
keel-mcp --host https://192.0.2.10 --token kat_… --fingerprint AB:CD:…   # serves MCP on stdin/stdout
keel-mcp --host https://192.0.2.10 --show-fingerprint
```

`KEEL_HOST`, `KEEL_TOKEN` and `KEEL_FINGERPRINT` in the environment do the same as the options.
`--check` is made for keelOS hosts: against keelAuth it prints the `connected:` and `tools:` lines
(which is what matters: `connected: keelauth …` and the tool list) and then fails on `host_info`, a
keelOS tool. That last error is expected.

Use keelAuth's own address, not the keelOS host's: the token is keelAuth's.

## 5. Adding it to the assistant

Claude Code:

```sh
claude mcp add keelauth --env KEEL_TOKEN=kat_… -- /path/to/keel-mcp --host https://192.0.2.10 --fingerprint AB:CD:…
```

Claude Desktop (`claude_desktop_config.json`, then restart the app):

```json
{
  "mcpServers": {
    "keelauth": {
      "command": "C:\\Tools\\keel-mcp.exe",
      "args": ["--host", "https://192.0.2.10", "--fingerprint", "AB:CD:…"],
      "env": { "KEEL_TOKEN": "kat_…" }
    }
  }
}
```

With a keelOS host as well, keep two entries (`keelos`, `keelauth`), each with its own token.

## 6. What the error messages mean

| Message | Meaning | What to do |
|---|---|---|
| `the host does not accept this token` | wrong or revoked token | make a new one (section 2) |
| `certificate fingerprint …, not the one given` | keelAuth presents another certificate | compare with the web page (section 3); keelAuth renews its certificate when its address changes, then the fingerprint changes too |
| `no /mcp on this host` | not keelAuth at that address (maybe the keelOS host) | use keelAuth's own address |
| `connection refused`, timeouts | keelAuth is off or the address is wrong | can the user open `https://<keelAuth address>/` in a browser? |
