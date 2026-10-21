package mcp

import (
	"fmt"
	"net/url"
)

// keelAuth's tools: each one API call (docs/02 section 6). Answers are the API's JSON.

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

var (
	readOnly  = map[string]any{"readOnlyHint": true, "openWorldHint": false}
	writes    = map[string]any{"readOnlyHint": false, "destructiveHint": false, "idempotentHint": false, "openWorldHint": false}
	sensitive = map[string]any{"readOnlyHint": false, "destructiveHint": true, "idempotentHint": false, "openWorldHint": false}
	nameProp  = map[string]any{"type": "string", "description": "the user's short name (lower-case, as in user_list)"}
	strList   = func(d string) map[string]any {
		return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": d}
	}
)

func str(a map[string]any, k string, required bool) (string, error) {
	v, ok := a[k]
	if !ok || v == nil {
		if required {
			return "", fmt.Errorf("%s is required", k)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok || (required && s == "") {
		return "", fmt.Errorf("%s: a string", k)
	}
	return s, nil
}

func strs(a map[string]any, k string) ([]string, error) {
	v, ok := a[k]
	if !ok || v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: a list of strings", k)
	}
	out := []string{}
	for _, x := range l {
		s, ok := x.(string)
		if !ok {
			return nil, fmt.Errorf("%s: a list of strings", k)
		}
		out = append(out, s)
	}
	return out, nil
}

// pick copies the arguments that are set into a request body.
func pick(a map[string]any, keys ...string) map[string]any {
	b := map[string]any{}
	for _, k := range keys {
		if v, ok := a[k]; ok && v != nil {
			b[k] = v
		}
	}
	return b
}

func get(path string) func(Doer, map[string]any) (any, error) {
	return func(api Doer, _ map[string]any) (any, error) {
		var out any
		return out, api.Do("GET", path, nil, &out)
	}
}

func userSummary(u map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range []string{"name", "display_name", "mail", "enabled", "groups", "admin", "has_nt", "must_change", "password_set_at", "password"} {
		if v, ok := u[k]; ok && v != nil && v != "" {
			out[k] = v
		}
	}
	return out
}

func setEnabled(on bool) func(Doer, map[string]any) (any, error) {
	return func(api Doer, a map[string]any) (any, error) {
		n, err := str(a, "name", true)
		if err != nil {
			return nil, err
		}
		var out map[string]any
		if err := api.Do("PATCH", "/v1/users/"+url.PathEscape(n), map[string]any{"enabled": on}, &out); err != nil {
			return nil, err
		}
		return userSummary(out), nil
	}
}

var tools = []Tool{
	{Name: "status", Title: "keelAuth status",
		Description: "keelAuth's state: version, domain, addresses, whether Kanidm (LDAP, SSO) and FreeRADIUS run, counts of users, groups, SSO applications and RADIUS clients, the last backup, the number of alerts, and the alerts themselves.",
		InputSchema: obj(map[string]any{}), Annotations: readOnly,
		Run: func(api Doer, _ map[string]any) (any, error) {
			var st, al map[string]any
			if err := api.Do("GET", "/v1/status", nil, &st); err != nil {
				return nil, err
			}
			if err := api.Do("GET", "/v1/alerts", nil, &al); err == nil {
				st["alert_list"] = al["alerts"]
			}
			return st, nil
		}},
	{Name: "user_list", Title: "List users",
		Description: "Every user: name, display name, mail, enabled, groups, admin (member of keelauth-admins), has_nt (false: Wi-Fi and shares do not work until the password is set again), must_change.",
		InputSchema: obj(map[string]any{}), Annotations: readOnly,
		Run: func(api Doer, _ map[string]any) (any, error) {
			var r struct {
				Users []map[string]any `json:"users"`
			}
			if err := api.Do("GET", "/v1/users", nil, &r); err != nil {
				return nil, err
			}
			out := []any{}
			for _, u := range r.Users {
				out = append(out, userSummary(u))
			}
			return out, nil
		}},
	{Name: "user_get", Title: "Show a user", Description: "One user in full (also its POSIX uid).",
		InputSchema: obj(map[string]any{"name": nameProp}, "name"), Annotations: readOnly,
		Run: func(api Doer, a map[string]any) (any, error) {
			n, err := str(a, "name", true)
			if err != nil {
				return nil, err
			}
			var out any
			return out, api.Do("GET", "/v1/users/"+url.PathEscape(n), nil, &out)
		}},
	{Name: "user_add", Title: "Add a user",
		Description: "Add a user. name: lower-case letters, digits, - and _, a letter first (e.g. the first name, \"anna\"). Without password keelAuth makes one and returns it once: give it to the person. " +
			"must_change (default true when keelAuth makes the password) makes them pick their own at the first login on keelAuth's page. A password must be at least 10 characters and not easy to guess.",
		InputSchema: obj(map[string]any{
			"name": nameProp, "display_name": map[string]any{"type": "string", "description": "full name, e.g. \"Anna Schmidt\""},
			"mail": map[string]any{"type": "string"}, "password": map[string]any{"type": "string"},
			"must_change": map[string]any{"type": "boolean"}, "groups": strList("groups to put the user in"),
		}, "name"), Annotations: writes,
		Run: func(api Doer, a map[string]any) (any, error) {
			if _, err := str(a, "name", true); err != nil {
				return nil, err
			}
			var out map[string]any
			if err := api.Do("POST", "/v1/users", pick(a, "name", "display_name", "mail", "password", "must_change", "groups"), &out); err != nil {
				return nil, err
			}
			return userSummary(out), nil
		}},
	{Name: "user_disable", Title: "Disable a user",
		Description: "Disable a user: no more logins anywhere (LDAP, SSO, Wi-Fi, shares). The account and its password stay; user_enable undoes it. The last administrator cannot be disabled.",
		InputSchema: obj(map[string]any{"name": nameProp}, "name"), Annotations: sensitive, Run: setEnabled(false)},
	{Name: "user_enable", Title: "Enable a user", Description: "Enable a disabled user again.",
		InputSchema: obj(map[string]any{"name": nameProp}, "name"), Annotations: writes, Run: setEnabled(true)},
	{Name: "user_reset_password", Title: "Reset a user's password",
		Description: "Set a new password for a user. Without password keelAuth makes one and returns it once. must_change (default true): the user picks their own at the next login on keelAuth's page. The old password stops working everywhere at once.",
		InputSchema: obj(map[string]any{"name": nameProp, "password": map[string]any{"type": "string"}, "must_change": map[string]any{"type": "boolean"}}, "name"),
		Annotations: sensitive,
		Run: func(api Doer, a map[string]any) (any, error) {
			n, err := str(a, "name", true)
			if err != nil {
				return nil, err
			}
			var out any
			return out, api.Do("POST", "/v1/users/"+url.PathEscape(n)+"/password", pick(a, "password", "must_change"), &out)
		}},
	{Name: "group_list", Title: "List groups", Description: "Every group with its members. keelauth-admins: the people who manage keelAuth.",
		InputSchema: obj(map[string]any{}), Annotations: readOnly, Run: get("/v1/groups")},
	{Name: "group_add", Title: "Add a group", Description: "Add a group (name like a user name), optionally with members.",
		InputSchema: obj(map[string]any{"name": map[string]any{"type": "string"}, "description": map[string]any{"type": "string"}, "members": strList("user names")}, "name"),
		Annotations: writes,
		Run: func(api Doer, a map[string]any) (any, error) {
			var out any
			return out, api.Do("POST", "/v1/groups", pick(a, "name", "description", "members"), &out)
		}},
	{Name: "group_members", Title: "Change a group's members",
		Description: "Add users to and remove users from a group. Adding someone to keelauth-admins makes them an administrator of keelAuth.",
		InputSchema: obj(map[string]any{"group": map[string]any{"type": "string"}, "add": strList("user names to add"), "remove": strList("user names to remove")}, "group"),
		Annotations: sensitive,
		Run: func(api Doer, a map[string]any) (any, error) {
			g, err := str(a, "group", true)
			if err != nil {
				return nil, err
			}
			add, err := strs(a, "add")
			if err != nil {
				return nil, err
			}
			rm, err := strs(a, "remove")
			if err != nil {
				return nil, err
			}
			if add == nil {
				add = []string{}
			}
			if rm == nil {
				rm = []string{}
			}
			var out any
			return out, api.Do("POST", "/v1/groups/"+url.PathEscape(g)+"/members", map[string]any{"add": add, "remove": rm}, &out)
		}},
	{Name: "oidc_list", Title: "List SSO applications",
		Description: "The web applications that log in with keelAuth (OIDC): client id, redirect URLs, who may log in (scope_group, empty = all users), the discovery URL to give the application.",
		InputSchema: obj(map[string]any{}), Annotations: readOnly, Run: get("/v1/oidc")},
	{Name: "oidc_create", Title: "Register an SSO application",
		Description: "Register a web application for single sign-on (OIDC). redirect_urls: the application's callback URLs (from its OIDC settings). scope_group: only this group may log in (empty: everybody). " +
			"Returns client_id, client_secret and discovery_url: enter them in the application. PKCE (S256) is required unless pkce is false (only for old applications that cannot do it). " +
			"short_username (default true): preferred_username is the bare name (alice), false: alice@<domain>.",
		InputSchema: obj(map[string]any{
			"name": map[string]any{"type": "string", "description": "short name, becomes the client id"}, "display_name": map[string]any{"type": "string"},
			"landing_url": map[string]any{"type": "string", "description": "the application's address"}, "redirect_urls": strList("callback URLs"),
			"scope_group": map[string]any{"type": "string"}, "pkce": map[string]any{"type": "boolean"},
			"short_username": map[string]any{"type": "boolean", "description": "user name without @domain (default true)"},
		}, "name", "redirect_urls"), Annotations: writes,
		Run: func(api Doer, a map[string]any) (any, error) {
			var out any
			return out, api.Do("POST", "/v1/oidc", pick(a, "name", "display_name", "landing_url", "redirect_urls", "scope_group", "pkce", "short_username"), &out)
		}},
	{Name: "radius_list", Title: "RADIUS clients",
		Description: "The RADIUS clients (Wi-Fi access points, VPN gateways) with their addresses and shared secrets, the group allowed to use RADIUS (empty: everybody), and users without an NT hash (they cannot use Wi-Fi until their password is set again).",
		InputSchema: obj(map[string]any{}), Annotations: readOnly, Run: get("/v1/radius")},
	{Name: "radius_client_add", Title: "Add a RADIUS client",
		Description: "Allow an access point or VPN gateway to ask keelAuth (WPA2/WPA3-Enterprise, PEAP-MSCHAPv2). address: its IP address or a network (192.168.1.0/24). Without secret keelAuth makes one. Returns the shared secret to enter on the device, with keelAuth's address and port 1812.",
		InputSchema: obj(map[string]any{"name": map[string]any{"type": "string"}, "address": map[string]any{"type": "string"}, "secret": map[string]any{"type": "string"}}, "name", "address"),
		Annotations: writes,
		Run: func(api Doer, a map[string]any) (any, error) {
			var out any
			return out, api.Do("POST", "/v1/radius/clients", pick(a, "name", "address", "secret"), &out)
		}},
	{Name: "ldap_info", Title: "LDAP settings for devices",
		Description: "What a device or application enters to read keelAuth's users over LDAP (LDAPS only): host (keelAuth's domain: devices that check the certificate need it in the office DNS and keelAuth's CA), port, base DN, " +
			"the device accounts (bind DN dn=token, each with its own password, which can read mail addresses), keelAuth's shared read-only account (short password, no mail), filters and attribute names.",
		InputSchema: obj(map[string]any{}), Annotations: readOnly,
		Run: func(api Doer, _ map[string]any) (any, error) {
			var out map[string]any
			if err := api.Do("GET", "/v1/ldap", nil, &out); err != nil {
				return nil, err
			}
			delete(out, "bind_password") // the shared account's password: on the page, not in a chat
			return out, nil
		}},
	{Name: "ldap_device_add", Title: "Add an LDAP device account",
		Description: "Make a read-only LDAP account for one device or application (a printer's address book, a Linux machine, GitLab, Redmine, Dovecot). Returns bind_dn (dn=token) and the password (a long token) once: " +
			"put it into the device. It reads users, groups and mail addresses, nothing else, and is revoked on its own (ldap_device_delete). Then ldap_examples gives the configuration.",
		InputSchema: obj(map[string]any{"name": map[string]any{"type": "string", "description": "short name (lower-case), e.g. printer-2f"},
			"description": map[string]any{"type": "string", "description": "what it is, e.g. \"Copier, 2nd floor\""}}, "name"),
		Annotations: writes,
		Run: func(api Doer, a map[string]any) (any, error) {
			var out any
			return out, api.Do("POST", "/v1/ldap/devices", pick(a, "name", "description"), &out)
		}},
	{Name: "ldap_device_password", Title: "New password for an LDAP device account",
		Description: "Give a device account a new password (returned once); the old one stops working at once.",
		InputSchema: obj(map[string]any{"name": map[string]any{"type": "string"}}, "name"), Annotations: sensitive,
		Run: func(api Doer, a map[string]any) (any, error) {
			n, err := str(a, "name", true)
			if err != nil {
				return nil, err
			}
			var out any
			return out, api.Do("POST", "/v1/ldap/devices/"+url.PathEscape(n)+"/password", nil, &out)
		}},
	{Name: "ldap_device_delete", Title: "Delete an LDAP device account",
		Description: "Delete a device account: the device can no longer read keelAuth's users.",
		InputSchema: obj(map[string]any{"name": map[string]any{"type": "string"}}, "name"), Annotations: sensitive,
		Run: func(api Doer, a map[string]any) (any, error) {
			n, err := str(a, "name", true)
			if err != nil {
				return nil, err
			}
			var out any
			return out, api.Do("DELETE", "/v1/ldap/devices/"+url.PathEscape(n), nil, &out)
		}},
	{Name: "ldap_examples", Title: "LDAP configuration examples",
		Description: "Ready configurations for keelAuth's LDAP: Linux sssd.conf, a printer's address book, Dovecot (auth_bind), Postfix through Dovecot SASL, GitLab, Redmine. " +
			"device: a device account's name to fill in; its password appears as DEVICE-PASSWORD (it is shown only when the account is made).",
		InputSchema: obj(map[string]any{"device": map[string]any{"type": "string"}}), Annotations: readOnly,
		Run: func(api Doer, a map[string]any) (any, error) {
			d, err := str(a, "device", false)
			if err != nil {
				return nil, err
			}
			p := "/v1/ldap/examples"
			if d != "" {
				p += "?device=" + url.QueryEscape(d)
			}
			var out any
			return out, api.Do("GET", p, nil, &out)
		}},
	{Name: "cert_status", Title: "Certificates",
		Description: "The certificates keelAuth uses (LDAPS, single sign-on, the web page, Wi-Fi/PEAP): keelAuth's own or the office's uploaded one, the CA devices must trust (anchor) with SHA-256 and SHA-1 fingerprints, names and end dates. " +
			"Devices download the CA from https://<keelAuth>/ca/keelauth-ca.crt (PEM), .cer (DER: Windows, Android) or .mobileconfig (Apple).",
		InputSchema: obj(map[string]any{}), Annotations: readOnly, Run: get("/v1/certs")},
	{Name: "backup_now", Title: "Back up now",
		Description: "Back up keelAuth now (Kanidm's database and keelAuth's own data). keelAuth also backs up once a day by itself.",
		InputSchema: obj(map[string]any{}), Annotations: writes,
		Run: func(api Doer, _ map[string]any) (any, error) {
			var out any
			return out, api.Do("POST", "/v1/backups", nil, &out)
		}},
}
