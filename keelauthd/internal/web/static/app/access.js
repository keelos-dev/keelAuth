// The ways in (docs/54 §3.2): LDAP, SSO (OIDC), RADIUS, a sub-tab each. Each says what it is
// for and what to fill in on the other side (the device, the application, the access point).
import { useEffect, useState } from "preact/hooks";
import { api, html, rel } from "./api.js";
import { fmtTime, t } from "./i18n.js";
import { ask, Dialog, FormDialog, Spinner, toast } from "./ui.js";
import { namePattern, Shown } from "./users.js";

const fail = (e) => toast(e.message, 8000);
const enc = encodeURIComponent;
const subs = ["ldap", "sso", "radius"];

function copy(v) { try { navigator.clipboard.writeText(v); toast(t("copied")); } catch (_) { /* none */ } }
const Val = ({ v }) => html`<span class="mono">${v}</span><button type="button" class="copy" onClick=${() => copy(String(v))}>${t("copy")}</button>`;

// Fill: the "what to fill in on the other side" table.
const Fill = ({ rows }) => html`<table class="kv-table"><tbody>${rows.map(([k, v, plain]) => html`<tr><th>${k}</th><td>${plain ? v : html`<${Val} v=${v} />`}</td></tr>`)}</tbody></table>`;

// Examples: ready configurations for the office's LDAP clients (docs/02 §7.10), with the device
// account's password put in when the page has it (right after it was made).
export function Examples({ device, password, onClose }) {
  const [d, setD] = useState(null);
  const [cur, setCur] = useState(0);
  useEffect(() => { api("GET", "v1/ldap/examples" + (device ? "?device=" + enc(device) : "")).then(setD).catch(fail); }, []);
  if (!d) return null;
  const ex = d.examples[cur];
  const text = password ? ex.text.split(d.password_holder).join(password) : ex.text;
  return html`<${Dialog} title=${device ? t("ldap.exfor", device) : t("ldap.examples")} onClose=${onClose} wide=${true}><div class="stack">
    <nav class="subnav">${d.examples.map((e, i) => html`<a href="#" class=${i === cur ? "on" : ""} onClick=${(ev) => { ev.preventDefault(); setCur(i); }}>${e.title}</a>`)}</nav>
    ${ex.file && html`<p class="small"><span class="muted">${t("ldap.exfile")}</span> <span class="mono">${ex.file}</span></p>`}
    <pre class="code ka-ex">${text}</pre>
    ${ex.note && html`<p class="muted small">${ex.note}</p>`}
    ${!password && html`<p class="muted small">${t("ldap.exholder", d.password_holder)}</p>`}
    <div class="actions"><button type="button" class="btn" onClick=${() => copy(text)}>${t("copy")}</button>
      <button type="button" class="primary" onClick=${onClose}>${t("dlg.done")}</button></div></div><//>`;
}

function DeviceForm({ onClose, onDone }) {
  const [f, setF] = useState({ name: "", description: "" });
  const set = (k) => (e) => { const v = e.target.value; setF((f) => ({ ...f, [k]: v })); };
  const save = async () => onDone(await api("POST", "v1/ldap/devices", { name: f.name.trim(), description: f.description.trim() }));
  return html`<${FormDialog} title=${t("ldap.devnew")} submit=${t("ldap.devadd")} onSubmit=${save} onClose=${onClose}>
    <p class="muted small">${t("ldap.devfor")}</p>
    <label>${t("ldap.devname")}<input type="text" required pattern=${namePattern} spellcheck="false" autocapitalize="off" placeholder="printer-2f" value=${f.name} onInput=${set("name")} /></label>
    <label>${t("ldap.devdesc")}<input type="text" maxlength="200" placeholder=${t("ldap.devdescex")} value=${f.description} onInput=${set("description")} /></label>
  <//>`;
}

// DeviceShown: the device account right after it was made (or got a new password): shown once.
function DeviceShown({ dev, onClose, onExamples }) {
  return html`<${Dialog} title=${t("ldap.devmade", dev.name)} onClose=${onClose}><div class="stack">
    <table class="kv-table once"><tbody>
      <tr><th>${t("ldap.binddn")}</th><td><${Val} v=${dev.bind_dn} /></td></tr>
      <tr><th>${t("ldap.bindpw")}</th><td><${Val} v=${dev.password} /></td></tr></tbody></table>
    <p class="warn small">${t("ldap.devonce")}</p>
    <div class="actions"><button type="button" class="btn" onClick=${onExamples}>${t("ldap.exwith")}</button>
      <button type="button" class="primary" onClick=${onClose}>${t("dlg.done")}</button></div></div><//>`;
}

function LDAP() {
  const [l, setL] = useState(null);
  const [show, setShow] = useState(false);
  const [dlg, setDlg] = useState(null);
  const load = () => api("GET", "v1/ldap").then(setL).catch(fail);
  useEffect(() => { load(); }, []);
  if (!l) return html`<${Spinner} />`;
  const close = () => setDlg(null);
  const reset = async () => {
    if (!await ask(t("ldap.resetq"))) return;
    try { setL(await api("POST", "v1/ldap/bind", { reset: true })); setShow(true); toast(t("ldap.reset.done")); } catch (e) { fail(e); }
  };
  const newpw = async (d) => {
    if (!await ask(t("ldap.devnewpwq", d.name))) return;
    try { const x = await api("POST", "v1/ldap/devices/" + enc(d.name) + "/password"); load(); setDlg({ kind: "shown", dev: x }); } catch (e) { fail(e); }
  };
  const del = async (d) => {
    if (!await ask(t("ldap.devdelq", d.name))) return;
    try { await api("DELETE", "v1/ldap/devices/" + enc(d.name)); load(); } catch (e) { fail(e); }
  };
  const devs = l.devices || [];
  return html`<div class="card"><div class="row-head"><h3>LDAP</h3><span class="grow"></span>
      <button class="btn" onClick=${() => setDlg({ kind: "examples" })}>${t("ldap.examples")}</button>
      <a class="btn" href=${rel("v1/ca")} download="keelauth-ca.crt">${t("acc.ca")}</a>
      <button class="primary" onClick=${() => setDlg({ kind: "new" })}>${t("ldap.devnew")}</button></div>
    <p class="ka-for">${t("ldap.for")}</p>
    <h3 class="sub">${t("ldap.devices")}</h3>
    ${devs.length === 0 && html`<p class="muted">${t("ldap.devnone")}</p>`}
    ${devs.length > 0 && html`<div class="table-wrap tall"><table class="data plain">
      <thead><tr><th>${t("ldap.devname")}</th><th>${t("ldap.devdesc")}</th><th>${t("ldap.devpwat")}</th><th></th></tr></thead>
      <tbody>${devs.map((d) => html`<tr><td><b>${d.name}</b>${d.missing ? html` <span class="badge" title=${t("ldap.devmissing")}>${t("ldap.devmissingb")}</span>` : ""}</td>
        <td>${d.description || "–"}</td><td>${fmtTime(d.password_set_at)}</td>
        <td class="nowrap"><button class="btn" onClick=${() => setDlg({ kind: "examples", dev: d.name })}>${t("ldap.examples")}</button>
          <button class="btn" onClick=${() => newpw(d)}>${t("ldap.devnewpw")}</button>
          <button class="btn danger" onClick=${() => del(d)}>${t("delete")}</button></td></tr>`)}</tbody></table></div>`}
    <h3 class="sub">${t("acc.fill")}</h3>
    <${Fill} rows=${[
      [t("ldap.server"), html`<span class="mono">${l.host}</span> <span class="muted small">(${(l.addresses || []).join(", ")})</span>`, true],
      [t("ldap.port"), l.port],
      [t("ldap.security"), t("ldap.ldaps"), true],
      ["Base DN", l.base_dn],
      [t("ldap.binddn"), l.device_bind_dn],
      [t("ldap.bindpw"), t("ldap.devpw"), true],
      [t("ldap.userfilter"), l.users_filter],
      [t("ldap.loginattr"), l.attributes.user_name],
      [t("ldap.mailattr"), l.attributes.mail],
      [t("ldap.nameattr"), l.attributes.display_name],
      [t("ldap.attrs"), "memberof, uidnumber, gidnumber (posixaccount)", true],
      [t("ldap.groupfilter"), l.group_filter + "  ·  " + t("ldap.member") + " member", true],
    ]} />
    <p class="muted small">${t("ldap.note", l.host)}</p>
    <details class="ka-shared"><summary>${t("ldap.shared")}</summary>
      <p class="muted small">${t("ldap.sharedfor")}</p>
      <${Fill} rows=${[
        [t("ldap.binddn"), l.bind_dn],
        [t("ldap.bindpw"), show ? html`<${Val} v=${l.bind_password} />` : html`<span class="mono">••••••••</span> <button type="button" class="copy" onClick=${() => setShow(true)}>${t("show")}</button>`, true],
      ]} />
      <div class="actions"><button class="btn" onClick=${reset}>${t("ldap.reset")}</button></div></details>
    ${dlg && dlg.kind === "new" && html`<${DeviceForm} onClose=${close} onDone=${(x) => { load(); setTimeout(() => setDlg({ kind: "shown", dev: x })); }} />`}
    ${dlg && dlg.kind === "shown" && html`<${DeviceShown} dev=${dlg.dev} onClose=${close} onExamples=${() => setDlg({ kind: "examples", dev: dlg.dev.name, password: dlg.dev.password })} />`}
    ${dlg && dlg.kind === "examples" && html`<${Examples} device=${dlg.dev} password=${dlg.password} onClose=${close} />`}
  </div>`;
}

function AppForm({ app, groups, onClose, onDone }) {
  const [f, setF] = useState(app ? { display_name: app.display_name, landing_url: app.landing_url, redirects: app.redirect_urls.join("\n"), scope_group: app.scope_group, pkce: app.pkce, short_username: !!app.short_username }
    : { name: "", display_name: "", landing_url: "", redirects: "", scope_group: "", pkce: true, short_username: true });
  const set = (k) => (e) => { const v = e.target.type === "checkbox" ? e.target.checked : e.target.value; setF((f) => ({ ...f, [k]: v })); };
  const save = async () => {
    const body = { display_name: f.display_name.trim(), redirect_urls: f.redirects.split(/\s+/).filter(Boolean), scope_group: f.scope_group, pkce: f.pkce, short_username: f.short_username };
    if (f.landing_url.trim()) body.landing_url = f.landing_url.trim();
    if (app) { await api("PATCH", "v1/oidc/" + enc(app.name), body); onDone(null); } else onDone(await api("POST", "v1/oidc", { name: f.name.trim(), ...body }));
  };
  return html`<${FormDialog} title=${app ? t("sso.edit", app.name) : t("sso.new")} submit=${app ? t("save") : t("sso.add")} onSubmit=${save} onClose=${onClose}>
    ${!app && html`<label>${t("sso.name")}<input type="text" required pattern=${namePattern} spellcheck="false" autocapitalize="off" value=${f.name} onInput=${set("name")} />
      <span class="muted small">${t("sso.namehint")}</span></label>`}
    <label>${t("sso.display")}<input type="text" value=${f.display_name} onInput=${set("display_name")} /></label>
    <label>${t("sso.redirects")}<textarea rows="3" class="mono" required spellcheck="false" value=${f.redirects} onInput=${set("redirects")}></textarea>
      <span class="muted small">${t("sso.redirectshint")}</span></label>
    <label>${t("sso.landing")}<input type="url" placeholder="https://gitlab.office.lan/" value=${f.landing_url} onInput=${set("landing_url")} /></label>
    <label>${t("sso.who")}<select value=${f.scope_group} onChange=${set("scope_group")}>
      <option value="">${t("sso.everyone")}</option>${groups.map((g) => html`<option value=${g.name}>${g.name}</option>`)}</select></label>
    <label class="check"><input type="checkbox" checked=${f.short_username} onChange=${set("short_username")} /> ${t("sso.short")}</label>
    <label class="check"><input type="checkbox" checked=${f.pkce} onChange=${set("pkce")} /> ${t("sso.pkce")}</label>
  <//>`;
}

// Connect: everything to enter in one application's OIDC settings (keelOS docs/54 D3).
function Connect({ app, domain, onSecret, onClose }) {
  const user = app.short_username ? "alice" : "alice@" + domain;
  return html`<${Dialog} title=${t("sso.connect1", app.display_name || app.name)} onClose=${onClose}><div class="stack">
    <${Fill} rows=${[
      [t("sso.discovery"), app.discovery_url],
      [t("sso.issuer"), app.issuer],
      ["Client ID", app.client_id || app.name],
      ["Client secret", html`<button type="button" class="btn" onClick=${onSecret}>${t("sso.secret")}</button>`, true],
      [t("sso.redirects"), html`${(app.redirect_urls || []).map((u) => html`<div class="mono">${u}</div>`)}<span class="muted small">${t("sso.redirectsset")}</span>`, true],
      [t("sso.scopes"), "openid profile email groups"],
      [t("sso.auth"), "client_secret_basic"],
      ["PKCE", app.pkce ? "S256" : t("sso.nopkce"), !app.pkce],
      [t("sso.userclaim"), html`<span class="mono">preferred_username</span> <span class="muted small">${t("sso.claimex", user)}</span>`, true],
      [t("sso.groupclaim"), html`<span class="mono">groups</span> <span class="muted small">${t("sso.claimex", "office@" + domain)}</span>`, true],
    ]} />
    <p class="muted small">${t("sso.note")}</p>
    <div class="actions"><button type="button" class="primary" onClick=${onClose}>${t("dlg.done")}</button></div></div><//>`;
}

// Roles: what an application (keelOS) says its groups mean there, with the missing ones to make.
function Roles({ app, onMade }) {
  const make = async (g) => {
    try { await api("POST", "v1/groups", { name: g, description: (app.roles_by || app.name) + ": " + app.roles[g] }); toast(t("sso.groupmade", g)); onMade(); } catch (e) { fail(e); }
  };
  const missing = app.missing_groups || [];
  return html`<div class="ka-roles"><p class="small">${t("sso.rolesfor", app.roles_by || app.name, app.name)}</p>
    <table class="data plain"><thead><tr><th>${t("sso.rolegroup")}</th><th>${t("sso.rolemeans", app.roles_by || app.name)}</th><th></th></tr></thead>
      <tbody>${Object.entries(app.roles).sort().map(([g, r]) => html`<tr><td class="mono">${missing.includes(g) ? g : html`<a href=${"#/groups"}>${g}</a>`}</td><td>${r}</td>
        <td>${missing.includes(g) ? html`<button class="btn" onClick=${() => make(g)}>${t("sso.makegroup")}</button>` : html`<span class="muted small">${t("sso.groupok")}</span>`}</td></tr>`)}</tbody></table>
    <p class="muted small">${t("sso.roleshint")}</p></div>`;
}

function SSO() {
  const [d, setD] = useState(null);
  const [groups, setGroups] = useState([]);
  const [dlg, setDlg] = useState(null);
  const load = () => Promise.all([api("GET", "v1/oidc"), api("GET", "v1/groups")]).then(([o, g]) => { setD(o); setGroups(g.groups || []); }).catch(fail);
  useEffect(() => { load(); }, []);
  if (!d) return html`<${Spinner} />`;
  const close = () => setDlg(null);
  const secret = async (a, reset) => {
    if (reset && !await ask(t("sso.resetq", a.name))) return;
    try { const r = await api("POST", "v1/oidc/" + enc(a.name) + "/secret", { reset }); setDlg({ kind: "shown", app: a, secret: r.client_secret }); } catch (e) { fail(e); }
  };
  const del = async (a) => {
    if (!await ask(t("sso.deleteq", a.name))) return;
    try { await api("DELETE", "v1/oidc/" + enc(a.name)); load(); } catch (e) { fail(e); }
  };
  const ex = d.clients[0];
  return html`<div class="card"><div class="row-head"><h3>${t("acc.sso")}</h3><button class="primary" onClick=${() => setDlg({ kind: "new" })}>${t("sso.new")}</button></div>
    <p class="ka-for">${t("sso.for")}</p>
    ${d.clients.length === 0 && html`<p class="muted">${t("sso.none")}</p>`}
    ${d.clients.length > 0 && html`<div class="table-wrap tall"><table class="data plain">
      <thead><tr><th>${t("sso.name")}</th><th>${t("sso.display")}</th><th>${t("sso.redirects")}</th><th>${t("sso.who")}</th><th></th></tr></thead>
      <tbody>${d.clients.map((a) => html`<tr><td><b>${a.name}</b></td><td>${a.display_name}</td><td class="mono small">${a.redirect_urls.join(" ") || "–"}</td>
        <td>${a.scope_group || t("sso.everyone")}${!a.pkce ? html` <span class="badge">${t("sso.nopkce")}</span>` : ""}</td>
        <td class="nowrap"><button class="btn" onClick=${() => setDlg({ kind: "connect", app: a })}>${t("sso.connect")}</button>
          <button class="btn" onClick=${() => setDlg({ kind: "edit", app: a })}>${t("edit")}</button>
          <button class="btn" onClick=${() => secret(a, false)}>${t("sso.secret")}</button>
          <button class="btn" onClick=${() => secret(a, true)}>${t("sso.newsecret")}</button>
          <button class="btn danger" onClick=${() => del(a)}>${t("delete")}</button></td></tr>`)}</tbody></table></div>`}
    ${d.clients.filter((a) => a.roles && Object.keys(a.roles).length).map((a) => html`<${Roles} key=${a.name} app=${a} onMade=${load} />`)}
    <h3 class="sub">${t("acc.fill")}</h3>
    <${Fill} rows=${[
      [t("sso.issuer"), ex ? ex.issuer : d.issuer_base + "<" + t("sso.name") + ">"],
      [t("sso.discovery"), ex ? ex.discovery_url : d.issuer_base + "<" + t("sso.name") + ">/.well-known/openid-configuration"],
      ["Client ID", t("sso.clientid"), true],
      ["Client secret", t("sso.clientsecret"), true],
      [t("sso.scopes"), "openid profile email groups"],
      [t("sso.auth"), "client_secret_basic"],
      ["PKCE", "S256"],
      [t("sso.userclaim"), "preferred_username"],
      [t("sso.groupclaim"), "groups"],
    ]} />
    <p class="muted small">${t("sso.note")}</p>
    ${dlg && dlg.kind === "new" && html`<${AppForm} groups=${groups} onClose=${close}
      onDone=${(a) => { load(); setTimeout(() => setDlg({ kind: "shown", app: a, secret: a.client_secret })); }} />`}
    ${dlg && dlg.kind === "edit" && html`<${AppForm} app=${dlg.app} groups=${groups} onClose=${close} onDone=${load} />`}
    ${dlg && dlg.kind === "connect" && html`<${Connect} app=${dlg.app} domain=${(d.issuer_base.match(/^https:\/\/([^:/]+)/) || [])[1] || ""} onClose=${close} onSecret=${() => secret(dlg.app, false)} />`}
    ${dlg && dlg.kind === "shown" && html`<${Shown} title=${t("sso.for1", dlg.app.name)} onClose=${close} note=${t("sso.secretnote")}
      rows=${[["Client ID", dlg.app.client_id || dlg.app.name], ["Client secret", dlg.secret], [t("sso.discovery"), dlg.app.discovery_url]]} />`}
  </div>`;
}

function ClientForm({ client, onClose, onDone }) {
  const [name, setName] = useState("");
  const [addr, setAddr] = useState(client ? client.address : "");
  const [sec, setSec] = useState("");
  const save = async () => {
    if (client) onDone(await api("PATCH", "v1/radius/clients/" + enc(client.name), sec ? { address: addr.trim(), secret: sec } : { address: addr.trim() }));
    else onDone(await api("POST", "v1/radius/clients", { name: name.trim(), address: addr.trim(), secret: sec }));
  };
  return html`<${FormDialog} title=${client ? t("rad.edit", client.name) : t("rad.new")} submit=${client ? t("save") : t("rad.add")} onSubmit=${save} onClose=${onClose}>
    ${!client && html`<label>${t("rad.name")}<input type="text" required pattern=${namePattern} spellcheck="false" autocapitalize="off" placeholder="ap-office" value=${name} onInput=${(e) => setName(e.target.value)} /></label>`}
    <label>${t("rad.address")}<input type="text" required spellcheck="false" placeholder="192.168.1.20" value=${addr} onInput=${(e) => setAddr(e.target.value)} />
      <span class="muted small">${t("rad.addresshint")}</span></label>
    <label>${t("rad.secret")}<input type="text" spellcheck="false" autocomplete="off" value=${sec} onInput=${(e) => setSec(e.target.value)} />
      <span class="muted small">${client ? t("rad.secretkeep") : t("rad.secrethint")}</span></label>
  <//>`;
}

function RADIUS() {
  const [d, setD] = useState(null);
  const [groups, setGroups] = useState([]);
  const [dlg, setDlg] = useState(null);
  const [show, setShow] = useState({});
  const load = () => Promise.all([api("GET", "v1/radius"), api("GET", "v1/groups")]).then(([r, g]) => { setD(r); setGroups(g.groups || []); }).catch(fail);
  useEffect(() => { load(); }, []);
  if (!d) return html`<${Spinner} />`;
  const close = () => setDlg(null);
  const del = async (c) => {
    if (!await ask(t("rad.deleteq", c.name))) return;
    try { await api("DELETE", "v1/radius/clients/" + enc(c.name)); load(); } catch (e) { fail(e); }
  };
  const setGroup = async (g) => { try { setD(await api("PUT", "v1/radius", { group: g })); } catch (e) { fail(e); } };
  return html`<div class="card"><div class="row-head"><h3>RADIUS</h3><button class="primary" onClick=${() => setDlg({ kind: "new" })}>${t("rad.new")}</button></div>
    <p class="ka-for">${t("rad.for")}</p>
    ${d.clients.length === 0 && html`<p class="muted">${t("rad.none")}</p>`}
    ${d.clients.length > 0 && html`<div class="table-wrap tall"><table class="data plain">
      <thead><tr><th>${t("rad.name")}</th><th>${t("rad.address")}</th><th>${t("rad.secret")}</th><th></th></tr></thead>
      <tbody>${d.clients.map((c) => html`<tr><td><b>${c.name}</b></td><td class="mono">${c.address}</td>
        <td>${show[c.name] ? html`<${Val} v=${c.secret} />` : html`<span class="mono">••••••••</span> <button type="button" class="copy" onClick=${() => setShow({ ...show, [c.name]: true })}>${t("show")}</button>`}</td>
        <td class="nowrap"><button class="btn" onClick=${() => setDlg({ kind: "edit", client: c })}>${t("edit")}</button>
          <button class="btn danger" onClick=${() => del(c)}>${t("delete")}</button></td></tr>`)}</tbody></table></div>`}
    <div class="attach-row"><span>${t("rad.who")}</span><select value=${d.group} onChange=${(e) => setGroup(e.target.value)}>
      <option value="">${t("rad.everyone")}</option>${groups.map((g) => html`<option value=${g.name}>${g.name}</option>`)}</select>
      <span class="muted small">${t("rad.users", d.users)}</span></div>
    ${d.missing_nt.length > 0 && html`<p class="warn small">${t("rad.missing", d.missing_nt.join(", "))}</p>`}
    <h3 class="sub">${t("rad.fillap")}</h3>
    <${Fill} rows=${[
      [t("rad.server"), (d.addresses || []).join(", ") || "–"],
      [t("rad.port"), d.port + " (UDP)"],
      [t("rad.secret"), t("rad.secretper"), true],
      [t("rad.security"), "WPA2-Enterprise / WPA3-Enterprise (802.1X)", true],
      [t("rad.acct"), t("rad.acctv"), true],
    ]} />
    <h3 class="sub">${t("rad.fillclient")}</h3>
    <${Fill} rows=${[
      [t("rad.eap"), d.eap || "PEAP", true],
      [t("rad.inner"), d.inner || "MSCHAPv2", true],
      [t("rad.ca"), d.ca ? html`${d.ca.subject} <a class="btn" href=${rel("v1/ca?format=der")} download="keelauth-ca.cer">.cer</a> <a class="btn" href=${rel("v1/ca")} download="keelauth-ca.crt">.crt</a> <a class="btn" href=${rel("v1/ca/mobileconfig")} download="keelauth-ca.mobileconfig">Apple</a>` : "–", true],
      [t("rad.domain"), d.server_name],
      [t("rad.identity"), t("rad.loginv"), true],
      [t("rad.anon"), t("rad.anonv"), true],
    ]} />
    <p class="muted small">${t("rad.note", d.server_name)}</p>
    ${d.ca && html`<p class="muted small">${t("rad.fp", d.ca.sha256, d.ca.sha1)}</p>`}
    ${dlg && dlg.kind === "new" && html`<${ClientForm} onClose=${close} onDone=${(c) => { load(); setTimeout(() => setDlg({ kind: "shown", client: c })); }} />`}
    ${dlg && dlg.kind === "edit" && html`<${ClientForm} client=${dlg.client} onClose=${close} onDone=${() => load()} />`}
    ${dlg && dlg.kind === "shown" && html`<${Shown} title=${t("rad.for1", dlg.client.name)} onClose=${close} note=${t("rad.shownote")}
      rows=${[[t("rad.server"), (d.addresses || [])[0] || "–"], [t("rad.port"), "1812"], [t("rad.secret"), dlg.client.secret]]} />`}
  </div>`;
}

export function Access({ sub }) {
  const tab = subs.includes(sub) ? sub : "ldap";
  return html`<nav class="subnav" aria-label=${t("nav.access")}>${subs.map((k) => html`<a href=${"#/access/" + k} class=${k === tab ? "on" : ""}
      aria-current=${k === tab ? "page" : null}>${t("acc." + k)}</a>`)}</nav>
    <div class="stack">${tab === "ldap" ? html`<${LDAP} />` : tab === "sso" ? html`<${SSO} />` : html`<${RADIUS} />`}</div>`;
}
