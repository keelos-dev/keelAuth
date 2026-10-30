// Users: the list; adding, editing, a new password: dialogs. A password keelAuth makes is shown
// once (Shown).
import { useEffect, useState } from "preact/hooks";
import { api, html } from "./api.js";
import { fmtTime, pwRules, t } from "./i18n.js";
import { ask, Dialog, FormDialog, Spinner, toast } from "./ui.js";

// usePwPolicy: the password rules in force (status.password_policy), for hints and minlength.
export function usePwPolicy() {
  const [pol, setPol] = useState(null);
  useEffect(() => { api("GET", "v1/status").then((x) => setPol(x.password_policy || null)).catch(() => {}); }, []);
  return pol;
}
export const pwMin = (p) => String(p && p.min_length ? p.min_length : 15);

const fail = (e) => toast(e.message, 8000);
const enc = encodeURIComponent;
export const namePattern = "[a-z][a-z0-9_\\-]{0,31}";

// Shown: something to hand on that is shown only now (a password, a secret, a token).
export function Shown({ title, rows, note, onClose }) {
  const copy = (v) => { try { navigator.clipboard.writeText(v); toast(t("copied")); } catch (_) { /* no clipboard */ } };
  return html`<${Dialog} title=${title} onClose=${onClose}><div class="stack">
    <table class="kv-table once"><tbody>${rows.map(([k, v]) => html`<tr><th>${k}</th><td><span class="mono">${v}</span>
      <button type="button" class="copy" onClick=${() => copy(v)}>${t("copy")}</button></td></tr>`)}</tbody></table>
    <p class="warn small">${note || t("shown.once")}</p>
    <div class="actions"><button type="button" class="primary" onClick=${onClose}>${t("dlg.done")}</button></div></div><//>`;
}

// GroupPicks: a check box per group.
function GroupPicks({ groups, value, onChange }) {
  if (!groups.length) return null;
  return html`<fieldset class="hn-g"><legend>${t("users.groups")}</legend><div>
    ${groups.map((g) => html`<label class="check"><input type="checkbox" checked=${value.includes(g.name)}
      onChange=${(e) => { const on = e.target.checked; onChange((cur) => (on ? [...cur, g.name] : cur.filter((x) => x !== g.name))); }} /> ${g.name}</label>`)}</div></fieldset>`;
}

// AccessPicks: which services the account may use (GET v1/consumers); value null = everything
// (an account never given a list), shown as all ticked and saved as an explicit list.
export function AccessPicks({ consumers, value, onChange, legend }) {
  if (!consumers || !consumers.length) return null;
  const all = value === null || value === undefined;
  const has = (id) => all || value.includes(id);
  const label = (c) => c.kind === "ldap" ? t("users.acc.ldap") : c.kind === "wifi" ? t("users.acc.wifi") : c.kind === "oidc" ? t("users.acc.oidc", c.name) : t("users.acc.sync", c.name);
  return html`<fieldset class="hn-g"><legend>${legend || t("users.access")}</legend><div>
    ${consumers.map((c) => html`<label class="check"><input type="checkbox" checked=${has(c.id)}
      onChange=${(e) => { const on = e.target.checked; onChange((cur) => { const base = cur === null || cur === undefined ? consumers.map((x) => x.id) : cur; return on ? [...base, c.id] : base.filter((x) => x !== c.id); }); }} /> ${label(c)}</label>`)}</div>
    <span class="muted small">${t("users.accesshint")}</span></fieldset>`;
}

// MailPicks: the mail domains keelMail offers, one mailbox <name>@<domain> per tick.
function MailPicks({ domains, name, value, onChange }) {
  if (!domains || !domains.length) return null;
  return html`<fieldset class="hn-g"><legend>${t("users.mailboxes")}</legend><div>
    ${domains.map((d) => html`<label class="check"><input type="checkbox" checked=${value.includes(d)}
      onChange=${(e) => { const on = e.target.checked; onChange((cur) => (on ? [...cur, d] : cur.filter((x) => x !== d))); }} /> ${(name || "…") + "@" + d}</label>`)}</div>
    <span class="muted small">${t("users.mailboxeshint")}</span></fieldset>`;
}

function NewUser({ groups, consumers, domains, onClose, onDone }) {
  const pol = usePwPolicy();
  const [f, setF] = useState({ name: "", display_name: "", mail: "", password: "", auto: true, must_change: true, groups: [], access: null, mail_domains: [] });
  const set = (k) => (e) => { const v = e.target.type === "checkbox" ? e.target.checked : e.target.value; setF((f) => ({ ...f, [k]: v })); };
  const save = async () => {
    const body = { name: f.name.trim(), display_name: f.display_name.trim(), mail: f.mail.trim(), must_change: f.must_change, groups: f.groups, mail_domains: f.mail_domains };
    if (f.access !== null) body.access = f.access;
    if (!f.auto) body.password = f.password;
    onDone(await api("POST", "v1/users", body));
  };
  return html`<${FormDialog} title=${t("users.new")} submit=${t("users.add")} onSubmit=${save} onClose=${onClose}>
    <label>${t("users.name")}<input type="text" required pattern=${namePattern} spellcheck="false" autocapitalize="off" value=${f.name} onInput=${set("name")} />
      <span class="muted small">${t("users.namehint")}</span></label>
    <label>${t("users.display")}<input type="text" value=${f.display_name} onInput=${set("display_name")} /></label>
    <label>${t("users.mail")}<input type="text" inputmode="email" value=${f.mail} onInput=${set("mail")} /></label>
    <${MailPicks} domains=${domains} name=${f.name.trim()} value=${f.mail_domains} onChange=${(up) => setF((f) => ({ ...f, mail_domains: up(f.mail_domains) }))} />
    <label class="check"><input type="checkbox" checked=${f.auto} onChange=${set("auto")} /> ${t("users.autopw")}</label>
    ${!f.auto && html`<label>${t("users.password")}<input type="password" autocomplete="new-password" minlength=${pwMin(pol)} required value=${f.password} onInput=${set("password")} />
      <span class="muted small">${pwRules(pol)}</span></label>`}
    <label class="check"><input type="checkbox" checked=${f.must_change} onChange=${set("must_change")} /> ${t("users.mustchange")}</label>
    <${GroupPicks} groups=${groups} value=${f.groups} onChange=${(up) => setF((f) => ({ ...f, groups: up(f.groups) }))} />
    <${AccessPicks} consumers=${consumers} value=${f.access} onChange=${(up) => setF((f) => ({ ...f, access: up(f.access) }))} />
  <//>`;
}

function EditUser({ user, groups, consumers, domains, onClose, onDone }) {
  const [f, setF] = useState({ display_name: user.display_name, mail: user.mail, groups: user.groups, must_change: user.must_change, access: user.access === undefined ? null : user.access, mail_domains: user.mail_domains || [] });
  const set = (k) => (e) => { const v = e.target.type === "checkbox" ? e.target.checked : e.target.value; setF((f) => ({ ...f, [k]: v })); };
  const save = async () => { const body = { ...f }; if (body.access === null) delete body.access; await api("PATCH", "v1/users/" + enc(user.name), body); onDone(); };
  return html`<${FormDialog} title=${t("users.edit", user.name)} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("users.display")}<input type="text" value=${f.display_name} onInput=${set("display_name")} /></label>
    <label>${t("users.mail")}<input type="text" inputmode="email" value=${f.mail} onInput=${set("mail")} /></label>
    <${MailPicks} domains=${domains} name=${user.name} value=${f.mail_domains} onChange=${(up) => setF((f) => ({ ...f, mail_domains: up(f.mail_domains) }))} />
    <${GroupPicks} groups=${groups} value=${f.groups} onChange=${(up) => setF((f) => ({ ...f, groups: up(f.groups) }))} />
    <${AccessPicks} consumers=${consumers} value=${f.access} onChange=${(up) => setF((f) => ({ ...f, access: up(f.access) }))} />
    <label class="check"><input type="checkbox" checked=${f.must_change} onChange=${set("must_change")} /> ${t("users.mustchange")}</label>
  <//>`;
}

function ResetPassword({ user, onClose, onDone }) {
  const pol = usePwPolicy();
  const [auto, setAuto] = useState(true);
  const [pw, setPw] = useState("");
  const [must, setMust] = useState(true);
  const save = async () => {
    const r = await api("POST", "v1/users/" + enc(user.name) + "/password", auto ? { must_change: must } : { password: pw, must_change: must });
    onDone(r.password);
  };
  return html`<${FormDialog} title=${t("users.resettitle", user.name)} submit=${t("users.reset")} onSubmit=${save} onClose=${onClose}>
    <p class="muted small">${t("users.resetnote")}</p>
    <label class="check"><input type="checkbox" checked=${auto} onChange=${(e) => setAuto(e.target.checked)} /> ${t("users.autopw")}</label>
    ${!auto && html`<label>${t("users.password")}<input type="password" autocomplete="new-password" minlength=${pwMin(pol)} required value=${pw} onInput=${(e) => setPw(e.target.value)} />
      <span class="muted small">${pwRules(pol)}</span></label>`}
    <label class="check"><input type="checkbox" checked=${must} onChange=${(e) => setMust(e.target.checked)} /> ${t("users.mustchange")}</label>
  <//>`;
}

function Flags({ u }) {
  return html`${!u.enabled && html`<span class="badge" style="color:var(--danger);border-color:var(--danger)">${t("users.disabled")}</span> `}
    ${u.admin && html`<span class="badge ok">${t("users.admin")}</span> `}
    ${u.must_change && html`<span class="badge">${t("users.mustshort")}</span> `}
    ${!u.has_nt && u.enabled && html`<span class="badge" title=${t("users.nonttip")} style="color:var(--warn);border-color:var(--warn)">${t("users.nont")}</span>`}`;
}

export function Users() {
  const [us, setUs] = useState(null);
  const [groups, setGroups] = useState([]);
  const [consumers, setConsumers] = useState([]);
  const [domains, setDomains] = useState([]);
  const [dlg, setDlg] = useState(null);
  const load = () => Promise.all([api("GET", "v1/users"), api("GET", "v1/groups"), api("GET", "v1/consumers").catch(() => ({}))])
    .then(([u, g, c]) => { setUs(u.users || []); setGroups(g.groups || []); setConsumers(c.consumers || []); setDomains(c.mail_domains || []); }).catch(fail);
  useEffect(() => { load(); }, []);
  if (!us) return html`<${Spinner} />`;
  const close = () => setDlg(null);
  const toggle = async (u) => {
    if (u.enabled && !await ask(t("users.disableq", u.name))) return;
    try { await api("PATCH", "v1/users/" + enc(u.name), { enabled: !u.enabled }); load(); } catch (e) { fail(e); }
  };
  const del = async (u) => {
    if (!await ask(t("users.deleteq", u.name))) return;
    try { await api("DELETE", "v1/users/" + enc(u.name)); load(); } catch (e) { fail(e); }
  };
  return html`<div class="card"><div class="row-head"><h3>${t("nav.users")} <span class="muted small">${us.length}</span></h3>
      <button class="primary" onClick=${() => setDlg({ kind: "new" })}>${t("users.new")}</button></div>
    ${us.length === 0 && html`<p class="muted">${t("users.none")}</p>`}
    ${us.length > 0 && html`<div class="table-wrap tall"><table class="data plain">
      <thead><tr><th>${t("users.name")}</th><th>${t("users.display")}</th><th>${t("users.mail")}</th><th>${t("users.groups")}</th><th>${t("users.setat")}</th><th></th></tr></thead>
      <tbody>${us.map((u) => html`<tr class=${u.enabled ? "" : "stale"}><td class="nowrap"><b>${u.name}</b> <${Flags} u=${u} /></td><td>${u.display_name}</td><td>${[u.mail, ...(u.addresses || [])].filter(Boolean).join(", ")}</td>
        <td>${u.groups.join(", ") || "–"}</td><td>${u.password_set_at ? fmtTime(u.password_set_at) : "–"}</td>
        <td class="nowrap"><button class="btn" onClick=${() => setDlg({ kind: "edit", user: u })}>${t("edit")}</button>
          <button class="btn" onClick=${() => setDlg({ kind: "reset", user: u })}>${t("users.reset")}</button>
          <button class="btn" onClick=${() => toggle(u)}>${u.enabled ? t("users.disable") : t("users.enable")}</button>
          <button class="btn danger" onClick=${() => del(u)}>${t("delete")}</button></td></tr>`)}</tbody></table></div>`}
    <p class="muted small">${t("users.note")}</p>
    ${dlg && dlg.kind === "new" && html`<${NewUser} groups=${groups} consumers=${consumers} domains=${domains} onClose=${close}
      onDone=${(u) => { load(); setTimeout(() => setDlg(u.password ? { kind: "shown", user: u, pw: u.password } : null)); }} />`}
    ${dlg && dlg.kind === "edit" && html`<${EditUser} user=${dlg.user} groups=${groups} consumers=${consumers} domains=${domains} onClose=${close} onDone=${load} />`}
    ${dlg && dlg.kind === "reset" && html`<${ResetPassword} user=${dlg.user} onClose=${close}
      onDone=${(pw) => { load(); setTimeout(() => setDlg(pw ? { kind: "shown", user: dlg.user, pw } : null)); if (!pw) toast(t("users.pwset")); }} />`}
    ${dlg && dlg.kind === "shown" && html`<${Shown} title=${t("users.pwfor", dlg.user.name)} rows=${[[t("users.name"), dlg.user.name], [t("users.password"), dlg.pw]]}
      note=${t("users.pwonce")} onClose=${close} />`}
  </div>`;
}
