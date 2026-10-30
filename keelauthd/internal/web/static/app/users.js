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

function NewUser({ groups, onClose, onDone }) {
  const pol = usePwPolicy();
  const [f, setF] = useState({ name: "", display_name: "", mail: "", password: "", auto: true, must_change: true, groups: [] });
  const set = (k) => (e) => { const v = e.target.type === "checkbox" ? e.target.checked : e.target.value; setF((f) => ({ ...f, [k]: v })); };
  const save = async () => {
    const body = { name: f.name.trim(), display_name: f.display_name.trim(), mail: f.mail.trim(), must_change: f.must_change, groups: f.groups };
    if (!f.auto) body.password = f.password;
    onDone(await api("POST", "v1/users", body));
  };
  return html`<${FormDialog} title=${t("users.new")} submit=${t("users.add")} onSubmit=${save} onClose=${onClose}>
    <label>${t("users.name")}<input type="text" required pattern=${namePattern} spellcheck="false" autocapitalize="off" value=${f.name} onInput=${set("name")} />
      <span class="muted small">${t("users.namehint")}</span></label>
    <label>${t("users.display")}<input type="text" value=${f.display_name} onInput=${set("display_name")} /></label>
    <label>${t("users.mail")}<input type="text" inputmode="email" value=${f.mail} onInput=${set("mail")} /></label>
    <label class="check"><input type="checkbox" checked=${f.auto} onChange=${set("auto")} /> ${t("users.autopw")}</label>
    ${!f.auto && html`<label>${t("users.password")}<input type="password" autocomplete="new-password" minlength=${pwMin(pol)} required value=${f.password} onInput=${set("password")} />
      <span class="muted small">${pwRules(pol)}</span></label>`}
    <label class="check"><input type="checkbox" checked=${f.must_change} onChange=${set("must_change")} /> ${t("users.mustchange")}</label>
    <${GroupPicks} groups=${groups} value=${f.groups} onChange=${(up) => setF((f) => ({ ...f, groups: up(f.groups) }))} />
  <//>`;
}

function EditUser({ user, groups, onClose, onDone }) {
  const [f, setF] = useState({ display_name: user.display_name, mail: user.mail, groups: user.groups, must_change: user.must_change });
  const set = (k) => (e) => { const v = e.target.type === "checkbox" ? e.target.checked : e.target.value; setF((f) => ({ ...f, [k]: v })); };
  const save = async () => { await api("PATCH", "v1/users/" + enc(user.name), f); onDone(); };
  return html`<${FormDialog} title=${t("users.edit", user.name)} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("users.display")}<input type="text" value=${f.display_name} onInput=${set("display_name")} /></label>
    <label>${t("users.mail")}<input type="text" inputmode="email" value=${f.mail} onInput=${set("mail")} /></label>
    <${GroupPicks} groups=${groups} value=${f.groups} onChange=${(up) => setF((f) => ({ ...f, groups: up(f.groups) }))} />
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
  const [dlg, setDlg] = useState(null);
  const load = () => Promise.all([api("GET", "v1/users"), api("GET", "v1/groups")])
    .then(([u, g]) => { setUs(u.users || []); setGroups(g.groups || []); }).catch(fail);
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
      <tbody>${us.map((u) => html`<tr class=${u.enabled ? "" : "stale"}><td class="nowrap"><b>${u.name}</b> <${Flags} u=${u} /></td><td>${u.display_name}</td><td>${u.mail}</td>
        <td>${u.groups.join(", ") || "–"}</td><td>${u.password_set_at ? fmtTime(u.password_set_at) : "–"}</td>
        <td class="nowrap"><button class="btn" onClick=${() => setDlg({ kind: "edit", user: u })}>${t("edit")}</button>
          <button class="btn" onClick=${() => setDlg({ kind: "reset", user: u })}>${t("users.reset")}</button>
          <button class="btn" onClick=${() => toggle(u)}>${u.enabled ? t("users.disable") : t("users.enable")}</button>
          <button class="btn danger" onClick=${() => del(u)}>${t("delete")}</button></td></tr>`)}</tbody></table></div>`}
    <p class="muted small">${t("users.note")}</p>
    ${dlg && dlg.kind === "new" && html`<${NewUser} groups=${groups} onClose=${close}
      onDone=${(u) => { load(); setTimeout(() => setDlg(u.password ? { kind: "shown", user: u, pw: u.password } : null)); }} />`}
    ${dlg && dlg.kind === "edit" && html`<${EditUser} user=${dlg.user} groups=${groups} onClose=${close} onDone=${load} />`}
    ${dlg && dlg.kind === "reset" && html`<${ResetPassword} user=${dlg.user} onClose=${close}
      onDone=${(pw) => { load(); setTimeout(() => setDlg(pw ? { kind: "shown", user: dlg.user, pw } : null)); if (!pw) toast(t("users.pwset")); }} />`}
    ${dlg && dlg.kind === "shown" && html`<${Shown} title=${t("users.pwfor", dlg.user.name)} rows=${[[t("users.name"), dlg.user.name], [t("users.password"), dlg.pw]]}
      note=${t("users.pwonce")} onClose=${close} />`}
  </div>`;
}
