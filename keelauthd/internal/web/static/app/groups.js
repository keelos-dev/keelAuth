// Groups: the list; adding and changing members in dialogs.
import { useEffect, useState } from "preact/hooks";
import { api, html } from "./api.js";
import { t } from "./i18n.js";
import { ask, FormDialog, Spinner, toast } from "./ui.js";
import { namePattern } from "./users.js";

const fail = (e) => toast(e.message, 8000);
const enc = encodeURIComponent;

function Members({ users, value, onChange }) {
  if (!users.length) return html`<p class="muted small">${t("groups.nousers")}</p>`;
  return html`<fieldset class="hn-g"><legend>${t("groups.members")}</legend><div>
    ${users.map((u) => html`<label class="check"><input type="checkbox" checked=${value.includes(u.name)}
      onChange=${(e) => { const on = e.target.checked; onChange((cur) => (on ? [...cur, u.name] : cur.filter((x) => x !== u.name))); }} /> ${u.name}${u.display_name && u.display_name !== u.name ? html` <span class="muted">(${u.display_name})</span>` : ""}</label>`)}</div></fieldset>`;
}

function GroupForm({ group, users, onClose, onDone }) {
  const [name, setName] = useState("");
  const [desc, setDesc] = useState(group ? group.description : "");
  const [mem, setMem] = useState(group ? group.members : []);
  const save = async () => {
    if (group) await api("PATCH", "v1/groups/" + enc(group.name), { description: desc, members: [...mem, ...(group.member_groups || [])] });
    else await api("POST", "v1/groups", { name: name.trim(), description: desc.trim(), members: mem });
    onDone();
  };
  return html`<${FormDialog} title=${group ? t("groups.edit", group.name) : t("groups.new")} submit=${group ? t("save") : t("groups.add")} onSubmit=${save} onClose=${onClose}>
    ${!group && html`<label>${t("groups.name")}<input type="text" required pattern=${namePattern} spellcheck="false" autocapitalize="off" value=${name} onInput=${(e) => setName(e.target.value)} /></label>`}
    <label>${t("groups.desc")}<input type="text" value=${desc} onInput=${(e) => setDesc(e.target.value)} /></label>
    <${Members} users=${users} value=${mem} onChange=${setMem} />
    ${group && group.builtin && html`<p class="warn small">${t("groups.adminnote")}</p>`}
  <//>`;
}

export function Groups() {
  const [gs, setGs] = useState(null);
  const [users, setUsers] = useState([]);
  const [dlg, setDlg] = useState(null);
  const load = () => Promise.all([api("GET", "v1/groups"), api("GET", "v1/users")])
    .then(([g, u]) => { setGs(g.groups || []); setUsers(u.users || []); }).catch(fail);
  useEffect(() => { load(); }, []);
  if (!gs) return html`<${Spinner} />`;
  const del = async (g) => {
    if (!await ask(t("groups.deleteq", g.name))) return;
    try { await api("DELETE", "v1/groups/" + enc(g.name)); load(); } catch (e) { fail(e); }
  };
  const close = () => setDlg(null);
  return html`<div class="card"><div class="row-head"><h3>${t("nav.groups")} <span class="muted small">${gs.length}</span></h3>
      <button class="primary" onClick=${() => setDlg({ kind: "new" })}>${t("groups.new")}</button></div>
    <div class="table-wrap tall"><table class="data plain">
      <thead><tr><th>${t("groups.name")}</th><th>${t("groups.desc")}</th><th>${t("groups.members")}</th><th></th></tr></thead>
      <tbody>${gs.map((g) => html`<tr><td><b>${g.name}</b>${g.builtin ? html` <span class="badge">${t("groups.builtin")}</span>` : ""}</td>
        <td>${g.builtin && !g.description ? t("groups.admindesc") : g.description}</td><td>${g.members.join(", ") || ((g.member_groups || []).length ? "" : "–")}${(g.member_groups || []).map((n, i) => html`${g.members.length || i ? ", " : ""}${n} <span class="muted small">[${t("groups.group")}]</span>`)}</td>
        <td class="nowrap"><button class="btn" onClick=${() => setDlg({ kind: "edit", group: g })}>${t("edit")}</button>
          ${!g.builtin && html`<button class="btn danger" onClick=${() => del(g)}>${t("delete")}</button>`}</td></tr>`)}</tbody></table></div>
    <p class="muted small">${t("groups.note")}</p>
    ${dlg && dlg.kind === "new" && html`<${GroupForm} users=${users} onClose=${close} onDone=${load} />`}
    ${dlg && dlg.kind === "edit" && html`<${GroupForm} group=${dlg.group} users=${users} onClose=${close} onDone=${load} />`}
  </div>`;
}
