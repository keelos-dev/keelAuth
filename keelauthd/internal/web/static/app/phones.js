// Phones: the phones enrolled for logging in (the phone module): everybody sees and manages
// their own on the password page, an administrator anybody's in the user dialog. Adding one
// shows a QR code (keelApp scans it) and waits until the phone registered.
import { useEffect, useState } from "preact/hooks";
import { api, html } from "./api.js";
import { fmtTime, t } from "./i18n.js";
import { ask, toast } from "./ui.js";

export function Phones({ user }) {
  const [d, setD] = useState(null);
  const [enrol, setEnrol] = useState(null); // {id, qr, state}
  const q = user ? "?user=" + encodeURIComponent(user) : "";
  const load = () => api("GET", "v1/phones" + q).then(setD).catch(() => setD({ phones: [], enabled: false }));
  useEffect(() => { load(); }, [user]);
  useEffect(() => {
    if (!enrol || enrol.state !== "pending") return undefined;
    const id = setInterval(async () => {
      try {
        const x = await api("GET", "v1/phones/enroll/" + enrol.id);
        if (x.state === "done") { setEnrol(null); toast(t("phones.added", x.phone.name)); load(); } else if (x.state === "expired") setEnrol((e) => ({ ...e, state: "expired" }));
      } catch (_) { /* next time */ }
    }, 2000);
    return () => clearInterval(id);
  }, [enrol && enrol.id, enrol && enrol.state]);
  if (!d || !d.enabled) return null;
  const add = async () => {
    try { const e = await api("POST", "v1/phones/enroll", user ? { user } : {}); setEnrol({ id: e.id, qr: e.qr, state: "pending" }); } catch (e) { toast(e.message, 8000); }
  };
  const del = async (p) => {
    if (!await ask(t("phones.removeq", p.name))) return;
    try { await api("DELETE", "v1/phones/" + p.id); load(); } catch (e) { toast(e.message, 8000); }
  };
  return html`<fieldset class="hn-g"><legend>${t("phones.title")}</legend>
    ${d.phones.length === 0 && !enrol && html`<p class="muted small">${t("phones.none")}</p>`}
    ${d.phones.length > 0 && html`<table class="data plain"><tbody>${d.phones.map((p) => html`<tr key=${p.id}><td>${p.name}${p.platform ? html` <span class="muted small">${p.platform}</span>` : null}</td>
      <td class="muted small">${t("phones.added2", fmtTime(p.created))}${p.last_used ? " · " + t("phones.lastused", fmtTime(p.last_used)) : ""}</td>
      <td class="actions"><button type="button" class="btn" onClick=${() => del(p)}>${t("phones.remove")}</button></td></tr>`)}</tbody></table>`}
    ${enrol ? html`<div class="phone-enrol">${enrol.state === "pending" ? html`<img src=${enrol.qr} alt="" /><p class="muted small">${t("phones.scan")}</p>`
      : html`<p class="warn small">${t("phones.expired")}</p>`}
      <button type="button" class="btn" onClick=${() => setEnrol(null)}>${t("cancel")}</button></div>`
      : html`<button type="button" class="btn" onClick=${add}>${t("phones.add")}</button>`}
  </fieldset>`;
}
