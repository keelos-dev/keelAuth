// Totp: the second-factor code (the totp module): everybody sets up their own on the
// password page (QR code for the authenticator app, confirmed with the first code); an
// administrator sees whether a user has one and can remove it (phone lost).
import { useEffect, useState } from "preact/hooks";
import { api, html } from "./api.js";
import { fmtTime, t } from "./i18n.js";
import { ask, toast } from "./ui.js";

export function Totp({ user }) {
  const [d, setD] = useState(null);
  const [enrol, setEnrol] = useState(null); // {qr, secret}
  const [code, setCode] = useState("");
  const [err, setErr] = useState("");
  const q = user ? "?user=" + encodeURIComponent(user) : "";
  const load = () => api("GET", "v1/totp" + q).then(setD).catch(() => setD({ enabled: false }));
  useEffect(() => { load(); }, [user]);
  if (!d || !d.enabled) return null;
  const start = async () => { setErr(""); try { setEnrol(await api("POST", "v1/totp/enroll", {})); } catch (e) { toast(e.message, 8000); } };
  const confirm = async (ev) => {
    ev.preventDefault(); setErr("");
    try { await api("POST", "v1/totp/confirm", { code }); setEnrol(null); setCode(""); toast(t("totp.confirmed")); load(); } catch (e) { setErr(e.message); }
  };
  const del = async () => {
    if (!await ask(t(user ? "totp.resetq" : "totp.removeq"))) return;
    try { await api("DELETE", "v1/totp" + q); load(); } catch (e) { toast(e.message, 8000); }
  };
  return html`<fieldset class="hn-g"><legend>${t("totp.title")}</legend>
    ${d.set ? html`<div class="row"><span>${t("totp.set", fmtTime(d.set_at))}</span> <button type="button" class="btn" onClick=${del}>${t(user ? "totp.reset" : "totp.remove")}</button></div>`
      : user ? html`<p class="muted small">${t("totp.none")}</p>`
      : enrol ? html`<form class="phone-enrol" onSubmit=${confirm}><img src=${enrol.qr} alt="" />
          <p class="muted small">${t("totp.scan")}</p><p class="mono small">${enrol.secret}</p>
          <input type="text" inputmode="numeric" autocomplete="one-time-code" placeholder=${t("totp.code")} value=${code} onInput=${(e) => setCode(e.target.value)} required />
          ${err && html`<p class="error small">${err}</p>`}
          <div class="actions"><button type="button" class="btn" onClick=${() => setEnrol(null)}>${t("cancel")}</button><button type="submit" class="primary">${t("totp.confirm")}</button></div></form>`
      : html`<p class="muted small">${t("totp.why")}</p><button type="button" class="btn" onClick=${start}>${t("totp.setup")}</button>`}
  </fieldset>`;
}
