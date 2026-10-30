// The own password: everybody who logs in can change theirs here; somebody whose password was
// set by an administrator with "must change" lands here first.
import { useEffect, useState } from "preact/hooks";
import { api, html } from "./api.js";
import { pwRules, t } from "./i18n.js";
import { toast } from "./ui.js";

export function OwnPassword({ session, onDone, onLogout }) {
  const [pol, setPol] = useState(null);
  useEffect(() => { api("GET", "v1/status").then((x) => setPol(x.password_policy || null)).catch(() => {}); }, []);
  const [old, setOld] = useState("");
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (ev) => {
    ev.preventDefault();
    setErr("");
    if (pw !== pw2) { setErr(t("pw.mismatch")); return; }
    setBusy(true);
    try {
      await api("POST", "password", { old, new: pw });
      setOld(""); setPw(""); setPw2("");
      toast(t("pw.changed"));
      onDone();
    } catch (e) { setErr(e.message); }
    setBusy(false);
  };
  return html`<h1>${t("pw.title")}</h1>
    <p class="muted small host">${session.display_name || session.name} (${session.name})</p>
    ${session.must_change && html`<p class="warn small">${t("pw.must")}</p>`}
    ${!session.admin && !session.must_change && html`<p class="muted small">${t("pw.useronly")}</p>`}
    <form class="stack" onSubmit=${submit}>
      <label>${t("pw.old")}<input type="password" autocomplete="current-password" required value=${old} onInput=${(e) => setOld(e.target.value)} /></label>
      <label>${t("pw.new")}<input type="password" autocomplete="new-password" minlength=${pol && pol.min_length ? pol.min_length : 15} required value=${pw} onInput=${(e) => setPw(e.target.value)} /></label>
      <label>${t("pw.again")}<input type="password" autocomplete="new-password" minlength=${pol && pol.min_length ? pol.min_length : 15} required value=${pw2} onInput=${(e) => setPw2(e.target.value)} /></label>
      <button type="submit" class="primary" disabled=${busy}>${t("pw.change")}</button>
    </form>
    ${err && html`<p class="error">${err}</p>`}
    <p class="muted small">${pwRules(pol)}</p>
    ${onLogout && html`<p class="small"><a href="#" onClick=${(e) => { e.preventDefault(); onLogout(); }}>${t("top.logout")}</a></p>`}`;
}
