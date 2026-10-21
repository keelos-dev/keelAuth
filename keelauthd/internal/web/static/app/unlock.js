// Unlock: keelauthd's master key is locked (the data disk under another seed, or a standalone
// keelAuth's new system disk): the recovery key (keelOS: Accounts → Recovery key) or the
// recovery passphrase opens it. Nothing else works until then.
import { useState } from "preact/hooks";
import { api, html } from "./api.js";
import { t } from "./i18n.js";

export function Unlock({ onDone }) {
  const [v, setV] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async (ev) => {
    ev.preventDefault();
    setErr("");
    setBusy(true);
    const s = v.trim();
    const body = /^kar1[\s-]/i.test(s) ? { recovery_key: s } : { passphrase: v };
    try { await api("POST", "unlock", body); setV(""); onDone(); } catch (e) { setErr(e.message); }
    setBusy(false);
  };
  return html`<form class="stack" onSubmit=${submit}>
    <p class="warn small">${t("lock.why")}</p>
    <input type="password" autocomplete="off" spellcheck="false" placeholder=${t("lock.input")} required value=${v} onInput=${(e) => setV(e.target.value)} />
    <button type="submit" class="primary" disabled=${busy}>${t("lock.button")}</button>
    ${err && html`<p class="error">${err}</p>`}
    <p class="muted small">${t("lock.hint")}</p>
  </form>`;
}
