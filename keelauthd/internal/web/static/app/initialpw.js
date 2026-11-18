// New initial passwords for many accounts at once (docs/07 section 1): the table of an import
// was not downloaded or got lost. Only accounts still waiting on their first password change
// are listed, and keelauthd skips any other; the new table is one CSV file, built here from
// what keelauthd answers, so it is nowhere once this dialog is closed.
import { useRef, useState } from "preact/hooks";
import { api, html } from "./api.js";
import { fmtTime, t } from "./i18n.js";
import { Dialog, Spinner } from "./ui.js";

const cell = (v) => { const s = v == null ? "" : String(v); return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
export function passwordsCSV(made) {
  const lines = [["account", "name", "mail", "initial password"],
    ...made.map((m) => [m.name, m.display_name, (m.addresses && m.addresses.length ? m.addresses.join(" ") : m.mail) || "", m.password])];
  return "﻿" + lines.map((l) => l.map(cell).join(",")).join("\r\n") + "\r\n"; // the mark: Excel reads it as UTF-8
}

export function InitialPasswords({ users, onClose, onChanged }) {
  const rows = users.filter((u) => u.must_change);
  const [ticks, setTicks] = useState({});
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [progress, setProgress] = useState(null);
  const [made, setMade] = useState([]);
  const [skipped, setSkipped] = useState([]);
  const link = useRef(null);

  const text = q.trim().toLowerCase();
  const shown = rows.filter((u) => !text || [u.name, u.display_name, u.mail, ...(u.addresses || [])].some((h) => h && h.toLowerCase().includes(text)));
  const names = rows.filter((u) => ticks[u.name]).map((u) => u.name);
  const allOn = shown.length > 0 && shown.every((u) => ticks[u.name]);
  const tickAll = (on) => setTicks((k) => { const n = { ...k }; for (const u of shown) n[u.name] = on; return n; });
  const save = (list) => {
    const url = URL.createObjectURL(new Blob([passwordsCSV(list)], { type: "text/csv;charset=utf-8" }));
    const a = link.current;
    a.href = url; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  };
  const run = async () => {
    setBusy(true); setErr("");
    const all = [...made], skip = [...skipped];
    try {
      // ten at a time: hashing a password takes a while, and the count shows it moving
      for (let i = 0; i < names.length; i += 10) {
        setProgress([i, names.length]);
        const o = await api("POST", "v1/passwords/initial", { names: names.slice(i, i + 10) });
        all.push(...(o.made || [])); skip.push(...(o.skipped || []));
        setMade([...all]); setSkipped([...skip]);
      }
      setTicks({});
    } catch (e) { setErr(e.message || String(e)); }
    setProgress(null); setBusy(false);
    if (all.length > made.length) { save(all); onChanged(); }
  };

  return html`<${Dialog} title=${t("initpw.title")} onClose=${onClose} wide=${true}><div class="stack">
    <p class="muted small">${t("initpw.intro")}</p>
    ${rows.length === 0 && html`<p class="muted">${t("initpw.none")}</p>`}
    ${rows.length > 0 && html`<div class="aud-bar"><input type="search" placeholder=${t("users.search")} value=${q} onInput=${(e) => setQ(e.target.value)} /></div>
    <div class="table-wrap tall"><table class="data plain">
      <thead><tr><th><input type="checkbox" checked=${allOn} disabled=${busy} title=${t("adimp.all")} onChange=${(e) => tickAll(e.target.checked)} /></th>
        <th>${t("users.name")}</th><th>${t("users.display")}</th><th>${t("users.mail")}</th><th>${t("users.setat")}</th></tr></thead>
      <tbody>${shown.map((u) => html`<tr key=${u.name} class=${u.enabled ? "" : "stale"}>
        <td><input type="checkbox" checked=${!!ticks[u.name]} disabled=${busy} onChange=${(e) => setTicks((k) => ({ ...k, [u.name]: e.target.checked }))} /></td>
        <td class="nowrap"><b>${u.name}</b></td><td>${u.display_name || "–"}</td><td>${[u.mail, ...(u.addresses || [])].filter(Boolean).join(", ") || "–"}</td>
        <td>${u.password_set_at ? fmtTime(u.password_set_at) : "–"}</td></tr>`)}</tbody></table></div>`}
    ${made.length > 0 && html`<p><b>${t("initpw.done", made.length)}</b> <button type="button" class="btn" onClick=${() => save(made)}>${t("adimp.csv")}</button>
      <span class="warn small"> ${t("initpw.csvnote")}</span></p>`}
    ${skipped.length > 0 && html`<p class="muted small">${t("initpw.skipped", skipped.join(", "))}</p>`}
    ${err && html`<p class="error">${err}</p>`}
    <a ref=${link} download="keelauth-initial-passwords.csv" style="display:none"></a>
    <div class="actions"><button type="button" class="primary" disabled=${busy || names.length === 0} onClick=${run}>${t("initpw.run", names.length)}</button>
      <button type="button" disabled=${busy} onClick=${onClose}>${t("dlg.close")}</button>${busy && html`<${Spinner} small=${true} />`}
      ${progress && html`<span>${t("initpw.progress", progress[0], progress[1])}</span>`}</div>
  </div><//>`;
}
