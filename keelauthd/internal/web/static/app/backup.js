// Backups: the list, back up now, restore one, how many to keep.
import { useEffect, useState } from "preact/hooks";
import { api, html, rel, upload } from "./api.js";
import { fmtTime, t } from "./i18n.js";
import { ask, fsize, FormDialog, Spinner, toast } from "./ui.js";

const fail = (e) => toast(e.message, 8000);

function Keep({ keep, onClose, onDone }) {
  const [k, setK] = useState(keep);
  const save = async () => { await api("PUT", "v1/settings", { backup_keep: Number(k) }); onDone(); };
  return html`<${FormDialog} title=${t("bk.keep")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("bk.keepn")}<input type="number" min="1" max="365" required value=${k} onInput=${(e) => setK(e.target.value)} /></label>
  <//>`;
}

// KeyDialog: a backup of another keelAuth needs its recovery key or passphrase.
function KeyDialog({ b, onClose, onDone }) {
  const [v, setV] = useState("");
  const save = async () => {
    const x = v.trim();
    await api("POST", "v1/backups/" + encodeURIComponent(b.name) + "/restore", /^kar1[\s-]/i.test(x) ? { recovery_key: x } : { passphrase: v });
    onDone();
  };
  return html`<${FormDialog} title=${t("bk.keytitle", fmtTime(b.time))} submit=${t("bk.restore")} onSubmit=${save} onClose=${onClose}>
    <p class="muted small">${t("bk.keyfor")}</p>
    <label>${t("lock.input")}<input type="password" autocomplete="off" spellcheck="false" required value=${v} onInput=${(e) => setV(e.target.value)} /></label>
  <//>`;
}

export function Backups() {
  const [d, setD] = useState(null);
  const [busy, setBusy] = useState(false);
  const [dlg, setDlg] = useState(null);
  const load = () => api("GET", "v1/backups").then(setD).catch(fail);
  useEffect(() => { load(); }, []);
  if (!d) return html`<${Spinner} />`;
  const now = async () => {
    setBusy(true);
    try { await api("POST", "v1/backups"); toast(t("bk.done")); load(); } catch (e) { fail(e); }
    setBusy(false);
  };
  const restore = async (b) => {
    if (!await ask(t("bk.restoreq", fmtTime(b.time)))) return;
    setBusy(true);
    try {
      await api("POST", "v1/backups/" + encodeURIComponent(b.name) + "/restore");
      restored();
    } catch (e) {
      if (e.body && e.body.code === "need_recovery_key") setDlg({ kind: "key", b }); else fail(e);
    }
    setBusy(false);
  };
  const restored = () => { toast(t("bk.restored")); setTimeout(() => location.reload(), 1500); };
  const pick = (ev) => {
    const f = ev.target.files && ev.target.files[0];
    ev.target.value = "";
    if (!f) return;
    setBusy(true);
    upload("v1/backups/upload?name=" + encodeURIComponent(f.name), f).then((r) => { toast(t("bk.uploaded", r.name)); load(); }).catch(fail).finally(() => setBusy(false));
  };
  return html`<div class="card"><div class="row-head"><h3>${t("nav.backup")}</h3>
      <span><label class="btn ka-upload">${t("bk.upload")}<input type="file" accept=".tar.gz,.gz,application/gzip" hidden onChange=${pick} /></label>
        <button class="btn" onClick=${() => setDlg({ kind: "keep" })}>${t("bk.keep")}…</button> <button class="primary" disabled=${busy} onClick=${now}>${t("bk.now")}</button></span></div>
    ${d.backups.length === 0 && html`<p class="muted">${t("bk.none")}</p>`}
    ${d.backups.length > 0 && html`<div class="table-wrap tall"><table class="data plain">
      <thead><tr><th>${t("bk.time")}</th><th>${t("bk.size")}</th><th>${t("bk.file")}</th><th></th></tr></thead>
      <tbody>${d.backups.map((b) => html`<tr><td>${fmtTime(b.time)}</td><td>${fsize(b.size)}</td><td class="mono small">${b.name}</td>
        <td class="nowrap"><a class="btn" href=${rel("v1/backups/" + encodeURIComponent(b.name))} download=${b.name}>${t("bk.download")}</a>
          <button class="btn" disabled=${busy} onClick=${() => restore(b)}>${t("bk.restore")}</button></td></tr>`)}</tbody></table></div>`}
    <p class="muted small">${t("bk.note", d.keep, d.dir)}</p>
    ${dlg && dlg.kind === "keep" && html`<${Keep} keep=${d.keep} onClose=${() => setDlg(null)} onDone=${load} />`}
    ${dlg && dlg.kind === "key" && html`<${KeyDialog} b=${dlg.b} onClose=${() => setDlg(null)} onDone=${restored} />`}
  </div>`;
}
