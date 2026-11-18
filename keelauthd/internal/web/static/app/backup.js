// Backups: the list, back up now, restore one, how many to keep.
import { useEffect, useState } from "preact/hooks";
import { api, html, rel, upload } from "./api.js";
import { fmtTime, t } from "./i18n.js";
import { ask, Dialog, fsize, FormDialog, Spinner, toast } from "./ui.js";

const fail = (e) => toast(e.message, 8000);
const toLines = (l) => (l || []).join("\n");
const fromLines = (v) => v.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

function SnapKeep({ d, onClose, onDone }) {
  const [h, setH] = useState(String(d.hourly));
  const [dd, setDd] = useState(String(d.daily));
  const save = async () => { await api("PUT", "v1/snapshots/keep", { hourly: Number(h), daily: Number(dd) }); onDone(); };
  return html`<${FormDialog} title=${t("sn.keep")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("sn.hourly")}<input type="number" min="0" max="168" required value=${h} onInput=${(e) => setH(e.target.value)} /></label>
    <label>${t("sn.daily")}<input type="number" min="0" max="400" required value=${dd} onInput=${(e) => setDd(e.target.value)} /></label>
    <p class="muted small">${t("sn.keephint")}</p>
  <//>`;
}

function PullAllow({ allow, onClose, onDone }) {
  const [v, setV] = useState(toLines(allow));
  const save = async () => { await api("PUT", "v1/backup/pull-allow", { allow: fromLines(v) }); onDone(); };
  return html`<${FormDialog} title=${t("pl.allow")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("pl.allowl")}<textarea rows="4" spellcheck="false" value=${v} onInput=${(e) => setV(e.target.value)}></textarea></label>
    <p class="muted small">${t("pl.allowhint")}</p>
  <//>`;
}

// PullNew: the address the backup machine reaches this keelAuth at goes into the token.
function PullNew({ onClose, onMade }) {
  const [host, setHost] = useState("");
  const save = async () => { const r = await api("POST", "v1/backup/pull-token", { host: host.trim() }); onMade(r.token); };
  return html`<${FormDialog} title=${t("pl.new")} submit=${t("pl.new")} onSubmit=${save} onClose=${onClose}>
    <label>${t("pl.host")}<input spellcheck="false" autocomplete="off" placeholder="192.0.2.10" value=${host} onInput=${(e) => setHost(e.target.value)} /></label>
  <//>`;
}

// Fetching by the backup machine (keelNAS docs/08): the pull token and the last fetch.
function Pull({ p, onDone }) {
  const [shown, setShown] = useState(null);
  const [dlg, setDlg] = useState(null);
  const make = async () => {
    if (p.token_set && !await ask(t("pl.newq"))) return;
    setDlg("new");
  };
  const revoke = async () => {
    if (!await ask(t("pl.revokeq"))) return;
    try { await api("DELETE", "v1/backup/pull-token"); onDone(); } catch (e) { fail(e); }
  };
  return html`<h4>${t("pl.title")}</h4>
    <p class="muted small">${t("pl.for")}</p>
    <table class="kv-table"><tbody>
      <tr><th>${t("pl.token")}</th><td>${p.token_set ? t("pl.made", fmtTime(p.token_at)) : t("pl.none")}${p.token_stale ? html` <span class="warn">${t("pl.stale")}</span>` : null}</td></tr>
      <tr><th>${t("pl.last")}</th><td>${p.last_at ? t("pl.lastv", fmtTime(p.last_at), p.last_snap, p.last_from) : "–"}</td></tr>
      <tr><th>${t("pl.allow")}</th><td>${p.allow.length ? p.allow.join(", ") : t("pl.anyone")}</td></tr>
    </tbody></table>
    <p><button class="btn" onClick=${make}>${p.token_set ? t("pl.renew") : t("pl.new")}</button>
      ${p.token_set && html` <button class="btn" onClick=${revoke}>${t("pl.revoke")}</button>`}
      <button class="btn" onClick=${() => setDlg("allow")}>${t("pl.allow")}…</button></p>
    ${shown && html`<${Dialog} title=${t("pl.token")} onClose=${() => setShown(null)}>
      <p class="mono" style="word-break:break-all;user-select:all">${shown}</p><p class="warn small">${t("pl.once")}</p><//>`}
    ${dlg === "new" && html`<${PullNew} onClose=${() => setDlg(null)} onMade=${(tok) => { setDlg(null); setShown(tok); onDone(); }} />`}
    ${dlg === "allow" && html`<${PullAllow} allow=${p.allow} onClose=${() => setDlg(null)} onDone=${() => { setDlg(null); onDone(); }} />`}`;
}

// Snapshots of the data disk (docs/02 §3.3a).
function Snapshots() {
  const [d, setD] = useState(null);
  const [busy, setBusy] = useState(false);
  const [dlg, setDlg] = useState(false);
  const load = () => api("GET", "v1/snapshots").then(setD).catch(fail);
  useEffect(() => { load(); }, []);
  if (!d) return html`<${Spinner} />`;
  const now = async () => {
    setBusy(true);
    try { await api("POST", "v1/snapshots"); toast(t("sn.done")); load(); } catch (e) { fail(e); }
    setBusy(false);
  };
  const del = async (x) => {
    if (!await ask(t("sn.delq", fmtTime(x.time)))) return;
    try { await api("DELETE", "v1/snapshots/" + encodeURIComponent(x.name)); load(); } catch (e) { fail(e); }
  };
  return html`<div class="card"><div class="row-head"><h3>${t("sn.title")}</h3>
      ${d.dataset && html`<span><button class="btn" onClick=${() => setDlg(true)}>${t("sn.keep")}…</button> <button class="primary" disabled=${busy} onClick=${now}>${t("sn.now")}</button></span>`}</div>
    <p class="muted small">${d.dataset ? t("sn.note", d.hourly, d.daily) : t("sn.nodisk")}</p>
    ${d.dataset && d.snapshots.length === 0 && html`<p class="muted">${t("sn.none")}</p>`}
    ${d.snapshots.length > 0 && html`<div class="table-wrap tall"><table class="data plain">
      <thead><tr><th>${t("bk.time")}</th><th>${t("sn.kind")}</th><th>${t("sn.used")}</th><th></th></tr></thead>
      <tbody>${d.snapshots.map((x) => html`<tr><td>${fmtTime(x.time)}</td><td>${t("sn.k." + x.kind)}</td><td>${fsize(x.used)}</td>
        <td class="nowrap"><button class="btn" onClick=${() => del(x)}>${t("delete")}</button></td></tr>`)}</tbody></table></div>`}
    ${d.dataset && d.pull && html`<${Pull} p=${d.pull} onDone=${load} />`}
    ${dlg && html`<${SnapKeep} d=${d} onClose=${() => setDlg(false)} onDone=${() => { setDlg(false); load(); }} />`}
  </div>`;
}

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
  </div><${Snapshots} />`;
}
