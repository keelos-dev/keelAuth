// Settings: general (time zone, the master key's protection), AI management (MCP tokens),
// keelNAS sync keys, the certificate. Sub-tabs; every change in a dialog.
import { useEffect, useState } from "preact/hooks";
import { api, html, rel } from "./api.js";
import { fmtTime, t } from "./i18n.js";
import { setZone, zones } from "./time.js";
import { ask, FormDialog, Spinner, toast } from "./ui.js";
import { Shown } from "./users.js";

const fail = (e) => toast(e.message, 8000);
const subs = ["general", "ai", "sync", "cert"];

function ZoneDialog({ zone, onClose, onDone }) {
  const [z, setZ] = useState(zone);
  const save = async () => { const r = await api("PUT", "v1/settings", { timezone: z }); setZone(r.timezone_in_use); onDone(); };
  return html`<${FormDialog} title=${t("gen.tztitle")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("gen.tz")}<select value=${z} onChange=${(e) => setZ(e.target.value)}>${zones().map((x) => html`<option value=${x}>${x}</option>`)}</select>
      <span class="muted small">${t("gen.tzfor")}</span></label>
  <//>`;
}

function PassDialog({ onClose, onDone }) {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const save = async () => {
    if (a !== b) throw new Error(t("gen.passdiff"));
    await api("PUT", "v1/recovery", { passphrase: a });
    toast(t("gen.passset"));
    onDone();
  };
  return html`<${FormDialog} title=${t("gen.setpass")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <p class="muted small">${t("gen.passfor")}</p>
    <label>${t("gen.pass")}<input type="password" autocomplete="new-password" minlength="12" required value=${a} onInput=${(e) => setA(e.target.value)} /></label>
    <label>${t("gen.pass2")}<input type="password" autocomplete="new-password" minlength="12" required value=${b} onInput=${(e) => setB(e.target.value)} /></label>
  <//>`;
}

function General() {
  const [s, setS] = useState(null);
  const [dlg, setDlg] = useState(null);
  const load = () => api("GET", "v1/settings").then(setS).catch(fail);
  useEffect(() => { load(); }, []);
  if (!s) return html`<${Spinner} />`;
  const mk = s.master_key || { slots: [] };
  const prot = mk.slots.includes("keel") ? t("gen.mkkeel") : mk.slots.includes("passphrase") ? t("gen.mkpass", fmtTime(mk.passphrase_set)) : null;
  return html`<div class="card"><div class="row-head"><h3>${t("set.general")}</h3></div>
    <table class="kv-table"><tbody>
      <tr><th>${t("gen.tz")}</th><td>${s.timezone_from_keel ? t("gen.tzkeel", s.timezone_in_use)
        : html`${s.timezone} <button class="btn" onClick=${() => setDlg("tz")}>${t("edit")}</button>`}</td></tr>
      <tr><th>${t("gen.mk")}</th><td>${prot ? prot : html`<span class="warn">${t("gen.mknone")}</span>`}
        ${!s.timezone_from_keel && html` <button class="btn" onClick=${() => setDlg("pass")}>${mk.slots.includes("passphrase") ? t("gen.changepass") : t("gen.setpass")}</button>`}</td></tr>
    </tbody></table>
    <p class="muted small">${s.timezone_from_keel ? t("gen.mkkeelnote") : t("gen.tzfor")}</p>
    ${dlg === "tz" && html`<${ZoneDialog} zone=${s.timezone} onClose=${() => setDlg(null)} onDone=${load} />`}
    ${dlg === "pass" && html`<${PassDialog} onClose=${() => setDlg(null)} onDone=${load} />`}
  </div>`;
}

function NewToken({ title, onClose, onDone, path }) {
  const [name, setName] = useState("");
  const save = async () => onDone(await api("POST", path, { name: name.trim() }));
  return html`<${FormDialog} title=${title} submit=${t("tok.make")} onSubmit=${save} onClose=${onClose}>
    <label>${t("tok.name")}<input type="text" required maxlength="64" value=${name} onInput=${(e) => setName(e.target.value)} />
      <span class="muted small">${t("tok.namehint")}</span></label>
  <//>`;
}

function TokenList({ list, onDelete }) {
  if (!list.length) return html`<p class="muted">${t("tok.none")}</p>`;
  return html`<div class="table-wrap tall"><table class="data plain">
    <thead><tr><th>${t("tok.name")}</th><th>ID</th><th>${t("tok.created")}</th><th>${t("tok.used")}</th><th></th></tr></thead>
    <tbody>${list.map((x) => html`<tr><td><b>${x.name}</b></td><td class="mono">${x.id}</td><td>${fmtTime(x.created)}</td><td>${x.last_used ? fmtTime(x.last_used) : "–"}</td>
      <td><button class="btn danger" onClick=${() => onDelete(x)}>${t("tok.revoke")}</button></td></tr>`)}</tbody></table></div>`;
}

function AI() {
  const [d, setD] = useState(null);
  const [dlg, setDlg] = useState(null);
  const [addr, setAddr] = useState("");
  const load = () => api("GET", "v1/tokens").then(setD).catch(fail);
  // keelAuth's own address on the LAN (not keel's, when this page comes through keel): the
  // assistant talks to keelAuth directly, its token checked by keelAuth
  useEffect(() => { load(); api("GET", "v1/status").then((s) => setAddr((s.addresses || [])[0] || s.domain)).catch(() => {}); }, []);
  if (!d) return html`<${Spinner} />`;
  const del = async (x) => {
    if (!await ask(t("tok.revokeq", x.name))) return;
    try { await api("DELETE", "v1/tokens/" + x.id); load(); } catch (e) { fail(e); }
  };
  const cmd = (tok) => "keel-mcp --host https://" + (addr || location.hostname) + " --token " + tok + " --fingerprint " + d.fingerprint;
  return html`<div class="card"><div class="row-head"><h3>${t("ai.title")}</h3><button class="primary" onClick=${() => setDlg({ kind: "new" })}>${t("ai.new")}</button></div>
    <p class="ka-for">${t("ai.for")}</p>
    <${TokenList} list=${d.tokens} onDelete=${del} />
    <h3 class="sub">${t("ai.connect")}</h3>
    <pre class="code">${cmd("kat_…")}</pre>
    <p class="muted small">${t("ai.note", d.fingerprint)}</p>
    ${dlg && dlg.kind === "new" && html`<${NewToken} title=${t("ai.new")} path="v1/tokens" onClose=${() => setDlg(null)}
      onDone=${(x) => { load(); setTimeout(() => setDlg({ kind: "shown", x })); }} />`}
    ${dlg && dlg.kind === "shown" && html`<${Shown} title=${t("ai.made", dlg.x.name)} onClose=${() => setDlg(null)}
      rows=${[[t("ai.token"), dlg.x.token], [t("ai.command"), cmd(dlg.x.token)]]} />`}
  </div>`;
}

function Sync() {
  const [d, setD] = useState(null);
  const [dlg, setDlg] = useState(null);
  const load = () => api("GET", "v1/sync/keys").then(setD).catch(fail);
  useEffect(() => { load(); }, []);
  if (!d) return html`<${Spinner} />`;
  const del = async (x) => {
    if (!await ask(t("tok.revokeq", x.name))) return;
    try { await api("DELETE", "v1/sync/keys/" + x.id); load(); } catch (e) { fail(e); }
  };
  return html`<div class="card"><div class="row-head"><h3>${t("sync.title")}</h3><button class="primary" onClick=${() => setDlg({ kind: "new" })}>${t("sync.new")}</button></div>
    <p class="ka-for">${t("sync.for")}</p>
    <${TokenList} list=${d.keys} onDelete=${del} />
    ${dlg && dlg.kind === "new" && html`<${NewToken} title=${t("sync.new")} path="v1/sync/keys" onClose=${() => setDlg(null)}
      onDone=${(x) => { load(); setTimeout(() => setDlg({ kind: "shown", x })); }} />`}
    ${dlg && dlg.kind === "shown" && html`<${Shown} title=${t("ai.made", dlg.x.name)} onClose=${() => setDlg(null)} rows=${[[t("sync.key"), dlg.x.key]]} />`}
  </div>`;
}

// OfficeForm: the office's own certificate for keelAuth's domain (docs/02 §7.10): PEM text or
// files; keelauthd checks it, switches and goes back by itself when the services refuse it.
function OfficeForm({ domain, onClose, onDone }) {
  const [cert, setCert] = useState("");
  const [key, setKey] = useState("");
  const file = (set) => async (e) => { const f = e.target.files[0]; if (f) set(await f.text()); };
  const save = async () => {
    const r = await api("POST", "v1/certs/office", { cert, key });
    if (r.warnings && r.warnings.length) toast(t("cert.warn", r.warnings.join("; ")), 10000);
    onDone(r);
  };
  return html`<${FormDialog} title=${t("cert.office")} submit=${t("cert.use")} onSubmit=${save} onClose=${onClose}>
    <p class="muted small">${t("cert.officefor", domain)}</p>
    <label>${t("cert.certfile")}<input type="file" accept=".pem,.crt,.cer,.txt" onChange=${file(setCert)} />
      <textarea class="ka-pem" rows="6" required spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----" value=${cert} onInput=${(e) => setCert(e.target.value)}></textarea>
      <span class="muted small">${t("cert.certhint")}</span></label>
    <label>${t("cert.keyfile")}<input type="file" accept=".pem,.key,.txt" onChange=${file(setKey)} />
      <textarea class="ka-pem" rows="4" spellcheck="false" placeholder="-----BEGIN PRIVATE KEY-----" value=${key} onInput=${(e) => setKey(e.target.value)}></textarea>
      <span class="muted small">${t("cert.keyhint")}</span></label>
    <p class="muted small">${t("cert.officenote")}</p>
  <//>`;
}

const until = (c) => html`${fmtTime(c.not_after)} <span class=${c.days_left < 30 ? "warn small" : "muted small"}>(${t("cert.days", c.days_left)})</span>`;
const fps = (c) => html`<div class="mono ka-fp">SHA-256 ${c.sha256}</div><div class="mono ka-fp muted">SHA-1 ${c.sha1}</div>`;

function Cert() {
  const [c, setC] = useState(null);
  const [s, setS] = useState(null);
  const [dlg, setDlg] = useState(false);
  const load = () => Promise.all([api("GET", "v1/certs"), api("GET", "v1/settings")]).then(([c, s]) => { setC(c); setS(s); }).catch(fail);
  useEffect(() => { load(); }, []);
  if (!c || !s) return html`<${Spinner} />`;
  const office = c.in_use === "office";
  const back = async () => {
    if (!await ask(t("cert.backq"))) return;
    try { setC(await api("DELETE", "v1/certs/office")); toast(t("cert.backdone")); } catch (e) { fail(e); }
  };
  const a = c.anchor;
  return html`<div class="card"><div class="row-head"><h3>${t("cert.title")}</h3><span class="grow"></span>
      ${office && html`<button class="btn" onClick=${back}>${t("cert.back")}</button>`}
      <button class="primary" onClick=${() => setDlg(true)}>${office ? t("cert.replace") : t("cert.office")}</button></div>
    <p class="ka-for">${office ? t("cert.forOffice") : t("cert.for")}</p>
    <table class="kv-table"><tbody>
      <tr><th>${t("cert.inuse")}</th><td>${office ? t("cert.inuseoffice", fmtTime(c.office_uploaded)) : t("cert.inuseown")}</td></tr>
      <tr><th>${t("cert.domain")}</th><td class="mono">${s.domain}</td></tr>
      ${a && html`<tr><th>${t("cert.anchor")}</th><td>${a.subject}<br />${until(a)}${fps(a)}
        <div class="actions"><a class="btn" href=${rel("v1/ca")} download>${t("cert.pem")}</a><a class="btn" href=${rel("v1/ca?format=der")} download>${t("cert.der")}</a>
          <a class="btn" href=${rel("v1/ca/mobileconfig")} download="keelauth-ca.mobileconfig">${t("cert.apple")}</a></div>
        <span class="muted small">${t("cert.public", s.domain)}</span></td></tr>`}
      ${c.server && html`<tr><th>${t("cert.server")}</th><td>${c.server.subject} · <span class="mono small">${(c.server.names || []).join(", ")}</span> · ${c.server.key}<br />${until(c.server)}${fps(c.server)}</td></tr>`}
      ${c.radius && html`<tr><th>${t("cert.radius")}</th><td>${c.radius.subject} · ${c.radius.key}<br />${until(c.radius)}${fps(c.radius)}</td></tr>`}
      ${office && c.own_ca && html`<tr><th>${t("cert.ownca")}</th><td class="muted">${c.own_ca.subject} · ${t("cert.notused")}
        <a class="btn" href=${rel("v1/ca?which=own")} download="keelauth-own-ca.crt">${t("cert.pem")}</a></td></tr>`}
      <tr><th>${t("cert.origin")}</th><td class="mono">${s.origin}</td></tr>
    </tbody></table>
    <p class="muted small">${t("cert.note")}</p>
    ${dlg && html`<${OfficeForm} domain=${s.domain} onClose=${() => setDlg(false)} onDone=${(r) => { setC(r); toast(t("cert.usedone")); }} />`}</div>`;
}

export function Settings({ sub }) {
  const tab = subs.includes(sub) ? sub : "general";
  return html`<nav class="subnav" aria-label=${t("nav.settings")}>${subs.map((k) => html`<a href=${"#/settings/" + k} class=${k === tab ? "on" : ""}
      aria-current=${k === tab ? "page" : null}>${t("set." + k)}</a>`)}</nav>
    <div class="stack">${tab === "general" ? html`<${General} />` : tab === "ai" ? html`<${AI} />` : tab === "sync" ? html`<${Sync} />` : html`<${Cert} />`}</div>`;
}
