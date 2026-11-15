// Settings: general (time zone, the master key's protection), AI management (MCP tokens),
// keelNAS sync keys, the certificate. Sub-tabs; every change in a dialog.
import { useEffect, useState } from "preact/hooks";
import { api, html, rel, send } from "./api.js";
import { fmtTime, langName, t } from "./i18n.js";
import { loadBrand, logoURL } from "./brand.js";
import { setZone, zones } from "./time.js";
import { ask, FormDialog, Spinner, toast } from "./ui.js";
import { Shown } from "./users.js";
import { featText } from "./features.js";

const fail = (e) => toast(e.message, 8000);
const subs = ["general", "modules", "ai", "api", "sync", "cert"];

function ZoneDialog({ zone, onClose, onDone }) {
  const [z, setZ] = useState(zone);
  const save = async () => { const r = await api("PUT", "v1/settings", { timezone: z }); setZone(r.timezone_in_use); onDone(); };
  return html`<${FormDialog} title=${t("gen.tztitle")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("gen.tz")}<select value=${z} onChange=${(e) => setZ(e.target.value)}>${zones().map((x) => html`<option value=${x}>${x}</option>`)}</select>
      <span class="muted small">${t("gen.tzfor")}</span></label>
  <//>`;
}

// PwPolicyDialog: the password rules (docs/02 §3.14): minimum length 10-64 and the strength
// Kanidm demands (strict = zxcvbn 4, Kanidm's own; normal = 3; length = none). Saving restarts
// kanidmd for a few seconds.
function PwPolicyDialog({ len, strength, onClose, onDone }) {
  const [n, setN] = useState(String(len));
  const [k, setK] = useState(strength);
  const save = async () => {
    const v = parseInt(n, 10);
    if (!(v >= 10 && v <= 64)) throw new Error(t("gen.pwlenbad"));
    await api("PUT", "v1/settings", { password_min_length: v, password_strength: k });
    toast(t("gen.pwsaved"));
    onDone();
  };
  return html`<${FormDialog} title=${t("gen.pwtitle")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("gen.pwlen")}<input type="number" min="8" max="64" value=${n} onInput=${(e) => setN(e.target.value)} /></label>
    <label>${t("gen.pwstrength")}<select value=${k} onChange=${(e) => setK(e.target.value)}>
      ${["strict", "normal", "length"].map((x) => html`<option value=${x}>${t("gen.pw." + x)}</option>`)}</select></label>
    <p class="muted small">${t("gen.pwnote")}</p>
  <//>`;
}

// SelfDialog: where employees change their own password and set up an authenticator (docs/02
// §9.5): on this page (the default) or in another app (a sync key with self_service); then the
// page shows them only the note (empty = the default text, shown as the placeholder).
function SelfDialog({ where, note, onClose, onDone }) {
  const [w, setW] = useState(where === "app" ? "app" : "page");
  const [n, setN] = useState(note);
  const save = async () => { await api("PUT", "v1/settings", { self_service_where: w, self_service_note: n }); onDone(); };
  return html`<${FormDialog} title=${t("gen.self")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <label>${t("gen.self.where")}<select value=${w} onChange=${(e) => setW(e.target.value)}>
      <option value="page">${t("gen.self.page")}</option><option value="app">${t("gen.self.app")}</option></select></label>
    ${w === "app" && html`<label>${t("gen.self.note")}<textarea rows="3" maxlength="500" placeholder=${t("self.default")} value=${n} onInput=${(e) => setN(e.target.value)}></textarea></label>`}
    <p class="muted small">${t("gen.self.hint")}</p>
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

const brandLangs = ["zh", "en", "ja"];

// BrandDialog: the company's name per language and its logo (keelauthd brand.go).
function BrandDialog({ brand, onClose, onDone }) {
  const [name, setName] = useState({ ...(brand.name || {}) });
  const [file, setFile] = useState(null);
  const [remove, setRemove] = useState(false);
  const save = async () => {
    await api("PUT", "v1/brand", { name });
    if (file) await send("PUT", "v1/brand/logo", file, file.type || "application/octet-stream");
    else if (remove) await api("DELETE", "v1/brand/logo");
    await loadBrand();
    toast(t("brand.saved"));
    onDone();
  };
  return html`<${FormDialog} title=${t("gen.brand")} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    <p class="muted small">${t("brand.for")}</p>
    ${brandLangs.map((l) => html`<label key=${l}>${t("brand.namein", langName(l))}<input type="text" maxlength="60" value=${name[l] || ""} placeholder="keelAuth" onInput=${(e) => setName({ ...name, [l]: e.target.value })} /></label>`)}
    <label>${t("brand.logofile")}<input type="file" accept="image/png,image/jpeg,image/webp,image/svg+xml" onChange=${(e) => setFile(e.target.files[0] || null)} />
      <span class="muted small">${t("brand.logohint")}</span></label>
    ${brand.logo && !file && html`<label class="check"><input type="checkbox" checked=${remove} onChange=${(e) => setRemove(e.target.checked)} /> ${t("brand.remove")}</label>`}
  <//>`;
}

function brandNames(b) {
  const n = (b && b.name) || {};
  const set = brandLangs.filter((l) => n[l]);
  if (!set.length) return t("brand.default");
  return set.map((l) => html`<span class="brand-name"><span class="muted">${langName(l)}:</span> ${n[l]}</span>`);
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
      <tr><th>${t("gen.brand")}</th><td>${brandNames(s.brand)}
        <span class="brand-row-logo">${s.brand && s.brand.logo ? html`<img class="brand-preview" src=${logoURL()} alt="" />` : html`<span class="muted">${t("brand.logo")}: ${t("brand.logonone")}</span>`}</span>
        <button class="btn" onClick=${() => setDlg("brand")}>${t("edit")}</button></td></tr>
      <tr><th>${t("gen.pw")}</th><td>${t("gen.pwvalue", s.password_min_length, t("gen.pw." + s.password_strength))}
        <button class="btn" onClick=${() => setDlg("pw")}>${t("edit")}</button></td></tr>
      <tr><th>${t("gen.self")}</th><td>${s.self_service_where === "app" ? t("gen.self.app") : t("gen.self.page")}
        <button class="btn" onClick=${() => setDlg("self")}>${t("edit")}</button></td></tr>
      <tr><th>${t("gen.support")}</th><td>${t("gen.supportnote")}<a class="btn" href=${rel("v1/support-bundle")} download>${t("gen.supportdl")}</a></td></tr>
    </tbody></table>
    <p class="muted small">${s.timezone_from_keel ? t("gen.mkkeelnote") : t("gen.tzfor")}</p>
    ${dlg === "tz" && html`<${ZoneDialog} zone=${s.timezone} onClose=${() => setDlg(null)} onDone=${load} />`}
    ${dlg === "brand" && html`<${BrandDialog} brand=${s.brand || {}} onClose=${() => setDlg(null)} onDone=${() => { setDlg(null); load(); }} />`}
    ${dlg === "pass" && html`<${PassDialog} onClose=${() => setDlg(null)} onDone=${load} />`}
    ${dlg === "self" && html`<${SelfDialog} where=${s.self_service_where} note=${s.self_service_note || ""} onClose=${() => setDlg(null)} onDone=${() => { setDlg(null); load(); }} />`}
    ${dlg === "pw" && html`<${PwPolicyDialog} len=${s.password_min_length} strength=${s.password_strength} onClose=${() => setDlg(null)} onDone=${() => { setDlg(null); load(); }} />`}
  </div>`;
}

// Modules: keelAuth's optional ways in, each switched on or off (keelauthd modules.go)
function Modules() {
  const [d, setD] = useState(null);
  const [fs, setFs] = useState([]); // the feature modules' declarations (features.go)
  const [conf, setConf] = useState(null); // the feature module whose settings dialog is open
  const load = () => Promise.all([api("GET", "v1/modules"), api("GET", "v1/features").catch(() => ({}))])
    .then(([x, f]) => { setD(x.modules); setFs(f.features || []); }).catch(fail);
  useEffect(() => { load(); const id = setInterval(load, 5000); return () => clearInterval(id); }, []);
  if (!d) return html`<${Spinner} />`;
  const label = (m) => { const f = fs.find((x) => x.name === m.name); return f ? featText(f.title) : t("mod." + m.name); };
  const flip = async (m) => {
    if (m.enabled && !await ask(t(m.kind === "feature" ? "mod.featoffq" : "mod.offq", label(m)))) return;
    try { await api("PUT", "v1/modules/" + m.name, { enabled: !m.enabled }); load(); } catch (e) { fail(e); }
  };
  const wipe = async (f) => {
    if (!await ask(t("mod.deldataq", featText(f.title), f.users_with_data))) return;
    try { await api("DELETE", "v1/features/" + f.name + "/data"); load(); } catch (e) { fail(e); }
  };
  const feats = d.filter((m) => m.kind === "feature");
  const state = (m) => !m.enabled ? html`<span class="muted">${t("mod.off")}</span>`
    : m.up ? html`<span class="badge ok">${t("mod.on")}</span>`
    : html`<span class="warn">${t("mod.notup")}${m.error ? ": " + m.error : ""}</span>`;
  return html`<div class="card"><div class="row-head"><h3>${t("set.modules")}</h3></div>
    <p class="ka-for">${t("mod.for")}</p>
    <table class="data plain"><thead><tr><th>${t("mod.module")}</th><th>${t("mod.what")}</th><th>${t("mod.ports")}</th><th>${t("mod.state")}</th><th></th></tr></thead><tbody>
      ${d.filter((m) => m.kind !== "feature").map((m) => html`<tr key=${m.name}><td>${t("mod." + m.name)}</td><td class="muted">${t("mod." + m.name + ".for")}</td>
        <td class="mono">${m.ports.join(", ")}</td><td>${state(m)}</td>
        <td class="actions">${m.fixed ? html`<span class="muted small">${t("mod.fixed")}</span>`
          : html`<button class="btn" onClick=${() => flip(m)}>${m.enabled ? t("mod.disable") : t("mod.enable")}</button>`}</td></tr>`)}
    </tbody></table>
    <p class="muted small">${t("mod.note")}</p>
    ${feats.length > 0 && html`<h4>${t("mod.features")}</h4><p class="ka-for">${t("mod.featfor")}</p>
    <table class="data plain"><thead><tr><th>${t("mod.module")}</th><th>${t("mod.what")}</th><th>${t("mod.data")}</th><th>${t("mod.state")}</th><th></th></tr></thead><tbody>
      ${feats.map((m) => { const f = fs.find((x) => x.name === m.name) || { users_with_data: 0 };
        return html`<tr key=${m.name}><td>${label(m)}</td><td class="muted">${featText(f.help)}</td><td>${f.users_with_data}</td>
        <td>${m.enabled ? html`<span class="badge ok">${t("mod.on")}</span>` : html`<span class="muted">${t("mod.off")}</span>`}</td>
        <td class="actions">${f.conf && html`<button class="btn" onClick=${() => setConf(f)}>${t("mod.conf")}</button> `}<button class="btn" onClick=${() => flip(m)}>${m.enabled ? t("mod.disable") : t("mod.enable")}</button>
          ${!m.enabled && f.users_with_data > 0 && html` <button class="btn danger" onClick=${() => wipe(f)}>${t("mod.deldata")}</button>`}</td></tr>`; })}
    </tbody></table>`}
    ${conf && html`<${FeatureConf} f=${conf} onClose=${() => setConf(null)} onDone=${load} />`}
  </div>`;
}

// FeatureConf: a feature module's settings (PUT v1/features/{name}/conf): the fixed length of its
// admin_len fields and the options of its choice fields. Emptied inputs stay empty (= any length).
function FeatureConf({ f, onClose, onDone }) {
  const [len, setLen] = useState(() => Object.fromEntries(Object.entries(f.conf.len || {}).map(([k, v]) => [k, v ? String(v) : ""])));
  const [opts, setOpts] = useState(() => JSON.parse(JSON.stringify(f.conf.options || {})));
  const langs = [["zh", "中文"], ["en", "English"], ["ja", "日本語"]];
  const setOpt = (name, i, up) => setOpts((o) => ({ ...o, [name]: o[name].map((x, j) => (j === i ? up(x) : x)) }));
  const save = async () => {
    const body = { len: Object.fromEntries(Object.entries(len).map(([k, v]) => [k, v === "" ? 0 : Number(v)])),
      options: Object.fromEntries(Object.entries(opts).map(([k, v]) => [k, v.map((o) => ({ code: o.code.trim(), title: o.title || {} }))])) };
    await api("PUT", "v1/features/" + f.name + "/conf", body); onDone();
  };
  return html`<${FormDialog} title=${t("featconf.title", featText(f.title))} submit=${t("save")} onSubmit=${save} onClose=${onClose}>
    ${f.fields.filter((fd) => fd.admin_len).map((fd) => html`<label>${t("featconf.len", featText(fd.title))}
      <input type="number" min="1" max=${fd.max || undefined} placeholder=${t("featconf.anylen")} value=${len[fd.name] ?? ""} onInput=${(e) => setLen((l) => ({ ...l, [fd.name]: e.target.value }))} />
      <span class="muted small">${t("featconf.lenhint")}</span></label>`)}
    ${f.fields.filter((fd) => fd.type === "choice").map((fd) => { const v = opts[fd.name] || [];
      return html`<fieldset class="hn-g feat"><legend>${t("featconf.options", featText(fd.title))}</legend><p class="muted small">${t("featconf.codehint")}</p>
        ${v.length ? html`<table class="data plain feat-rows"><thead><tr><th>${t("featconf.code")}</th>${langs.map(([, n]) => html`<th>${n}</th>`)}<th></th></tr></thead>
          <tbody>${v.map((o, i) => html`<tr><td><input type="text" required pattern="[a-z][a-z0-9_\\-]{0,31}" spellcheck="false" autocapitalize="off" value=${o.code} onInput=${(e) => setOpt(fd.name, i, (x) => ({ ...x, code: e.target.value }))} /></td>
            ${langs.map(([l]) => html`<td><input type="text" maxlength="64" value=${(o.title || {})[l] || ""} onInput=${(e) => setOpt(fd.name, i, (x) => ({ ...x, title: { ...(x.title || {}), [l]: e.target.value } }))} /></td>`)}
            <td><button type="button" class="btn" onClick=${() => setOpts((c) => ({ ...c, [fd.name]: v.filter((_, j) => j !== i) }))}>${t("feat.remove")}</button></td></tr>`)}</tbody></table>`
          : html`<p class="muted small">${t("featconf.noopts")}</p>`}
        <button type="button" class="btn" onClick=${() => setOpts((c) => ({ ...c, [fd.name]: [...v, { code: "", title: {} }] }))}>${t("featconf.addopt")}</button></fieldset>`; })}
  <//>`;
}

// NewToken: scopes given = an API key, with its scope (api.scope.<name> says what each allows)
function NewToken({ title, onClose, onDone, path, scopes }) {
  const [name, setName] = useState("");
  const [scope, setScope] = useState(scopes ? scopes[0] : "");
  const save = async () => onDone(await api("POST", path, scopes ? { name: name.trim(), scope } : { name: name.trim() }));
  return html`<${FormDialog} title=${title} submit=${t("tok.make")} onSubmit=${save} onClose=${onClose}>
    <label>${t("tok.name")}<input type="text" required maxlength="64" value=${name} onInput=${(e) => setName(e.target.value)} />
      <span class="muted small">${t("tok.namehint")}</span></label>
    ${scopes && html`<label>${t("api.scope")}<select value=${scope} onChange=${(e) => setScope(e.target.value)}>
        ${scopes.map((x) => html`<option value=${x}>${t("api.scope." + x)}</option>`)}</select>
      <span class="muted small">${t("api.scopehint." + scope)}</span></label>`}
  <//>`;
}

// NewSyncKey: a sync key with whose accounts it is given (its group), whether it gets their
// password hashes, and whether a login through it needs the authenticator app's code.
function NewSyncKey({ onClose, onDone }) {
  const [f, setF] = useState({ name: "", group: "", secrets: true, require_totp: false, self_service: false, features: [] });
  const [feats, setFeats] = useState([]);
  useEffect(() => { api("GET", "v1/features").then((x) => setFeats((x.features || []).filter((y) => y.enabled))).catch(() => {}); }, []);
  const set = (k) => (e) => { const v = e.target.type === "checkbox" ? e.target.checked : e.target.value; setF((f) => ({ ...f, [k]: v })); };
  const save = async () => onDone(await api("POST", "v1/sync/keys", { name: f.name.trim(), group: f.group.trim(), secrets: f.secrets, require_totp: f.require_totp, self_service: f.self_service, features: f.features }));
  return html`<${FormDialog} title=${t("sync.new")} submit=${t("tok.make")} onSubmit=${save} onClose=${onClose}>
    <label>${t("tok.name")}<input type="text" required maxlength="64" value=${f.name} onInput=${set("name")} />
      <span class="muted small">${t("tok.namehint")}</span></label>
    <label>${t("sync.group")}<input type="text" pattern="[a-z][a-z0-9_\\-]{0,31}" spellcheck="false" autocapitalize="off" value=${f.group} onInput=${set("group")} />
      <span class="muted small">${t("sync.grouphint")}</span></label>
    <label class="check"><input type="checkbox" checked=${f.secrets} onChange=${set("secrets")} /> ${t("sync.secrets")}</label>
    <label class="check"><input type="checkbox" checked=${f.require_totp} onChange=${set("require_totp")} /> ${t("sync.totp")}</label>
    <label class="check"><input type="checkbox" checked=${f.self_service} onChange=${set("self_service")} /> ${t("sync.self")}</label>
    ${feats.length > 0 && html`<p class="muted small">${t("sync.features")}</p>${feats.map((x) => html`<label class="check"><input type="checkbox" checked=${f.features.includes(x.name)}
      onChange=${(e) => setF((f) => ({ ...f, features: e.target.checked ? [...f.features, x.name] : f.features.filter((n) => n !== x.name) }))} /> ${featText(x.title)}</label>`)}`}
  <//>`;
}

function TokenList({ list, onDelete, scope, extra }) {
  if (!list.length) return html`<p class="muted">${t("tok.none")}</p>`;
  return html`<div class="table-wrap tall"><table class="data plain">
    <thead><tr><th>${t("tok.name")}</th><th>ID</th>${scope && html`<th>${t("api.scope")}</th>`}<th>${t("tok.created")}</th><th>${t("tok.used")}</th><th></th></tr></thead>
    <tbody>${list.map((x) => html`<tr><td><b>${x.name}</b>${extra ? extra(x) : ""}</td><td class="mono">${x.id}</td>${scope && html`<td>${t("api.scope." + x.scope)}</td>`}<td>${fmtTime(x.created)}</td><td>${x.last_used ? fmtTime(x.last_used) : "–"}</td>
      <td><button class="btn danger" onClick=${() => onDelete(x)}>${t("tok.revoke")}</button></td></tr>`)}</tbody></table></div>`;
}

// API keys: another system (a web application moving its accounts here, docs/02 §3.11) calls
// /v1 with a key of its own; the key's scope says how far it may go
function API() {
  const [d, setD] = useState(null);
  const [dlg, setDlg] = useState(null);
  const [addr, setAddr] = useState("");
  const load = () => api("GET", "v1/api/keys").then(setD).catch(fail);
  useEffect(() => { load(); api("GET", "v1/status").then((s) => setAddr((s.addresses || [])[0] || s.domain)).catch(() => {}); }, []);
  if (!d) return html`<${Spinner} />`;
  const del = async (x) => {
    if (!await ask(t("tok.revokeq", x.name))) return;
    try { await api("DELETE", "v1/api/keys/" + x.id); load(); } catch (e) { fail(e); }
  };
  const cmd = (key) => "curl -H 'Authorization: Bearer " + key + "' https://" + (addr || location.hostname) + "/v1/users";
  return html`<div class="card"><div class="row-head"><h3>${t("api.title")}</h3><button class="primary" onClick=${() => setDlg({ kind: "new" })}>${t("api.new")}</button></div>
    <p class="ka-for">${t("api.for")}</p>
    <${TokenList} list=${d.keys} onDelete=${del} scope=${true} />
    <h3 class="sub">${t("ai.connect")}</h3>
    <pre class="code">${cmd("kap_…")}</pre>
    <p class="muted small">${t("api.note", d.fingerprint)}</p>
    ${dlg && dlg.kind === "new" && html`<${NewToken} title=${t("api.new")} path="v1/api/keys" scopes=${d.scopes} onClose=${() => setDlg(null)}
      onDone=${(x) => { load(); setTimeout(() => setDlg({ kind: "shown", x })); }} />`}
    ${dlg && dlg.kind === "shown" && html`<${Shown} title=${t("ai.made", dlg.x.name)} onClose=${() => setDlg(null)}
      rows=${[[t("api.key"), dlg.x.key], [t("ai.command"), cmd(dlg.x.key)]]} />`}
  </div>`;
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
    <${TokenList} list=${d.keys} onDelete=${del} extra=${(x) => html`${x.group ? html` <span class="badge">${x.group}</span>` : ""}${x.secrets === false ? html` <span class="badge">${t("sync.nosecrets")}</span>` : ""}${x.require_totp ? html` <span class="badge">${t("sync.totpbadge")}</span>` : ""}${x.self_service ? html` <span class="badge">${t("sync.selfbadge")}</span>` : ""}${(x.features || []).map((n) => html` <span class="badge">${n}</span>`)}`} />
    ${dlg && dlg.kind === "new" && html`<${NewSyncKey} onClose=${() => setDlg(null)}
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
    <div class="stack">${tab === "general" ? html`<${General} />` : tab === "modules" ? html`<${Modules} />` : tab === "ai" ? html`<${AI} />` : tab === "api" ? html`<${API} />` : tab === "sync" ? html`<${Sync} />` : html`<${Cert} />`}</div>`;
}
