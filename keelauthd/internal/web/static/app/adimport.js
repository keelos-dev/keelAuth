// Importing accounts from a Windows AD (docs/07): connect, look at what was read, tick and
// correct, import. What was read lives in keelauthd for 15 minutes; every change of a choice
// asks it again how the rows would look (v1/import/ad/preview), so the checks are keelauthd's.
import { useEffect, useRef, useState } from "preact/hooks";
import { api, html, rel } from "./api.js";
import { t, tr } from "./i18n.js";
import { Dialog, Spinner } from "./ui.js";

const fpShow = (f) => (f || "").toUpperCase().replace(/(..)(?=.)/g, "$1:");
const problemText = (x) => tr("adimp.p." + x.problem_code, x.problem);
const noteText = (n) => tr("adimp.n." + n.code, n.text, ...(n.args || []));

export function ADImport({ onClose, onChanged }) {
  const [conn, setConn] = useState({ address: "", user: "", password: "" });
  const [cert, setCert] = useState("");     // a fingerprint waiting for the administrator's yes
  const [read, setRead] = useState(null);   // { id, domain, mail_domains, our_mail_domains, fingerprint }
  const [plan, setPlan] = useState(null);
  const [m, setM] = useState({ name_from: "sam", mail: {}, rename: {}, users: null, groups: null });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [tab, setTab] = useState("users");
  const [q, setQ] = useState("");
  const [onlyRed, setOnlyRed] = useState(false);
  const [progress, setProgress] = useState(null); // [made, of] while an import runs
  const [done, setDone] = useState({ made: 0, groups: 0, failed: [], notes: {} });
  const timer = useRef(0);
  const seq = useRef(0);
  useEffect(() => () => clearTimeout(timer.current), []);

  const fail = (e) => { setErr(e.message || String(e)); if (e.body && e.body.code === "ad_read_gone") { setRead(null); setPlan(null); } };
  const connect = async (ev, fingerprint) => {
    if (ev) ev.preventDefault();
    setErr(""); setBusy(true);
    try {
      const o = await api("POST", "v1/import/ad/read", { ...conn, fingerprint: fingerprint || "" });
      if (o.confirm_certificate) { setCert(o.confirm_certificate); return; }
      setCert(""); setRead(o); setPlan(o.plan);
      setConn((c) => ({ ...c, password: "" }));
    } catch (e) { fail(e); } finally { setBusy(false); }
  };

  // preview: ask keelauthd how the rows look under the choices nm (at once, or a moment after typing).
  const preview = (nm, later) => {
    setM(nm);
    clearTimeout(timer.current);
    const go = async () => {
      const mine = ++seq.current;
      try {
        const o = await api("POST", "v1/import/ad/preview", { id: read.id, ...nm });
        if (mine === seq.current) { setPlan(o.plan); setErr(""); }
      } catch (e) { if (mine === seq.current) fail(e); }
    };
    if (later) timer.current = setTimeout(go, 400); else go();
  };
  const tickedUsers = () => plan.users.filter((r) => r.ticked).map((r) => r.sam);
  const tickedGroups = () => Object.fromEntries(plan.groups.filter((g) => g.ticked).map((g) => [g.ad, (m.groups || {})[g.ad] || ""]));
  const tickUser = (sam, on) => { const cur = tickedUsers().filter((x) => x !== sam); preview({ ...m, users: on ? [...cur, sam] : cur }); };
  const tickAll = (rows, on) => {
    const these = new Set(rows.filter((r) => !r.exists).map((r) => r.sam));
    const cur = tickedUsers().filter((x) => !these.has(x));
    preview({ ...m, users: on ? [...cur, ...these] : cur });
  };
  const tickGroup = (ad, on) => { const cur = tickedGroups(); if (on) cur[ad] = cur[ad] || ""; else delete cur[ad]; preview({ ...m, groups: cur }); };
  const nameGroup = (ad, name) => { const cur = tickedGroups(); cur[ad] = name; preview({ ...m, groups: cur }, true); };
  const rename = (sam, name) => preview({ ...m, rename: { ...m.rename, [sam]: name } }, true);
  const mailRule = (dom, v) => preview({ ...m, mail: { ...m.mail, [dom]: v === "keep" || v === "drop" ? { to: v } : { to: "domain", domain: v } } });

  // run: the sound ticked rows, ten at a time (making an account takes a second or two: the
  // password hash), so that the dialog can say how far it is; the red rows stay ticked.
  const run = async () => {
    setErr(""); setBusy(true);
    clearTimeout(timer.current); seq.current++;
    const todo = plan.users.filter((r) => r.ticked && !r.problem).map((r) => r.sam);
    const stay = plan.users.filter((r) => r.ticked && r.problem).map((r) => r.sam);
    const groups = tickedGroups();
    let made = 0;
    try {
      for (let i = 0; i < todo.length; i += 10) {
        setProgress([made, todo.length]);
        const o = await api("POST", "v1/import/ad/run", { id: read.id, ...m, groups, users: todo.slice(i, i + 10) });
        made += o.made.length;
        setDone((d) => ({ made: d.made + o.made.length, groups: d.groups + o.groups.length, failed: [...d.failed, ...o.failed], notes: { ...d.notes, ...o.notes } }));
        if (o.made.length || o.groups.length) onChanged();
      }
    } catch (e) { fail(e); }
    setProgress(null); setBusy(false);
    const left = { ...m, users: stay, groups };
    setM(left);
    try { setPlan((await api("POST", "v1/import/ad/preview", { id: read.id, ...left })).plan); } catch (e) { fail(e); }
  };

  if (!read) {
    return html`<${Dialog} title=${t("adimp.title")} onClose=${onClose}><form class="stack" onSubmit=${connect}>
      <p class="muted small">${t("adimp.intro")}</p>
      <label>${t("adimp.address")}<input required value=${conn.address} placeholder="dc1.example.com" autocomplete="off" disabled=${busy || !!cert}
        onInput=${(e) => setConn({ ...conn, address: e.target.value })} /></label>
      <label>${t("adimp.user")}<input required value=${conn.user} placeholder="reader@example.com" autocomplete="off" disabled=${busy || !!cert}
        onInput=${(e) => setConn({ ...conn, user: e.target.value })} /><span class="muted small">${t("adimp.userhint")}</span></label>
      <label>${t("adimp.password")}<input required type="password" value=${conn.password} autocomplete="new-password" disabled=${busy || !!cert}
        onInput=${(e) => setConn({ ...conn, password: e.target.value })} /></label>
      ${cert && html`<div class="stack"><p class="warn small">${t("adimp.certq")}</p><p class="mono small" style="word-break: break-all">${fpShow(cert)}</p></div>`}
      ${err && html`<p class="error">${err}</p>`}
      <div class="actions">
        ${cert ? html`<button type="button" class="primary" disabled=${busy} onClick=${() => connect(null, cert)}>${t("adimp.certyes")}</button>
          <button type="button" disabled=${busy} onClick=${() => setCert("")}>${t("adimp.back")}</button>`
        : html`<button type="submit" class="primary" disabled=${busy}>${t("adimp.read")}</button>`}
        <button type="button" disabled=${busy} onClick=${onClose}>${t("dlg.cancel")}</button>${busy && html`<${Spinner} small=${true} />`}</div>
    </form><//>`;
  }

  const text = q.trim().toLowerCase();
  const rows = plan.users.filter((r) => (!onlyRed || (r.ticked && r.problem)) &&
    (!text || [r.sam, r.name, r.display_name, r.mail].some((h) => h && h.toLowerCase().includes(text))));
  const ready = plan.users.filter((r) => r.ticked && !r.problem).length;
  const red = plan.users.filter((r) => r.ticked && r.problem).length;
  const redGroups = plan.groups.filter((g) => g.ticked && g.problem).length;
  const allOn = rows.some((r) => !r.exists) && rows.every((r) => r.exists || r.ticked);
  const noted = Object.entries(done.notes).filter(([, l]) => l && l.length);
  const ruleValue = (dom) => { const r = plan.mail[dom] || {}; return r.to === "domain" ? r.domain : r.to || "keep"; };
  const result = (r) => {
    if (r.addresses && r.addresses.length) return r.addresses.join(", ");
    return r.contact ? html`${r.contact} <span class="muted small">${t("adimp.contact")}</span>` : "–";
  };

  return html`<${Dialog} title=${t("adimp.titlefrom", read.domain)} onClose=${onClose} wide=${true}><div class="stack">
    <div class="aud-bar">
      <label>${t("adimp.namefrom")} <select value=${m.name_from} onChange=${(e) => preview({ ...m, name_from: e.target.value })}>
        <option value="sam">${t("adimp.from.sam")}</option><option value="mail">${t("adimp.from.mail")}</option><option value="upn">${t("adimp.from.upn")}</option></select></label>
      ${read.mail_domains.map((dom) => html`<label>${t("adimp.mailof", dom)} <select value=${ruleValue(dom)} onChange=${(e) => mailRule(dom, e.target.value)}>
        ${read.our_mail_domains.map((d) => html`<option value=${d}>${t("adimp.mail.box", d)}</option>`)}
        <option value="keep">${t("adimp.mail.keep")}</option><option value="drop">${t("adimp.mail.drop")}</option></select></label>`)}
    </div>
    <div class="row-head"><div class="tabs">
        <button type="button" class=${tab === "users" ? "primary" : "btn"} onClick=${() => setTab("users")}>${t("nav.users")} ${plan.users.length}${red ? html` <span class="error">(${red})</span>` : ""}</button>
        <button type="button" class=${tab === "groups" ? "primary" : "btn"} onClick=${() => setTab("groups")}>${t("nav.groups")} ${plan.groups.length}${redGroups ? html` <span class="error">(${redGroups})</span>` : ""}</button></div>
      ${tab === "users" && html`<div class="aud-bar"><input type="search" placeholder=${t("adimp.search")} value=${q} onInput=${(e) => setQ(e.target.value)} />
        <label class="check"><input type="checkbox" checked=${onlyRed} onChange=${(e) => setOnlyRed(e.target.checked)} /> ${t("adimp.onlyred")}</label></div>`}</div>

    ${tab === "users" && html`<div class="table-wrap tall"><table class="data plain">
      <thead><tr><th><input type="checkbox" checked=${allOn} title=${t("adimp.all")} onChange=${(e) => tickAll(rows, e.target.checked)} /></th>
        <th>${t("adimp.col.ad")}</th><th>${t("adimp.col.name")}</th><th>${t("users.display")}</th><th>${t("adimp.col.admail")}</th><th>${t("adimp.col.mail")}</th><th>${t("users.groups")}</th><th class="adimp-note">${t("adimp.col.state")}</th></tr></thead>
      <tbody>${rows.map((r) => html`<tr key=${r.sam} class=${r.exists || r.disabled ? "stale" : ""}>
        <td><input type="checkbox" checked=${r.ticked} disabled=${r.exists && !r.ticked} onChange=${(e) => tickUser(r.sam, e.target.checked)} /></td>
        <td class="nowrap">${r.sam}</td>
        <td>${r.exists && !r.ticked ? html`<b>${r.name}</b>` : html`<input class=${"mono" + (r.ticked && r.problem ? " bad" : "")} size="18" maxlength="32" spellcheck=${false}
          value=${m.rename[r.sam] !== undefined && m.rename[r.sam] !== "" ? m.rename[r.sam] : r.name} onInput=${(e) => rename(r.sam, e.target.value)} />`}</td>
        <td class="nowrap">${r.display_name || "–"}</td><td>${r.mail || "–"}</td><td>${result(r)}</td><td>${(r.new_groups || []).join(", ") || "–"}</td>
        <td>${r.exists && !r.ticked ? html`<span class="muted">${t("adimp.exists")}</span>` : r.problem && r.ticked ? html`<span class="error">${problemText(r)}</span>` : r.disabled && !r.ticked ? html`<span class="muted">${t("adimp.disabled")}</span>` : ""}
          ${(r.notes || []).map((n) => html`<div class="muted small">${noteText(n)}</div>`)}</td></tr>`)}</tbody></table></div>`}

    ${tab === "groups" && html`<div class="table-wrap tall"><table class="data plain">
      <thead><tr><th></th><th>${t("adimp.col.adgroup")}</th><th>${t("adimp.col.group")}</th><th>${t("adimp.col.members")}</th><th>${t("adimp.col.state")}</th></tr></thead>
      <tbody>${plan.groups.map((g) => html`<tr key=${g.ad}>
        <td><input type="checkbox" checked=${g.ticked} onChange=${(e) => tickGroup(g.ad, e.target.checked)} /></td>
        <td class="nowrap">${g.ad}</td>
        <td><input class=${"mono" + (g.ticked && g.problem ? " bad" : "")} size="24" maxlength="32" spellcheck=${false} disabled=${!g.ticked}
          value=${(m.groups || {})[g.ad] || g.name} onInput=${(e) => nameGroup(g.ad, e.target.value)} /></td>
        <td title=${(g.members || []).join(", ")}>${(g.members || []).length}</td>
        <td>${g.problem && g.ticked ? html`<span class="error">${problemText(g)}</span>` : g.exists ? html`<span class="muted">${t("adimp.groupexists")}</span>` : ""}</td></tr>`)}</tbody></table></div>`}

    ${(done.made > 0 || done.groups > 0) && html`<p><b>${t("adimp.done", done.made, done.groups)}</b>
      ${done.made > 0 && html` <a class="btn" href=${rel("v1/import/ad/" + read.id + "/passwords.csv")} download>${t("adimp.csv")}</a> <span class="warn small">${t("adimp.csvnote")}</span>`}</p>`}
    ${done.failed.length > 0 && html`<p class="error">${done.failed.map((f) => html`<div>${f.ad} → ${f.name}: ${f.error}</div>`)}</p>`}
    ${noted.length > 0 && html`<p class="muted small">${noted.map(([n, l]) => html`<div>${n}: ${l.join("; ")}</div>`)}</p>`}
    ${err && html`<p class="error">${err}</p>`}
    <div class="actions"><button type="button" class="primary" disabled=${busy || ready === 0} onClick=${run}>${t("adimp.run", ready)}</button>
      <button type="button" disabled=${busy} onClick=${onClose}>${t("dlg.close")}</button>${busy && html`<${Spinner} small=${true} />`}
      ${progress && html`<span>${t("adimp.progress", progress[0], progress[1])}</span>`}
      <span class="muted small">${red + redGroups > 0 ? t("adimp.redstay", red + redGroups) : ""}</span></div>
  </div><//>`;
}
