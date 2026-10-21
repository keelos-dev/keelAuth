// keelAuth's web page: Preact + htm, no build step, the look and the rules of keel's page
// (keelOS docs/32 "界面风格": square corners, ESXi density; pages are lists; adding and editing
// always in a dialog; long pages get sub-tabs). Hash routes, relative addresses only.
import { render } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import { api, html, setCSRF, setLoggedOut } from "./api.js";
import { framed, getLang, langName, languages, setLang, t } from "./i18n.js";
import { Spinner } from "./ui.js";
import { setZone } from "./time.js";
import { logoHTML, markSVG } from "./logo.js";
import { Overview } from "./overview.js";
import { Users } from "./users.js";
import { Groups } from "./groups.js";
import { Access } from "./access.js";
import { Backups } from "./backup.js";
import { Settings } from "./settings.js";
import { OwnPassword } from "./password.js";
import { Unlock } from "./unlock.js";

// the theme: keelAuth's own; in keel's 账号 tab keel's (same origin, its setting)
function theme() {
  try { return (framed && localStorage.getItem("keel.theme")) || localStorage.getItem("keelauth.theme") || "auto"; } catch (_) { return "auto"; }
}
function applyTheme(v) {
  if (v === "auto") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = v;
}
applyTheme(theme());

function useHash() {
  const [hash, setHash] = useState(location.hash);
  useEffect(() => {
    const f = () => setHash(location.hash);
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);
  return hash;
}

// LoginPage: keel's login page (left half the form, right half the dark blue with the mark).
function LoginPage({ children, lang, onLang, th, onTheme }) {
  return html`<div class="login">
    <div class="login-form">
      <span class="login-mark" dangerouslySetInnerHTML=${{ __html: markSVG }}></span>
      <div class="login-box">${children}</div>
    </div>
    <div class="login-brand">
      <div class="login-pick">
        <select class="small" value=${lang} onChange=${(e) => onLang(e.target.value)} aria-label="language">
          ${languages.map((l) => html`<option value=${l}>${langName(l)}</option>`)}
        </select>
        <select class="small" value=${th} onChange=${(e) => onTheme(e.target.value)} aria-label=${t("top.theme")} title=${t("top.theme")}>
          ${["auto", "light", "dark"].map((v) => html`<option value=${v}>${t("theme." + v)}</option>`)}
        </select>
      </div>
      <div class="login-water" aria-hidden="true" dangerouslySetInnerHTML=${{ __html: markSVG }}></div>
      <div class="login-logo" dangerouslySetInnerHTML=${{ __html: logoHTML }}></div>
    </div>
  </div>`;
}

function Login({ onLogin, ...page }) {
  const [st, setSt] = useState(null);
  const [name, setName] = useState("");
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  useEffect(() => { api("GET", "login/state").then((x) => { setZone(x.timezone); setSt(x); }).catch(() => setSt({})); }, []);
  const submit = async (ev) => {
    ev.preventDefault();
    setErr("");
    try { const s = await api("POST", "login", { name: name.trim(), password: pw }); setPw(""); onLogin(s); } catch (e) { setErr(e.message); }
  };
  if (st && st.locked) {
    return html`<${LoginPage} ...${page}><h1>${t("lock.title")}</h1>
      <p class="muted small host">${st.domain || location.hostname}</p><${Unlock} onDone=${() => location.reload()} /><//>`;
  }
  return html`<${LoginPage} ...${page}>
    <h1>${t("login.to")}</h1>
    <p class="muted small host">${st ? (st.domain || location.hostname) : ""}</p>
    <form class="stack" onSubmit=${submit}>
      <input type="text" autocomplete="username" placeholder=${t("login.user")} required autofocus spellcheck="false" autocapitalize="off"
        value=${name} onInput=${(e) => setName(e.target.value)} />
      <input type="password" autocomplete="current-password" placeholder=${t("login.password")} required
        value=${pw} onInput=${(e) => setPw(e.target.value)} />
      <button type="submit" class="primary">${t("login.button")}</button>
    </form>
    ${err && html`<p class="error">${err}</p>`}
    <p class="muted small">${t("login.hint")}</p>
    ${st && st.admins === false && html`<p class="warn small">${t("login.noadmin")}</p>`}
  <//>`;
}

const tabs = [["#/", "nav.overview", (h) => h === "" || h === "#/"], ["#/users", "nav.users", (h) => h.startsWith("#/users")],
  ["#/groups", "nav.groups", (h) => h.startsWith("#/groups")], ["#/access", "nav.access", (h) => h.startsWith("#/access")],
  ["#/backup", "nav.backup", (h) => h.startsWith("#/backup")], ["#/settings", "nav.settings", (h) => h.startsWith("#/settings")]];

function Nav({ hash, alerts, cls }) {
  return html`<nav class=${cls || "nav"}>${tabs.map(([href, k, on]) => html`<a href=${href} class=${on(hash) ? "on" : ""} aria-current=${on(hash) ? "page" : null}>${t(k)}${k === "nav.overview" && alerts > 0 ? html` <span class="badge" style="color:var(--danger);border-color:var(--danger)">${alerts}</span>` : null}</a>`)}</nav>`;
}

// TopMenu: who is logged in, language, theme (keel's hamburger menu).
function TopMenu({ session, lang, onLang, th, onTheme }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const away = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const esc = (e) => { if (e.key === "Escape") setOpen(false); };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", away); document.removeEventListener("keydown", esc); };
  }, [open]);
  return html`<div class="top-menu" ref=${ref}>
    <button class="burger" aria-label=${t("top.menu")} title=${t("top.menu")} aria-expanded=${open} onClick=${() => setOpen(!open)}>☰</button>
    ${open && html`<div class="top-pop">
      ${session && html`<div class="small">${session.display_name || session.name} · ${session.admin ? t("scope.admin") : t("scope.user")}</div>`}
      ${session && !session.via_keel && html`<a class="small" href="#/password">${t("pw.own")}</a>`}
      <label class="small">${t("top.lang")}
        <select class="small" value=${lang} onChange=${(e) => onLang(e.target.value)} aria-label="language">
          ${languages.map((l) => html`<option value=${l}>${langName(l)}</option>`)}
        </select></label>
      <label class="small">${t("top.theme")}
        <select class="small" value=${th} onChange=${(e) => onTheme(e.target.value)}>
          ${["auto", "light", "dark"].map((v) => html`<option value=${v}>${t("theme." + v)}</option>`)}
        </select></label>
    </div>`}
  </div>`;
}

function App() {
  const [session, setSession] = useState(undefined); // undefined: asking; null: logged out
  const [lang, setLangState] = useState(getLang());
  const [th, setTh] = useState(theme());
  const [status, setStatus] = useState(null);
  const hash = useHash();
  const onLang = (l) => { setLang(l); setLangState(l); };
  const onTheme = (v) => { try { localStorage.setItem("keelauth.theme", v); } catch (_) { /* none */ } applyTheme(v); setTh(v); };
  const got = (s) => { setCSRF(s.csrf); setZone(s.timezone); setSession(s); };
  useEffect(() => {
    setLoggedOut(() => setSession(null));
    api("GET", "session").then(got).catch(() => setSession(null));
  }, []);
  useEffect(() => {
    if (!session || !session.admin) return undefined;
    const load = () => api("GET", "v1/status").then(setStatus).catch(() => {});
    load();
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, [session, hash]);
  useEffect(() => { document.title = status ? "keelAuth · " + status.domain : "keelAuth"; }, [status]);
  const page = { lang, onLang, th, onTheme };
  if (session === undefined) return html`<${Spinner} />`;
  if (session === null) return html`<${Login} onLogin=${got} ...${page} />`;
  const logout = async () => { try { await api("POST", "logout"); } catch (_) { /* gone anyway */ } setSession(null); };
  // not an admin, or a password to change first: only the own password
  if (!session.admin || session.must_change) {
    return html`<${LoginPage} ...${page}><${OwnPassword} session=${session} onDone=${() => api("GET", "session").then(got).catch(() => setSession(null))} onLogout=${logout} /><//>`;
  }
  let body;
  if (status && status.master_key && status.master_key.locked) body = html`<div class="card ka-pw"><h3>${t("lock.title")}</h3><${Unlock} onDone=${() => location.reload()} /></div>`;
  else if (hash.startsWith("#/users")) body = html`<${Users} />`;
  else if (hash.startsWith("#/groups")) body = html`<${Groups} />`;
  else if (hash.startsWith("#/access")) body = html`<${Access} sub=${hash.split("/")[2] || ""} status=${status} />`;
  else if (hash.startsWith("#/backup")) body = html`<${Backups} />`;
  else if (hash.startsWith("#/settings")) body = html`<${Settings} sub=${hash.split("/")[2] || ""} session=${session} />`;
  else if (hash.startsWith("#/password")) body = html`<div class="card ka-pw"><${OwnPassword} session=${session} onDone=${() => { location.hash = "#/"; }} /></div>`;
  else body = html`<${Overview} status=${status} />`;
  // in keel's 账号 tab keel's frame (its title bar, the instance's name and domain) is enough:
  // no second dark bar, the tabs as a light strip; language and theme follow keel's
  if (session.via_keel) {
    return html`<div class="ka-framed"><${Nav} hash=${hash} alerts=${status ? status.alerts : 0} cls="subnav ka-tabs" />
      <main key=${lang}>${body}</main></div>`;
  }
  return html`<header class="top"><div class="top-in">
      <a class="brand" href="#/" dangerouslySetInnerHTML=${{ __html: logoHTML }}></a>
      <${Nav} hash=${hash} alerts=${status ? status.alerts : 0} />
      <span class="spacer"></span>
      <span class="muted top-host" title=${status ? status.hostname : ""}>${status ? status.domain : ""}</span>
      <${TopMenu} session=${session} lang=${lang} onLang=${onLang} th=${th} onTheme=${onTheme} />
      ${!session.via_keel && html`<button onClick=${logout}>${t("top.logout")}</button>`}
    </div></header>
    <main key=${lang}>${body}</main>`;
}

render(html`<${App} />`, document.getElementById("app"));
