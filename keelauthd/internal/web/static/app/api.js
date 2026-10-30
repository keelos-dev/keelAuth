// Talking to keelauthd: JSON over fetch with the session cookie and the CSRF header. Every
// address is relative (no leading "/"): the page works at / on keelAuth and under a prefix
// when keel passes it through (docs/02 section 5), e.g. /i/<instance>/.
import { h } from "preact";
import htm from "htm";
import { t } from "./i18n.js";

export const html = htm.bind(h);

export class HTTPError extends Error {
  constructor(status, msg, body) { super(msg); this.status = status; this.body = body; }
}

let csrf = "";
let onLoggedOut = () => {};
export function setCSRF(v) { csrf = v || ""; }
export function setLoggedOut(f) { onLoggedOut = f; }

// rel: an API path ("/v1/users" or "v1/users") as an address relative to this page.
export const rel = (p) => p.replace(/^\/+/, "");

// underKeel: the page is in keel's frame (/i/<instance>/ on keelOS, /h/<host>/i/<instance>/
// through a keel manager; docs/02 section 5). keel's login guards it with an access cookie of
// 15 minutes that keel's own page renews at the root's /refresh (the refresh cookie lives
// there). So a 401 here is keel's, not keelauthd's: renew once and try again; only when that
// fails is the login over (keel's, so its page is where to log in again, main.js).
export const underKeel = /\/i\/[^/]+\/$/.test(location.pathname);
let refreshing = null;
function keelRefresh() {
  if (!refreshing) {
    // the one address at the root on purpose: keel's (or the manager's) /refresh, not this page's
    refreshing = fetch(location.origin + "/refresh", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", cache: "no-store" })
      .then((r) => r.ok).catch(() => false).finally(() => { refreshing = null; });
  }
  return refreshing;
}
async function renewed(r, retried) { return r.status === 401 && underKeel && !retried && await keelRefresh(); }

// srvText: the server's error in the page's language when it carries a code the page knows.
function srvText(j) {
  if (!j) return "";
  const k = "srv." + j.code;
  const s = j.code ? t(k) : k;
  return s !== k ? s : j.error || "";
}

export async function api(method, path, body, retried) {
  const hd = {};
  if (method !== "GET") {
    hd["Content-Type"] = "application/json";
    if (csrf) hd["X-Keelauth-CSRF"] = csrf;
  }
  const r = await fetch(rel(path), {
    method, headers: hd, credentials: "same-origin", cache: "no-store",
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (await renewed(r, retried)) return api(method, path, body, true);
  let j = null;
  try { j = await r.json(); } catch (_) { /* empty */ }
  if (!r.ok) {
    if (r.status === 401 && path !== "login" && path !== "session" && path !== "password") onLoggedOut();
    let msg = srvText(j) || r.status + " " + r.statusText;
    if (j && j.code === "weak_password" && j.error) msg = t("srv.weak_password") + " (" + j.error.replace(/^password refused: /, "") + ")";
    throw new HTTPError(r.status, msg, j);
  }
  return j;
}

// upload sends a file as the request's body (a backup: POST v1/backups/upload).
export async function upload(path, file, retried) {
  const hd = { "Content-Type": "application/gzip" };
  if (csrf) hd["X-Keelauth-CSRF"] = csrf;
  const r = await fetch(rel(path), { method: "POST", headers: hd, credentials: "same-origin", cache: "no-store", body: file });
  if (await renewed(r, retried)) return upload(path, file, true);
  let j = null;
  try { j = await r.json(); } catch (_) { /* empty */ }
  if (!r.ok) throw new HTTPError(r.status, srvText(j) || r.status + " " + r.statusText, j);
  return j;
}

// send sends raw bytes as the request's body with their own type (a logo: PUT v1/brand/logo).
export async function send(method, path, body, ctype, retried) {
  const hd = { "Content-Type": ctype };
  if (csrf) hd["X-Keelauth-CSRF"] = csrf;
  const r = await fetch(rel(path), { method, headers: hd, credentials: "same-origin", cache: "no-store", body });
  if (await renewed(r, retried)) return send(method, path, body, ctype, true);
  let j = null;
  try { j = await r.json(); } catch (_) { /* empty */ }
  if (!r.ok) throw new HTTPError(r.status, srvText(j) || r.status + " " + r.statusText, j);
  return j;
}
