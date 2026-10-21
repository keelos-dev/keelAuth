// Small pieces the pages share: keelOS's keel/internal/web/static/app/ui.js (Dialog,
// FormDialog, ask, toast, Spinner …) without the parts for guests (state icons, consoles, OS
// labels, NUMA). Keep the two in step: keelAuth's page looks and behaves like keel's.
import { html } from "./api.js";
import { useEffect, useRef, useState } from "preact/hooks";
import { t } from "./i18n.js";

const localTimes = (s) => s;

// gib: a size in GiB; below 1 GiB in MiB (or KiB), so that a small amount does not read "0.0 GiB" (user 2026-10-03).
export function gib(bytes) {
  if (!bytes && bytes !== 0) return "–";
  if (bytes === 0) return "0 GiB";
  if (bytes < 2 ** 30) return fsize(bytes);
  const g = bytes / 2 ** 30;
  return g >= 1024 ? (g / 1024).toFixed(2) + " TiB" : g >= 10 ? g.toFixed(0) + " GiB" : g.toFixed(1) + " GiB";
}

// fsize: a file's or a small amount's size in the unit that fits (358 KiB, 12 MiB); from 1 GiB up as gib().
export function fsize(bytes) {
  if (!bytes && bytes !== 0) return "–";
  if (bytes >= 2 ** 30) return gib(bytes);
  if (bytes >= 2 ** 20) { const m = bytes / 2 ** 20; return (m >= 10 ? m.toFixed(0) : m.toFixed(1)) + " MiB"; }
  if (bytes >= 1024) return (bytes / 1024).toFixed(0) + " KiB";
  return bytes + " B";
}

export function mib(n) { return n >= 1024 && n % 1024 === 0 ? n / 1024 + " GiB" : n + " MiB"; }

export function Bar({ pct }) {
  if (pct === undefined || !isFinite(pct)) return null;
  return html`<div class="bar"><i style=${{ width: Math.min(100, Math.max(0, pct)).toFixed(0) + "%" }}></i></div>`;
}

export function KV({ k, v, pct }) {
  return html`<div class="kv"><div class="k">${k}</div><div class="v">${v}</div><${Bar} pct=${pct} /></div>`;
}

let toastTimer = 0;
export function toast(msg, ms) {
  let el = document.getElementById("toast");
  if (!el) {
    el = document.createElement("div");
    el.id = "toast";
    el.className = "toast";
    document.body.append(el);
  }
  el.textContent = msg;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, ms || 3500);
}

// loadCSS adds a stylesheet once.
export function loadCSS(href) {
  if (document.querySelector('link[href="' + href + '"]')) return;
  const l = document.createElement("link");
  l.rel = "stylesheet";
  l.href = href;
  document.head.append(l);
}

// Spinner: shown while a page loads; it appears only after 200 ms, so a quick answer does not
// flash it.
export function Spinner({ small }) {
  const [on, setOn] = useState(false);
  useEffect(() => { const id = setTimeout(() => setOn(true), 200); return () => clearTimeout(id); }, []);
  if (!on) return null;
  return html`<div class=${"spin-wrap" + (small ? " small" : "")} role="status" aria-live="polite"><span class="spinner"></span><span class="muted small">${t("loading")}</span></div>`;
}

// ask / askText: the page's own confirm and prompt (user 2026-10-01: no browser popups for
// questions). A modal <dialog> with the question, OK and Cancel (Esc = Cancel); askText adds a
// text field. They resolve to true/false and to the text/null, like confirm() and prompt().
function dialogBox(message, withText) {
  return new Promise((resolve) => {
    const d = document.createElement("dialog");
    d.className = "ask";
    const p = document.createElement("p");
    p.textContent = message;
    p.style.whiteSpace = "pre-wrap";
    d.appendChild(p);
    let input = null;
    if (withText) {
      input = document.createElement("input");
      input.type = "text";
      input.autocomplete = "off";
      d.appendChild(input);
    }
    const row = document.createElement("div");
    row.className = "actions";
    const cancel = document.createElement("button");
    cancel.className = "btn";
    cancel.textContent = t("dlg.cancel");
    const ok = document.createElement("button");
    ok.className = "primary";
    ok.textContent = t("dlg.ok");
    row.append(cancel, ok);
    d.appendChild(row);
    let done = false;
    const finish = (v) => { if (done) return; done = true; d.close(); d.remove(); resolve(v); };
    cancel.onclick = () => finish(withText ? null : false);
    ok.onclick = () => finish(withText ? input.value : true);
    d.addEventListener("cancel", (e) => { e.preventDefault(); finish(withText ? null : false); });
    if (input) input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); ok.click(); } });
    document.body.appendChild(d);
    d.showModal();
    (input || ok).focus();
  });
}
// Dialog: a modal <dialog> with a title; closing it (Esc, a button) calls onClose. The pages
// show lists; whatever adds or edits something opens in one (user 2026-10-03: adding is rare,
// its form does not belong on the page).
// wide: a dialog that shows something to read (a config, a log) rather than a form
export function Dialog({ title, children, onClose, wide }) {
  const ref = useRef(null);
  useEffect(() => {
    const d = ref.current;
    d.showModal();
    const f = () => onClose();
    d.addEventListener("close", f);
    return () => d.removeEventListener("close", f);
  }, []);
  return html`<dialog ref=${ref} class=${"form-dialog" + (wide ? " wide" : "")}><h3>${title}</h3>${children}</dialog>`;
}

// FormDialog: a Dialog around a form with its two buttons. submit is the label of the button
// that runs onSubmit (async); while it runs the buttons are off; when it throws, the message
// shows in the dialog, which stays open; otherwise the dialog closes. disabled: the form is
// not ready (nothing chosen yet); danger: the button is a destructive one.
export function FormDialog({ title, submit, danger, disabled, onSubmit, onClose, children }) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const go = async (ev) => {
    ev.preventDefault();
    setErr("");
    setBusy(true);
    try { await onSubmit(); } catch (e) { setErr(localTimes(e.message || String(e))); setBusy(false); return; }
    onClose();
  };
  return html`<${Dialog} title=${title} onClose=${onClose}><form class="stack" onSubmit=${go}>
    ${children}
    ${err && html`<p class="error">${err}</p>`}
    <div class="actions"><button type="submit" class=${danger ? "btn danger" : "primary"} disabled=${busy || !!disabled}>${submit || t("dlg.ok")}</button>
      <button type="button" disabled=${busy} onClick=${onClose}>${t("dlg.cancel")}</button>${busy && html`<${Spinner} small=${true} />`}</div>
  </form><//>`;
}

export const ask = (message) => dialogBox(message, false);
export const askText = (message) => dialogBox(message, true);
