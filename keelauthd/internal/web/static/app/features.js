// features.js: the feature modules (keelauthd features.go, docs/02 §10): attributes on an account,
// each declared once in keelauthd; the page draws their fields from the declaration (GET
// v1/features), so a new module needs nothing here.
import { html } from "./api.js";
import { getLang, t } from "./i18n.js";

// featText: a declaration's text in the page's language
export const featText = (x) => (x && (x[getLang()] || x.en)) || "";
// a choice field's options (the admin's, Settings → Modules) and what one is called
export const featOptions = (f, fd) => ((f.conf || {}).options || {})[fd.name] || [];
export const optTitle = (o) => featText(o.title) || o.code;
// featCell: a one-row module's value of a user, as the lists show it ("" = none)
export function featCell(u, f, fd) {
  const v = ((u.features || {})[f.name] || {})[fd.name];
  if (v === undefined || v === null || v === "") return "";
  if (fd.type !== "choice") return String(v);
  const o = featOptions(f, fd).find((x) => x.code === v);
  return o ? optTitle(o) : String(v);
}

// FeatureFields: the inputs of every enabled feature module; value = {module: rows | object},
// onChange(up) with up(value) -> new value. Empty inputs stay empty (the default is the
// placeholder; keelauthd keeps it at save).
export function FeatureFields({ features, value, onChange }) {
  const on = (features || []).filter((f) => f.enabled);
  if (!on.length) return null;
  const put = (name, v) => onChange((cur) => ({ ...cur, [name]: v }));
  const input = (f, fd, v, set) => {
    const len = fd.admin_len ? ((f.conf || {}).len || {})[fd.name] || 0 : 0;
    const ph = fd.default !== undefined && fd.default !== null ? String(fd.default) : len ? t("feat.exact", len) : "";
    if (fd.type === "choice") {
      return html`<select value=${v ?? ""} onChange=${(e) => set(e.target.value)}><option value=""></option>
        ${featOptions(f, fd).map((o) => html`<option value=${o.code}>${optTitle(o)}</option>`)}</select>`;
    }
    if (fd.type === "bool") return html`<input type="checkbox" checked=${!!v} onChange=${(e) => set(e.target.checked)} />`;
    const num = fd.type === "port" || fd.type === "int";
    return html`<input type=${num ? "number" : "text"} spellcheck="false" autocapitalize="off" required=${!!fd.required}
      min=${fd.type === "port" ? 1 : undefined} max=${fd.type === "port" ? 65535 : fd.type === "int" && fd.max ? fd.max : undefined}
      maxlength=${fd.type === "text" && (len || fd.max) ? len || fd.max : undefined} minlength=${len || undefined}
      pattern=${fd.type === "text" && fd.pattern ? fd.pattern : undefined} placeholder=${ph} value=${v ?? ""} onInput=${(e) => set(e.target.value)} />`;
  };
  return on.map((f) => {
    const v = value[f.name] ?? (f.rows ? [] : {});
    if (!f.rows) {
      return html`<fieldset class="hn-g feat"><legend>${featText(f.title)}</legend><p class="muted small">${featText(f.help)}</p>
        ${f.fields.map((fd) => html`<label>${featText(fd.title)}${input(f, fd, v[fd.name], (x) => put(f.name, { ...v, [fd.name]: x }))}</label>`)}</fieldset>`;
    }
    const setRow = (i, k, x) => put(f.name, v.map((r, j) => (j === i ? { ...r, [k]: x } : r)));
    return html`<fieldset class="hn-g feat"><legend>${featText(f.title)}</legend><p class="muted small">${featText(f.help)}</p>
      ${v.length ? html`<table class="data plain feat-rows"><thead><tr>${f.fields.map((fd) => html`<th>${featText(fd.title)}</th>`)}<th></th></tr></thead>
        <tbody>${v.map((r, i) => html`<tr>${f.fields.map((fd) => html`<td>${input(f, fd, r[fd.name], (x) => setRow(i, fd.name, x))}</td>`)}
          <td><button type="button" class="btn" onClick=${() => put(f.name, v.filter((_, j) => j !== i))}>${t("feat.remove")}</button></td></tr>`)}</tbody></table>`
        : html`<p class="muted small">${t("feat.none")}</p>`}
      <button type="button" class="btn" onClick=${() => put(f.name, [...v, {}])}>${t("feat.add")}</button></fieldset>`;
  });
}
