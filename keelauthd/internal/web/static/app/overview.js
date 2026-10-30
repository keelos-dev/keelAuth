// Overview: what keelAuth is now (services, counts, last backup) and what is wrong (alerts).
import { useEffect, useState } from "preact/hooks";
import { api, html } from "./api.js";
import { fmtTime, t, tr } from "./i18n.js";
import { KV, Spinner } from "./ui.js";

// Alerts follows the status (every 30 seconds, main.js): asked once at the first look it kept
// saying "radiusd is not up" from the seconds after an upgrade while the tile next to it
// already said running (user, 2026-10-30).
function Alerts({ status }) {
  const [as, setAs] = useState(null);
  useEffect(() => { api("GET", "v1/alerts").then((r) => setAs(r.alerts || [])).catch(() => setAs([])); }, [status]);
  if (!as || as.length === 0) return null;
  return html`<div class="card"><div class="row-head"><h3>${t("ov.alerts")}</h3></div>
    ${as.map((a) => html`<p class=${a.level === "error" ? "error" : "warn"}>${tr("alert." + a.code, a.text, a.object)}</p>`)}</div>`;
}

const up = (ok, why) => html`<span class=${"badge" + (ok ? " ok" : "")} style=${ok ? null : "color:var(--danger);border-color:var(--danger)"}>${ok ? t("ov.running") : t("ov.down")}</span>${!ok && why ? html` <span class="muted small">${why}</span>` : null}`;

const dur = (n) => (n < 3600 ? Math.max(1, Math.round(n / 60)) + " min" : n < 172800 ? Math.round(n / 3600) + " h" : Math.round(n / 86400) + " d");

export function Overview({ status }) {
  if (!status) return html`<${Spinner} />`;
  const s = status;
  const c = s.counts || {};
  const addr = (s.addresses || []).join(", ") || "–";
  const mk = s.master_key || { slots: [] };
  return html`<div class="stack">
    <div class="card"><div class="row-head"><h3>keelAuth</h3></div>
      <div class="host-grid">
        <${KV} k=${t("ov.version")} v=${s.version} />
        <${KV} k=${t("ov.addresses")} v=${addr} />
        <${KV} k=${t("ov.uptime")} v=${dur(s.uptime_s || 0)} />
        <${KV} k=${t("ov.lastbackup")} v=${s.last_backup ? fmtTime(s.last_backup) : t("ov.never")} />
        <${KV} k=${t("ov.mk")} v=${mk.slots.includes("keel") ? t("gen.mkkeel") : mk.slots.includes("passphrase") ? t("gen.mkpass", fmtTime(mk.passphrase_set)) : t("gen.mknone")} />
      </div></div>
    <${Alerts} status=${status} />
    <div class="tiles">
      <div class="card"><div class="row-head"><h3>${t("ov.services")}</h3></div>
        <table class="kv-table"><tbody>
          ${s.engine === "native"
            ? html`<tr><th>${t("ov.store")}</th><td>${up(s.services && s.services.store, s.service_errors && s.service_errors.store)}</td></tr>`
            : html`<tr><th>Kanidm (LDAP, SSO)</th><td>${up(s.services && s.services.kanidmd, s.service_errors && s.service_errors.kanidmd)}</td></tr>`}
          <tr><th>FreeRADIUS</th><td>${up(s.services && s.services.radiusd, s.service_errors && s.service_errors.radiusd)}</td></tr>
          ${s.managed_by_keel === false && html`<tr><th>keelOS</th><td class="muted">${t("ov.standalone")}</td></tr>`}
          ${s.keel && html`<tr><th>keelOS</th><td>${s.keel.registered ? html`<span class="badge ok">${t("ov.registered")}</span>` : html`<span class="warn">${s.keel.error || t("ov.notyet")}</span>`}</td></tr>`}
        </tbody></table></div>
      <div class="card"><div class="row-head"><h3>${t("ov.accounts")}</h3></div>
        <table class="kv-table"><tbody>
          <tr><th><a href="#/users">${t("nav.users")}</a></th><td>${c.users}</td></tr>
          <tr><th><a href="#/groups">${t("nav.groups")}</a></th><td>${c.groups}</td></tr>
          <tr><th><a href="#/access/sso">${t("acc.sso")}</a></th><td>${c.oidc}</td></tr>
          <tr><th><a href="#/access/radius">${t("acc.radiusclients")}</a></th><td>${c.radius_clients}</td></tr>
        </tbody></table></div>
      <div class="card"><div class="row-head"><h3>${t("ov.ways")}</h3></div>
        <table class="kv-table"><tbody>
          <tr><th><a href="#/access/ldap">LDAP</a></th><td class="mono">ldaps://${s.domain}:${s.ldap_port}</td></tr>
          <tr><th><a href="#/access/sso">SSO (OIDC)</a></th><td class="mono">${s.origin}</td></tr>
          <tr><th><a href="#/access/radius">RADIUS</a></th><td class="mono">${(s.addresses || [])[0] || s.domain}:${s.radius_port}/udp</td></tr>
        </tbody></table></div>
    </div>
  </div>`;
}
