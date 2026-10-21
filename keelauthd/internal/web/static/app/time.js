// Times (keelOS docs/47, keel's static/app/time.js): keelauthd stores and sends UTC; the page
// shows times in the zone of the place, never in the browser's: keel's setting when keel
// manages this keelAuth (it comes with the session), keelAuth's own setting when it runs
// standalone (Settings → Time zone, default UTC). The format is keel's: 2026-10-03 00:04:27.

let zone = "UTC";
let fmt = null; // Intl.DateTimeFormat of the zone, made once

// setZone: the zone from GET session or login/state. A name this browser does not know leaves UTC.
export function setZone(z) {
  try {
    fmt = new Intl.DateTimeFormat("en-CA", { timeZone: z || "UTC", hourCycle: "h23", year: "numeric", month: "2-digit",
      day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
    zone = z || "UTC";
  } catch (_) {
    if (z && z !== "UTC") setZone("UTC");
  }
}
setZone("UTC");

export const getZone = () => zone;

// localStamp: a Date as "YYYY-MM-DD HH:MM[:SS]" on the zone's clock.
export function localStamp(d, secs = true) {
  if (!(d instanceof Date) || isNaN(d)) return "";
  const o = {};
  for (const p of fmt.formatToParts(d)) o[p.type] = p.value;
  return `${o.year}-${o.month}-${o.day} ${o.hour}:${o.minute}` + (secs ? ":" + o.second : "");
}

// fmtTime: what the API sent (RFC 3339) for people; nothing: "–".
export const fmtTime = (x) => (x ? localStamp(new Date(x)) || String(x) : "–");

// zones: the zone names this browser knows, for the standalone setting.
export function zones() {
  try { return ["UTC", ...Intl.supportedValuesOf("timeZone").filter((z) => z !== "UTC")]; } catch (_) { return ["UTC"]; }
}
