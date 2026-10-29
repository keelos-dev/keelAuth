// The company's name and logo on the page (keelauthd brand.go): GET brand (no login) gives
// the names per language and whether there is a logo; brandName(lang) picks the name for the
// language, or the first one set (zh, en, ja), or "" (the page then says keelAuth).
import { api, rel } from "./api.js";

const order = ["zh", "en", "ja"];
let brand = { name: {}, logo: false, logo_tag: "" };
const subs = new Set();

export function getBrand() { return brand; }
export function onBrand(f) { subs.add(f); return () => subs.delete(f); }
export async function loadBrand() {
  try { brand = await api("GET", "brand"); } catch (_) { /* keelAuth's own */ }
  subs.forEach((f) => f(brand));
  return brand;
}
export function brandName(lang) {
  const n = brand.name || {};
  if (n[lang]) return n[lang];
  for (const l of order) if (n[l]) return n[l];
  return "";
}
export function logoURL() { return brand.logo ? rel("brand/logo?v=" + brand.logo_tag) : ""; }
