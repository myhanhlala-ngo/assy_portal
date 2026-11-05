// /api/hc/login  – GET: who am I · POST {password}: sign in · DELETE: sign out
/* ---- auth helpers ---- */
// Shared helpers for the manpower report API (/api/hc/*)
// Optional passwords (Cloudflare → Settings → Variables and Secrets):
//   HC_PASSWORD       – edit access
//   HC_VIEW_PASSWORD  – view-only access
// With neither set, the report is open to anyone who has the link.
/* the report may also be opened as an HTML file on a PC (origin "null") → allow cross-origin calls; sign-in travels in the x-hc-token header, not in cookies */
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type, x-hc-token", "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS", "Access-Control-Max-Age": "86400" };
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS, ...headers } });
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

const COOKIE = "hc_auth";
async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
const authOn = env => !!(env.HC_PASSWORD || env.HC_VIEW_PASSWORD);
async function tokenFor(role, env) {
  const pw = role === "edit" ? env.HC_PASSWORD : env.HC_VIEW_PASSWORD;
  return pw ? role + "." + (await sha("hc|" + role + "|" + pw)) : null;
}
/* → "edit" | "view" | null (not signed in) */
async function roleOf(request, env) {
  if (!authOn(env)) return "edit";
  const m = (request.headers.get("cookie") || "").match(/(?:^|;\s*)hc_auth=([^;]+)/);
  const given = request.headers.get("x-hc-token") || (m && m[1]);
  if (!given) return null;
  for (const role of ["edit", "view"]) { const t = await tokenFor(role, env); if (t && t === given) return role; }
  return null;
}
const setCookie = v => `${COOKIE}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${v ? 15552000 : 0}`;

export async function onRequestGet({ request, env }) {
  const role = await roleOf(request, env);
  return json({ ok: true, auth: authOn(env) && !!role, role: role || "view", required: authOn(env) });
}
export async function onRequestPost({ request, env }) {
  const { password = "" } = await request.json().catch(() => ({}));
  for (const [role, pw] of [["edit", env.HC_PASSWORD], ["view", env.HC_VIEW_PASSWORD]]) {
    if (pw && password === pw) { const token = await tokenFor(role, env); return json({ ok: true, role, token }, 200, { "Set-Cookie": setCookie(token) }); }
  }
  if (!authOn(env)) return json({ ok: true, role: "edit" });
  return json({ ok: false, error: "Wrong password" }, 401);
}
export async function onRequestDelete() {
  return json({ ok: true }, 200, { "Set-Cookie": setCookie("") });
}
