// /api/hc/db – document store for the manpower report (Cloudflare D1, binding: DB, table hc_docs)
//   GET  ?since=<ms>   → { docs:[{path,ver,data,del}], now }
//   GET  ?prefix=<p/>  → { docs:[…], now }
//   POST { ops:[{op:"set"|"delete"|"add"|"patch", path, data/date/fields}] }
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

const MAX_VERSIONS = 60;
async function ensure(db) {
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS hc_docs (path TEXT PRIMARY KEY, data TEXT, ver INTEGER NOT NULL, del INTEGER NOT NULL DEFAULT 0)"),
    db.prepare("CREATE INDEX IF NOT EXISTS hc_docs_ver ON hc_docs(ver)")
  ]);
}
const row = r => ({ path: r.path, ver: r.ver, del: !!r.del, data: r.del || r.data == null ? null : JSON.parse(r.data) });

export async function onRequestGet({ request, env }) {
  if (!(await roleOf(request, env))) return json({ error: "login" }, 401);
  try {
    await ensure(env.DB);
    const u = new URL(request.url), now = Date.now();
    const prefix = u.searchParams.get("prefix");
    if (prefix != null) {
      const r = await env.DB.prepare("SELECT * FROM hc_docs WHERE del = 0 AND substr(path, 1, ?) = ?").bind(prefix.length, prefix).all();
      return json({ docs: r.results.map(row), now });
    }
    const since = Number(u.searchParams.get("since") || 0);
    const r = await env.DB.prepare("SELECT * FROM hc_docs WHERE ver > ? AND path NOT LIKE 'versions/%' ORDER BY ver").bind(since).all();
    return json({ docs: r.results.map(row), now });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

const PATCH_FIELDS = new Set([
  "hc", "hcM", "to", "toX4", "dCT", "dTV", "dX4", "nCT", "nTV", "nX4", "dX4M", "nX4M",
  "dGT", "dQC", "dRW", "dRMA", "dDCT", "nGT", "nQC", "nRW", "nRMA", "nDCT",
  "pDir", "pX4", "pTV", "pInd", "off"
]);
function validatePatch(o) {
  const path = String(o.path || ""), date = String(o.date || ""), fields = o.fields;
  const m = /^months\/(\d{4})-(0[1-9]|1[0-2])$/.exec(path);
  if (!m || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !date.startsWith(path.slice(7) + "-")) return "Invalid month/date";
  if (!fields || typeof fields !== "object" || Array.isArray(fields)) return "Invalid fields";
  const keys = Object.keys(fields);
  if (!keys.length || keys.length > 30) return "Invalid fields count";
  for (const k of keys) {
    if (!PATCH_FIELDS.has(k)) return "Field not allowed: " + k;
    const v = fields[k];
    if (k === "off") { if (v !== "" && v !== "sun" && v !== "hol") return "Invalid off value"; }
    else if (k === "hcM") { if (v !== 0 && v !== 1 && v !== null) return "Invalid hcM value"; }
    else if (v !== null && (typeof v !== "number" || !Number.isFinite(v) || v < 0)) return "Invalid numeric value: " + k;
  }
  return null;
}

export async function onRequestPost({ request, env }) {
  const role = await roleOf(request, env);
  if (!role) return json({ error: "login" }, 401);
  if (role !== "edit") return json({ error: "Chế độ chỉ xem – không được sửa" }, 403);
  try {
    const body = await request.json().catch(() => null);
    const ops = body && Array.isArray(body.ops) ? body.ops : null;
    if (!ops || !ops.length || ops.length > 50) return json({ error: "Invalid ops" }, 400);
    await ensure(env.DB);
    const last = (await env.DB.prepare("SELECT MAX(ver) AS v FROM hc_docs").first())?.v || 0;
    const now = Math.max(Date.now(), last + 1), paths = [], stmts = [], patchIndexes = [];
    let addedVersion = false;
    for (const o of ops) {
      let path = String(o.path || "");
      if (o.op === "add") { path = path.replace(/\/?$/, "/") + now.toString(36) + Math.random().toString(36).slice(2, 8); if (path.startsWith("versions/")) addedVersion = true; }
      if (!path || path.endsWith("/") || path.length > 200) return json({ error: "Invalid path: " + path }, 400);
      paths.push(path);
      if (o.op === "patch") {
        const invalid = validatePatch(o);
        if (invalid) return json({ error: invalid }, 400);
        const fields = Object.entries(o.fields);
        const sets = [];
        const binds = [];
        for (const [key, value] of fields) {
          // Locate the day by its date inside the UPDATE itself; no stale array index is used.
          sets.push("'$.days[' || (SELECT CAST(key AS INTEGER) FROM json_each(data, '$.days') WHERE json_extract(value, '$.date') = ? LIMIT 1) || ']." + key + "'");
          binds.push(o.date, JSON.stringify(value));
        }
        const pairs = sets.map((p, i) => p + ", json(?)");
        const sql = "UPDATE hc_docs SET data=json_set(data, " + pairs.join(", ") + ", '$.updatedAt', json(?)), ver=MAX(?, (SELECT COALESCE(MAX(ver),0)+1 FROM hc_docs)), del=0 WHERE path=? AND del=0 AND EXISTS (SELECT 1 FROM json_each(data, '$.days') WHERE json_extract(value, '$.date')=?)";
        binds.push(JSON.stringify(new Date().toISOString()), Date.now(), path, o.date);
        patchIndexes.push(stmts.length);
        stmts.push(env.DB.prepare(sql).bind(...binds));
      }
      else if (o.op === "delete") stmts.push(env.DB.prepare("INSERT INTO hc_docs (path, data, ver, del) VALUES (?, NULL, ?, 1) ON CONFLICT(path) DO UPDATE SET data = NULL, ver = excluded.ver, del = 1").bind(path, now));
      else if (o.op === "set" || o.op === "add") {
        const data = JSON.stringify(o.data ?? null);
        if (data.length > 1900000) return json({ error: "Dữ liệu quá lớn (tối đa ~2MB/mục): " + path }, 413);
        stmts.push(env.DB.prepare("INSERT INTO hc_docs (path, data, ver, del) VALUES (?, ?, ?, 0) ON CONFLICT(path) DO UPDATE SET data = excluded.data, ver = excluded.ver, del = 0").bind(path, data, now));
      } else if (o.op !== "patch") return json({ error: "Unknown op: " + o.op }, 400);
    }
    const results = await env.DB.batch(stmts);
    for (const ix of patchIndexes) {
      const changes = results[ix] && results[ix].meta && results[ix].meta.changes;
      if (!changes) return json({ error: "Không tìm thấy ngày cần cập nhật trong tháng" }, 404);
    }
    if (addedVersion) /* keep the newest MAX_VERSIONS snapshots */
      await env.DB.prepare("DELETE FROM hc_docs WHERE path LIKE 'versions/%' AND path NOT IN (SELECT path FROM hc_docs WHERE path LIKE 'versions/%' ORDER BY ver DESC LIMIT ?)").bind(MAX_VERSIONS).run();
    const patchDocs = [];
    // Return the authoritative month documents so the browser cache can reconcile after a patch.
    for (const p of new Set(ops.filter(o => o.op === "patch").map(o => String(o.path)))) {
      const r = await env.DB.prepare("SELECT * FROM hc_docs WHERE path=? AND del=0").bind(p).first();
      if (r) patchDocs.push(row(r));
    }
    return json({ ok: true, paths, now, docs: patchDocs });
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}
