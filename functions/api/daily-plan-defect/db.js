// Dedicated D1 endpoint for the Daily Plan & Defect module.
// Binding: DB -> dailyhc_db. Does not read or modify hc_docs/dailyhc_docs.
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "content-type, x-hc-token",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Max-Age": "86400"
};
const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS }
});
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
async function roleOf(request, env) {
  const authOn = !!(env.HC_PASSWORD || env.HC_VIEW_PASSWORD);
  if (!authOn) return "edit";
  const given = request.headers.get("x-hc-token") || "";
  for (const role of ["edit", "view"]) {
    const pw = role === "edit" ? env.HC_PASSWORD : env.HC_VIEW_PASSWORD;
    if (pw && given === role + "." + await sha("hc|" + role + "|" + pw)) return role;
  }
  return null;
}
async function ensure(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS daily_plan_defect_docs (
    doc_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    ver INTEGER NOT NULL,
    updated_at TEXT NOT NULL
  )`).run();
}

export async function onRequestGet({ request, env }) {
  const role = await roleOf(request, env);
  if (!role) return json({ ok: false, error: "login_required" }, 401);
  try {
    await ensure(env.DB);
    const row = await env.DB.prepare("SELECT doc_id, data, ver, updated_at FROM daily_plan_defect_docs WHERE doc_id = 'main'").first();
    return json({ ok: true, doc: row ? { data: JSON.parse(row.data), ver: row.ver, updatedAt: row.updated_at } : null });
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  const role = await roleOf(request, env);
  if (!role) return json({ ok: false, error: "login_required" }, 401);
  if (role !== "edit") return json({ ok: false, error: "read_only" }, 403);
  try {
    const body = await request.json().catch(() => null);
    if (!body || !body.data || typeof body.data !== "object" || Array.isArray(body.data))
      return json({ ok: false, error: "invalid_data" }, 400);
    const serialized = JSON.stringify(body.data);
    if (serialized.length > 1900000) return json({ ok: false, error: "document_too_large" }, 413);
    const expectedVer = Number(body.expectedVer);
    if (!Number.isSafeInteger(expectedVer) || expectedVer < 0)
      return json({ ok: false, error: "invalid_expected_version" }, 400);
    await ensure(env.DB);
    const current = await env.DB.prepare("SELECT ver FROM daily_plan_defect_docs WHERE doc_id = 'main'").first();
    const currentVer = current ? Number(current.ver) : 0;
    if (currentVer !== expectedVer)
      return json({ ok: false, error: "version_conflict", currentVer }, 409);
    const nextVer = currentVer + 1;
    const updatedAt = new Date().toISOString();
    const result = await env.DB.prepare(`INSERT INTO daily_plan_defect_docs (doc_id, data, ver, updated_at)
      VALUES ('main', ?, ?, ?)
      ON CONFLICT(doc_id) DO UPDATE SET data=excluded.data, ver=excluded.ver, updated_at=excluded.updated_at
      WHERE daily_plan_defect_docs.ver = ?`).bind(serialized, nextVer, updatedAt, expectedVer).run();
    if (!result.meta || result.meta.changes !== 1) {
      const latest = await env.DB.prepare("SELECT ver FROM daily_plan_defect_docs WHERE doc_id='main'").first();
      return json({ ok: false, error: "version_conflict", currentVer: latest ? Number(latest.ver) : 0 }, 409);
    }
    return json({ ok: true, ver: nextVer, updatedAt });
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}
