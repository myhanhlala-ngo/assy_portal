// /api/sync/<app> – kho dữ liệu dùng chung cho các ứng dụng trong ASSY Portal (Cloudflare D1, binding: DB)
//   GET  ?since=<ver>        → { ok, now, data:{ key:{ value, ver, who, ts, del } } }   (since=0 → toàn bộ, bỏ mục đã xóa)
//   GET  ?history=<key>      → { ok, items:[{ id, ver, who, ts, del, size }] }        (lịch sử 1 khóa, để khôi phục)
//   GET  ?hid=<id>           → { ok, item:{ id, key, ver, who, ts, del, value } }
//   POST { by, items:[{ key, json } | { key, del:1 }] }  → { ok, now }               (cần quyền sửa)
// Quyền: dùng chung mật khẩu của báo cáo nhân lực (HC_PASSWORD = sửa, HC_VIEW_PASSWORD = chỉ xem).
//   Xem: công khai. Ghi: cần đăng nhập quyền sửa (nếu chưa đặt mật khẩu nào thì ai có link cũng ghi được).

const APPS = new Set(["daily-plan-defect", "loss-cost", "material-ng-loss", "quality", "revenue-manpower"]);
const MAX_ITEMS = 25;               // mỗi lần POST (trình duyệt tự chia nhỏ)
const MAX_BYTES = 1900000;          // D1: tối đa ~2MB / dòng
const KEEP_HISTORY = 400;           // số bản lịch sử giữ lại cho mỗi ứng dụng

/* ---- auth (giống /api/hc/*) ---- */
const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type, x-hc-token", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Max-Age": "86400" };
const HDR = { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS };
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: HDR });
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });
async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
const authOn = env => !!(env.HC_PASSWORD || env.HC_VIEW_PASSWORD);
async function tokenFor(role, env) {
  const pw = role === "edit" ? env.HC_PASSWORD : env.HC_VIEW_PASSWORD;
  return pw ? role + "." + (await sha("hc|" + role + "|" + pw)) : null;
}
async function roleOf(request, env) {
  if (!authOn(env)) return "edit";
  const m = (request.headers.get("cookie") || "").match(/(?:^|;\s*)hc_auth=([^;]+)/);
  const given = request.headers.get("x-hc-token") || (m && m[1]);
  if (!given) return null;
  for (const role of ["edit", "view"]) { const t = await tokenFor(role, env); if (t && t === given) return role; }
  return null;
}

/* ---- schema ---- */
let schemaReady = false;
async function ensure(db) {
  if (schemaReady) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS sync_kv (app TEXT NOT NULL, key TEXT NOT NULL, value TEXT, ver INTEGER NOT NULL, who TEXT, ts INTEGER, del INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (app, key))"),
    db.prepare("CREATE INDEX IF NOT EXISTS sync_kv_ver ON sync_kv(ver)"),
    db.prepare("CREATE INDEX IF NOT EXISTS sync_kv_app_ver ON sync_kv(app, ver)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sync_hist (id INTEGER PRIMARY KEY AUTOINCREMENT, app TEXT NOT NULL, key TEXT NOT NULL, value TEXT, ver INTEGER, who TEXT, ts INTEGER, del INTEGER)"),
    db.prepare("CREATE INDEX IF NOT EXISTS sync_hist_app ON sync_hist(app, id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS sync_hist_key ON sync_hist(app, key, id)"),
    db.prepare("CREATE TRIGGER IF NOT EXISTS sync_kv_hist_i AFTER INSERT ON sync_kv BEGIN INSERT INTO sync_hist (app, key, value, ver, who, ts, del) VALUES (NEW.app, NEW.key, NEW.value, NEW.ver, NEW.who, NEW.ts, NEW.del); END"),
    db.prepare("CREATE TRIGGER IF NOT EXISTS sync_kv_hist_u AFTER UPDATE ON sync_kv BEGIN INSERT INTO sync_hist (app, key, value, ver, who, ts, del) VALUES (NEW.app, NEW.key, NEW.value, NEW.ver, NEW.who, NEW.ts, NEW.del); END")
  ]);
  schemaReady = true;
}
const appOf = params => { const a = String(params.app || ""); return APPS.has(a) ? a : null; };
const bytes = s => new TextEncoder().encode(s).length;

export async function onRequestGet({ request, env, params }) {
  const app = appOf(params);
  if (!app) return json({ ok: false, error: "Unknown app" }, 404);
  try {
    await ensure(env.DB);
    const u = new URL(request.url);
    if (u.searchParams.has("history")) {
      const r = await env.DB.prepare("SELECT id, ver, who, ts, del, length(value) AS size FROM sync_hist WHERE app=? AND key=? ORDER BY id DESC LIMIT 100").bind(app, u.searchParams.get("history")).all();
      return json({ ok: true, items: r.results });
    }
    if (u.searchParams.has("hid")) {
      const r = await env.DB.prepare("SELECT id, key, ver, who, ts, del, value FROM sync_hist WHERE app=? AND id=?").bind(app, Number(u.searchParams.get("hid")) || 0).first();
      if (!r) return json({ ok: false, error: "Not found" }, 404);
      return new Response('{"ok":true,"item":{"id":' + r.id + ',"key":' + JSON.stringify(r.key) + ',"ver":' + r.ver + ',"who":' + JSON.stringify(r.who || "") + ',"ts":' + (r.ts || 0) + ',"del":' + (r.del ? 1 : 0) + ',"value":' + (r.del || r.value == null ? "null" : r.value) + "}}", { headers: HDR });
    }
    const since = Math.max(0, Math.floor(Number(u.searchParams.get("since")) || 0));
    // Đọc trong 1 batch (1 giao dịch) để "now" và dữ liệu nhất quán với nhau
    const [mx, rows] = await env.DB.batch([
      env.DB.prepare("SELECT COALESCE(MAX(ver),0) AS v FROM sync_kv"),
      since > 0
        ? env.DB.prepare("SELECT key, value, ver, who, ts, del FROM sync_kv WHERE app=? AND ver>? ORDER BY ver").bind(app, since)
        : env.DB.prepare("SELECT key, value, ver, who, ts, del FROM sync_kv WHERE app=? AND del=0 ORDER BY ver").bind(app)
    ]);
    const now = (mx.results[0] && mx.results[0].v) || 0;
    // Ghép chuỗi trực tiếp: giá trị đã là JSON hợp lệ trong D1, không cần parse lại
    const parts = rows.results.map(r => JSON.stringify(r.key) + ':{"ver":' + r.ver + ',"who":' + JSON.stringify(r.who || "") + ',"ts":' + (r.ts || 0) + ',"del":' + (r.del ? 1 : 0) + ',"value":' + (r.del || r.value == null ? "null" : r.value) + "}");
    return new Response('{"ok":true,"now":' + now + ',"data":{' + parts.join(",") + "}}", { headers: HDR });
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}

export async function onRequestPost({ request, env, params }) {
  const app = appOf(params);
  if (!app) return json({ ok: false, error: "Unknown app" }, 404);
  const role = await roleOf(request, env);
  if (!role) return json({ ok: false, error: "login" }, 401);
  if (role !== "edit") return json({ ok: false, error: "Chế độ chỉ xem – không được sửa" }, 403);
  try {
    const body = await request.json().catch(() => null);
    const items = body && Array.isArray(body.items) ? body.items : null;
    if (!items || !items.length || items.length > MAX_ITEMS) return json({ ok: false, error: "Invalid items" }, 400);
    const who = String((body && body.by) || "").slice(0, 60);
    await ensure(env.DB);
    const ts = Date.now(), stmts = [];
    for (const it of items) {
      const key = String((it && it.key) || "");
      if (!key || key.length > 200) return json({ ok: false, error: "Invalid key" }, 400);
      if (it.del) {
        stmts.push(env.DB.prepare("INSERT INTO sync_kv (app, key, value, ver, who, ts, del) VALUES (?, ?, NULL, (SELECT COALESCE(MAX(ver),0)+1 FROM sync_kv), ?, ?, 1) ON CONFLICT(app, key) DO UPDATE SET value=NULL, ver=excluded.ver, who=excluded.who, ts=excluded.ts, del=1").bind(app, key, who, ts));
        continue;
      }
      const v = it.json;
      if (typeof v !== "string") return json({ ok: false, error: "Invalid value: " + key }, 400);
      if (bytes(v) > MAX_BYTES) return json({ ok: false, error: "Dữ liệu quá lớn (tối đa ~1.9MB/mục): " + key }, 413);
      try { JSON.parse(v); } catch (e) { return json({ ok: false, error: "Invalid JSON: " + key }, 400); }
      stmts.push(env.DB.prepare("INSERT INTO sync_kv (app, key, value, ver, who, ts, del) VALUES (?, ?, ?, (SELECT COALESCE(MAX(ver),0)+1 FROM sync_kv), ?, ?, 0) ON CONFLICT(app, key) DO UPDATE SET value=excluded.value, ver=excluded.ver, who=excluded.who, ts=excluded.ts, del=0").bind(app, key, v, who, ts));
    }
    stmts.push(env.DB.prepare("DELETE FROM sync_hist WHERE app=?1 AND id <= (SELECT id FROM sync_hist WHERE app=?1 ORDER BY id DESC LIMIT 1 OFFSET ?2)").bind(app, KEEP_HISTORY));
    stmts.push(env.DB.prepare("SELECT COALESCE(MAX(ver),0) AS v FROM sync_kv"));
    const res = await env.DB.batch(stmts);
    const last = res[res.length - 1];
    return json({ ok: true, now: (last.results[0] && last.results[0].v) || 0 });
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}
