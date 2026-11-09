// /api/mqis/* – máy chủ dữ liệu dùng chung cho MQIS (Cloudflare D1, binding: DB)
// Đúng giao thức "máy chủ" có sẵn trong trang MQIS:
//   GET  /api/mqis/rev            → { server:"mqis", revs:{ "2026-9":3, … }, years:[2026], empty }
//   GET  /api/mqis/month?key=K    → [ …bản ghi của tháng K… ]
//   POST /api/mqis/op  { ops:[…] }→ { ok, revs }        (cần quyền sửa)
//        op: init|reset {state:{years,data}} · month {key,recs} · years {years}
//            set {key,rec} · del {key,id} · patch {key,id,f}
//   GET  /api/mqis/img/<id>       → ảnh (ảnh dán vào được tách khỏi dữ liệu để mỗi tháng luôn nhỏ hơn giới hạn 2MB của D1)
// Quyền: dùng chung mật khẩu với báo cáo nhân lực (HC_PASSWORD / HC_VIEW_PASSWORD). Xem công khai, ghi cần quyền sửa.

const IMG_PREFIX = "/api/mqis/img/";
const IMG_FIELDS = ["qpnImg", "img"];

const CORS = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "content-type, x-hc-token", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Max-Age": "86400" };
const json = (data, status = 200) => new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS } });
export const onRequestOptions = () => new Response(null, { status: 204, headers: CORS });

/* ---- auth (giống /api/hc/*) ---- */
async function sha(s) {
  const b = await crypto.subtle.digest("SHA-256", typeof s === "string" ? new TextEncoder().encode(s) : s);
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
    db.prepare("CREATE TABLE IF NOT EXISTS mqis_month (key TEXT PRIMARY KEY, recs TEXT NOT NULL, rev INTEGER NOT NULL)"),
    db.prepare("CREATE TABLE IF NOT EXISTS mqis_meta (k TEXT PRIMARY KEY, v TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS mqis_img (id TEXT PRIMARY KEY, mime TEXT NOT NULL, data BLOB NOT NULL)")
  ]);
  schemaReady = true;
}
const validKey = k => typeof k === "string" && /^\d{4}-\d{1,2}$/.test(k);

async function readState(db) {
  const [months, meta] = await db.batch([
    db.prepare("SELECT key, rev FROM mqis_month"),
    db.prepare("SELECT v FROM mqis_meta WHERE k='years'")
  ]);
  const revs = {};
  months.results.forEach(r => { revs[r.key] = r.rev; });
  let years = [];
  try { years = JSON.parse((meta.results[0] && meta.results[0].v) || "[]"); } catch (e) { }
  return { revs, years, empty: !months.results.length && !meta.results.length };
}

/* ---- ảnh: data:image/... → bảng mqis_img, thay bằng đường dẫn /api/mqis/img/<id> ---- */
function b64ToBytes(b64) {
  const bin = atob(b64), out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function extractImages(recs, pending) {
  for (const r of recs || []) {
    if (!r || typeof r !== "object") continue;
    for (const f of IMG_FIELDS) {
      if (!Array.isArray(r[f])) continue;
      for (let i = 0; i < r[f].length; i++) {
        const s = r[f][i];
        const m = typeof s === "string" && /^data:(image\/[a-z0-9.+-]+);base64,(.+)$/i.exec(s);
        if (!m) continue;
        const bytes = b64ToBytes(m[2]);
        if (bytes.length > 1900000) continue;               // quá lớn → giữ nguyên (hiếm, ảnh đã được thu nhỏ ở trình duyệt)
        const id = (await sha(bytes)).slice(0, 32) + "." + (m[1].split("/")[1].replace("jpeg", "jpg").replace(/[^a-z0-9]/gi, "") || "img");
        pending.set(id, { mime: m[1].toLowerCase(), bytes });
        r[f][i] = IMG_PREFIX + id;
      }
    }
  }
}
function imageStatements(db, pending) {
  const out = [], list = [...pending.entries()];
  for (let i = 0; i < list.length; i += 30) {                // ≤ 90 tham số / câu lệnh
    const part = list.slice(i, i + 30);
    const sql = "INSERT OR IGNORE INTO mqis_img (id, mime, data) VALUES " + part.map(() => "(?, ?, ?)").join(", ");
    out.push(db.prepare(sql).bind(...part.flatMap(([id, v]) => [id, v.mime, v.bytes])));
  }
  return out;
}
const reno = recs => recs.forEach((r, i) => { if (r && typeof r === "object") r.no = i + 1; });

export async function onRequestGet({ request, env, params }) {
  const path = (params.path || []).join("/");
  try {
    await ensure(env.DB);
    if (path === "rev") {
      const st = await readState(env.DB);
      return json({ server: "mqis", revs: st.revs, years: st.years.length ? st.years : (st.empty ? [] : [2026]), empty: st.empty });
    }
    if (path === "month") {
      const key = new URL(request.url).searchParams.get("key");
      const r = await env.DB.prepare("SELECT recs FROM mqis_month WHERE key=?").bind(key).first();
      return new Response(r ? r.recs : "[]", { headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...CORS } });
    }
    if (path.startsWith("img/")) {
      const r = await env.DB.prepare("SELECT mime, data FROM mqis_img WHERE id=?").bind(path.slice(4)).first();
      if (!r) return new Response("Not found", { status: 404, headers: CORS });
      return new Response(new Uint8Array(r.data), { headers: { "Content-Type": r.mime, "Cache-Control": "public, max-age=31536000, immutable", ...CORS } });
    }
    return json({ error: "Not found" }, 404);
  } catch (e) {
    return json({ error: e.message }, 500);
  }
}

export async function onRequestPost({ request, env, params }) {
  const path = (params.path || []).join("/");
  if (path !== "op") return json({ error: "Not found" }, 404);
  const role = await roleOf(request, env);
  if (!role) return json({ ok: false, error: "login" }, 401);
  if (role !== "edit") return json({ ok: false, error: "Chế độ chỉ xem – không được sửa" }, 403);
  try {
    const body = await request.json().catch(() => null);
    const ops = body && Array.isArray(body.ops) ? body.ops : null;
    if (!ops || !ops.length || ops.length > 500) return json({ ok: false, error: "Invalid ops" }, 400);
    await ensure(env.DB);
    const db = env.DB, imgs = new Map();

    // 1) Thay toàn bộ (init / reset) – lấy op cuối cùng nếu có nhiều
    let i0 = 0;
    for (let i = ops.length - 1; i >= 0; i--) if (ops[i] && (ops[i].t === "init" || ops[i].t === "reset")) { i0 = i; break; }
    const full = ops[i0] && (ops[i0].t === "init" || ops[i0].t === "reset") ? ops[i0] : null;
    if (full) {
      const st = full.state || {}, data = st.data && typeof st.data === "object" ? st.data : {};
      const old = await readState(db);
      if (full.t === "init" && !old.empty) { /* đã có dữ liệu – bỏ qua init (máy khác đã khởi tạo trước) */ }
      else {
        const stmts = [db.prepare("DELETE FROM mqis_month")];
        for (const [k, recs] of Object.entries(data)) {
          if (!validKey(k) || !Array.isArray(recs)) continue;
          await extractImages(recs, imgs);
          stmts.push(db.prepare("INSERT INTO mqis_month (key, recs, rev) VALUES (?, ?, ?)").bind(k, JSON.stringify(recs), (old.revs[k] || 0) + 1));
        }
        const ys = Array.isArray(st.years) ? st.years.filter(y => Number.isInteger(y)) : [];
        stmts.push(db.prepare("INSERT INTO mqis_meta (k, v) VALUES ('years', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(ys.length ? ys : [2026])));
        await db.batch([...imageStatements(db, imgs), ...stmts]);
        imgs.clear();
      }
    }

    // 2) Các op còn lại, gom theo tháng; ghi có kiểm tra rev (tránh ghi đè khi 2 người sửa cùng lúc)
    const byKey = new Map();
    let years = null;
    for (let i = full ? i0 + 1 : 0; i < ops.length; i++) {
      const o = ops[i];
      if (!o || typeof o !== "object") continue;
      if (o.t === "years") { if (Array.isArray(o.years)) years = o.years.filter(y => Number.isInteger(y)).sort(); continue; }
      if (!["month", "set", "del", "patch"].includes(o.t)) continue;
      if (!validKey(o.key)) return json({ ok: false, error: "Invalid key" }, 400);
      if (!byKey.has(o.key)) byKey.set(o.key, []);
      byKey.get(o.key).push(o);
    }
    if (years) await db.prepare("INSERT INTO mqis_meta (k, v) VALUES ('years', ?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(JSON.stringify(years)).run();

    for (const [key, list] of byKey) {
      for (let attempt = 0; ; attempt++) {
        const row = await db.prepare("SELECT recs, rev FROM mqis_month WHERE key=?").bind(key).first();
        let recs = row ? JSON.parse(row.recs) : [];
        for (const o of list) {
          if (o.t === "month") { recs = Array.isArray(o.recs) ? JSON.parse(JSON.stringify(o.recs)) : []; await extractImages(recs, imgs); }
          else if (o.t === "set" && o.rec && typeof o.rec === "object") {
            const rec = JSON.parse(JSON.stringify(o.rec)); await extractImages([rec], imgs);
            const ix = rec.id ? recs.findIndex(r => r && r.id === rec.id) : -1;
            if (ix >= 0) recs[ix] = rec; else recs.push(rec);
            reno(recs);
          } else if (o.t === "del") { recs = recs.filter(r => !(r && r.id === o.id)); reno(recs); }
          else if (o.t === "patch" && o.f && typeof o.f === "object") {
            const r = recs.find(x => x && x.id === o.id);
            if (r) { const f = JSON.parse(JSON.stringify(o.f)); await extractImages([f], imgs); Object.assign(r, f); }
          }
        }
        const txt = JSON.stringify(recs);
        if (new TextEncoder().encode(txt).length > 1900000) return json({ ok: false, error: "Dữ liệu tháng " + key + " quá lớn" }, 413);
        const write = row
          ? db.prepare("UPDATE mqis_month SET recs=?, rev=? WHERE key=? AND rev=?").bind(txt, row.rev + list.length, key, row.rev)
          : db.prepare("INSERT OR IGNORE INTO mqis_month (key, recs, rev) VALUES (?, ?, ?)").bind(key, txt, list.length);
        const res = await db.batch([...imageStatements(db, imgs), write]);
        imgs.clear();
        if (res[res.length - 1].meta.changes) break;
        if (attempt >= 4) return json({ ok: false, error: "Xung đột ghi, thử lại" }, 409);
      }
    }
    const st = await readState(db);
    return json({ ok: true, revs: st.revs, years: st.years });
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}
