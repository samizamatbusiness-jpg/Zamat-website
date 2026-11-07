import { DurableObject } from "cloudflare:workers";
// Zamat site worker: the public website stays open, the Zamat app (/app) needs the owner's password.
// Only one-way hashes are stored here; the password itself is not in this file.
const LOGIN_HASH = "d9e2f51dcf184f8a405dfa52d073b92f4ef864429dd855531390d0f2a38e05ad";
const COOKIE_HASH = "50e1f2a621ee50fbab7ada8aeced310377b84a974c45bd9ab96ffe9bdaa74f1e";
const COOKIE = "zamat_key";
// forgiving check: letters that look alike count the same (S/5, B/8, G/6, O/0, I/L/1, Z/2), and the 4 groups may be in any order
const LOGIN2 = "eacaa318d372ec9cc0eb6244f973ad1295c496554f34c5d706dd37580dbdc3a7";
const COOKIE2 = "47846e3c5e876dd610e6dbed7561cfa5b4de2c0d50f0637973524268d5f73613";
const fold = s => s.toUpperCase().replace(/[^A-Z0-9]/g, "").replace(/S/g, "5").replace(/B/g, "8").replace(/G/g, "6").replace(/O/g, "0").replace(/[IL]/g, "1").replace(/Z/g, "2");
function perms(a) { if (a.length < 2) return [a]; const out = []; a.forEach((x, i) => perms(a.filter((_, j) => j !== i)).forEach(r => out.push([x, ...r]))); return out; }
// files the phone needs to add the app to the home screen (no client data in them)
const OPEN = /^\/app\/(manifest\.webmanifest|icon-192\.png|icon-512\.png|apple-touch-icon\.png|favicon\.ico)$/;

async function sha(text) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function getCookie(req, name) {
  const c = req.headers.get("Cookie") || "";
  const m = c.match(new RegExp("(?:^|;\\s*)" + name + "=([a-f0-9]{64})"));
  return m ? m[1] : null;
}
function page(msg) {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#12264B">
<meta name="apple-mobile-web-app-capable" content="yes"><meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Zamat"><link rel="manifest" href="/app/manifest.webmanifest"><link rel="apple-touch-icon" href="/app/apple-touch-icon.png">
<title>Zamat</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#12264B;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:#fff;padding:24px}
.b{width:100%;max-width:340px;text-align:center}img{width:84px;height:84px;border-radius:20px;margin-bottom:18px}
h1{font-size:24px;letter-spacing:3px;margin:0}p{color:#C9D1DB;font-size:14px;margin:6px 0 22px}
input{width:100%;padding:14px;border-radius:12px;border:1px solid #33496F;background:#1A3263;color:#fff;font-size:17px;text-align:center;letter-spacing:2px}
input::placeholder{letter-spacing:0;color:#8A9AB5}button{width:100%;margin-top:12px;padding:14px;border:0;border-radius:12px;background:#D3DAE3;color:#12264B;font-size:16px;font-weight:700}
.e{color:#FF9B9B;font-size:13px;min-height:18px;margin-top:12px}</style></head><body><form class="b" method="POST" action="/app/__login">
<img src="/app/apple-touch-icon.png" alt=""><h1>ZAMAT</h1><p>Private system — enter your password</p>
<input name="username" value="Zamat" autocomplete="username" style="display:none">
<input name="password" type="password" autocomplete="current-password" placeholder="Password" autofocus required>
<button type="submit">Open</button><div class="e">${msg || ""}</div></form></body></html>`;
}
const html = (body, status = 200, extra = {}) =>
  new Response(body, { status, headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow", ...extra } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url), p = url.pathname;
    const isApp = p === "/app" || p.startsWith("/app/");
    if (p === "/__v") return recordVisit(req, env);
    if (!isApp || OPEN.test(p)) return env.ASSETS.fetch(req);

    if (p === "/app/__login") {
      if (req.method !== "POST") return Response.redirect(url.origin + "/app/", 303);
      let raw = "";
      try { raw = String((await req.formData()).get("password") || ""); } catch (e) {}
      const f = fold(raw);
      const tries = f.length === 16 ? perms(f.match(/.{4}/g)).map(g => g.join("")) : [f];
      for (const t of tries) {
        if (t && (await sha(t + "|zamat-login-v2")) === LOGIN2) {
          const key = await sha(t + "|zamat-cookie-v2");
          return new Response(null, { status: 303, headers: { Location: "/app/", "Cache-Control": "no-store",
            "Set-Cookie": `${COOKIE}=${key}; Path=/app; Max-Age=34560000; Secure; HttpOnly; SameSite=Lax` } });
        }
      }
      return html(page("Wrong password. Try again."), 401);
    }

    const key = getCookie(req, COOKIE);
    if (key && [COOKIE_HASH, COOKIE2].includes(await sha(key))) {
      if (p.startsWith("/app/api/")) return env.STORE.get(env.STORE.idFromName("main")).fetch(req);
      if (p === "/app/visits" || p === "/app/visits/") return visitsPage(env, url);
      const res = await env.ASSETS.fetch(req);
      const r = new Response(res.body, res);
      r.headers.set("Cache-Control", "no-store");
      r.headers.set("X-Robots-Tag", "noindex, nofollow");
      return r;
    }
    if (p.startsWith("/app/api/")) return json({ error: "login" }, 401);
    return html(page(""), 401);
  }
};

// ---------- Site visitor counter ----------
// Counts visits to the public website. No names or phone numbers exist here (a website can't see them);
// visitors are told apart only by a one-way scrambled code of their connection + phone model.
const BOT = /bot|crawl|spider|preview|facebookexternalhit|whatsapp\/|telegram|slurp|headless|lighthouse|curl|wget|python/i;
const visitsDO = env => env.STORE.get(env.STORE.idFromName("visits"));
const noContent = () => new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });

async function recordVisit(req, env) {
  if (req.method !== "POST") return noContent();
  const ua = req.headers.get("User-Agent") || "";
  if (BOT.test(ua) || /(?:^|;\s*)zamat_me=1/.test(req.headers.get("Cookie") || "")) return noContent();
  let b = {};
  try { const t = await req.text(); if (t.length < 3000) b = JSON.parse(t); } catch (e) {}
  if (!b || typeof b.id !== "string" || !/^[a-z0-9]{6,40}$/.test(b.id)) return noContent();
  const cf = req.cf || {};
  let src = "Direct";
  const ref = String(b.r || "").toLowerCase();
  if (b.s === "status") src = "WhatsApp Status";
  else if (b.s) src = String(b.s).slice(0, 30);
  else if (/instagram/.test(ref) || /Instagram/.test(ua)) src = "Instagram";
  else if (/facebook|fb\.|FBAN|FBAV/i.test(ref + ua)) src = "Facebook";
  else if (/google\./.test(ref)) src = "Google";
  else if (/whatsapp|wa\.me/.test(ref)) src = "WhatsApp";
  else if (ref && !/zamatinsurance\.com/.test(ref)) { try { src = new URL(ref).hostname.replace(/^www\./, ""); } catch (e) {} }
  const dev = /iPhone/.test(ua) ? "iPhone" : /iPad/.test(ua) ? "iPad" : /Android/.test(ua) ? (/Mobile/.test(ua) ? "Android" : "Android tablet")
    : /Windows/.test(ua) ? "Windows PC" : /Macintosh/.test(ua) ? "Mac" : "Other";
  const ip = req.headers.get("CF-Connecting-IP") || "";
  const vis = (await sha(ip + "|" + ua + "|zamat-visitor")).slice(0, 16);
  const rec = { id: b.id, src, country: cf.country || "", city: cf.city || cf.region || "", dev, vis,
    d: Math.max(0, Math.min(86400, Math.floor(+b.d || 0))), a: b.a === "wa" || b.a === "call" ? b.a : "" };
  await visitsDO(env).fetch("https://do/__visits/hit", { method: "POST", body: JSON.stringify(rec) });
  return noContent();
}

const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SRC_AR = { "WhatsApp Status": "ستوري الواتساب", "WhatsApp": "واتساب", "Instagram": "إنستغرام", "Facebook": "فيسبوك", "Google": "غوغل", "Direct": "مباشر" };
const COUNTRY_AR = { LB: "لبنان", AE: "الإمارات", SA: "السعودية", FR: "فرنسا", DE: "ألمانيا", US: "أميركا", CA: "كندا", AU: "أستراليا", QA: "قطر", KW: "الكويت", GB: "بريطانيا", CI: "ساحل العاج", NG: "نيجيريا", GH: "غانا", SN: "السنغال", BR: "البرازيل", SY: "سوريا", TR: "تركيا", CY: "قبرص" };
const dur = s => !s ? "—" : s < 60 ? s + " ث" : Math.floor(s / 60) + " د " + (s % 60) + " ث";

async function visitsPage(env, url) {
  const data = await (await visitsDO(env).fetch("https://do/__visits/stats")).json();
  const rows = data.rows || [];
  const now = Date.now(), DAY = 86400000;
  const bey = ts => new Date(ts).toLocaleString("en-GB", { timeZone: "Asia/Beirut", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false });
  const dayKey = ts => new Date(ts).toLocaleDateString("en-CA", { timeZone: "Asia/Beirut" });
  const today = dayKey(now);
  const inRange = (r, days) => days === 0 ? dayKey(r.ts) === today : r.ts > now - days * DAY;
  const stat = days => { const rs = rows.filter(r => inRange(r, days)); return { v: rs.length, p: new Set(rs.map(r => r.vis)).size,
    st: rs.filter(r => r.src === "WhatsApp Status").length, act: rs.filter(r => r.act).length }; };
  const T = stat(0), W = stat(7), M = stat(30);
  const firstSeen = {}; rows.slice().sort((a, b) => a.ts - b.ts).forEach(r => { if (!(r.vis in firstSeen)) firstSeen[r.vis] = r.ts; });
  const days = []; for (let i = 13; i >= 0; i--) { const k = dayKey(now - i * DAY); days.push({ k, n: rows.filter(r => dayKey(r.ts) === k).length }); }
  const mx = Math.max(1, ...days.map(d => d.n));
  const bySrc = {}; rows.filter(r => inRange(r, 30)).forEach(r => bySrc[r.src] = (bySrc[r.src] || 0) + 1);
  const card = (t, s) => `<div class="c"><small>${t}</small><b>${s.v}</b><span>زيارة · ${s.p} شخص</span><span>من الستوري: ${s.st}</span><span>كبسوا واتساب/اتصال: ${s.act}</span></div>`;
  const list = rows.slice(0, 150).map(r => `<tr><td dir="ltr">${bey(r.ts)}</td><td>${esc(SRC_AR[r.src] || r.src)}</td><td>${esc(r.city)}${r.city ? "، " : ""}${esc(COUNTRY_AR[r.country] || r.country)}</td><td>${esc(r.dev)}</td><td>${dur(r.dur)}</td><td>${r.act === "wa" ? "✅ واتساب" : r.act === "call" ? "✅ اتصال" : ""}${firstSeen[r.vis] < r.ts - 600000 ? ' <i>رجع</i>' : ""}</td></tr>`).join("");
  const body = `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow"><meta name="theme-color" content="#12264B"><title>زوار السايت · Zamat</title><style>
*{box-sizing:border-box}body{margin:0;background:#0E1E3D;color:#fff;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Tahoma,sans-serif;padding:18px 14px 40px;padding-top:max(18px,env(safe-area-inset-top))}
.top{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}h1{font-size:21px;margin:0}a.bk{color:#C9D1DB;text-decoration:none;font-size:14px;border:1px solid #33496F;padding:7px 12px;border-radius:10px}
.g{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}.c{background:#16305E;border-radius:14px;padding:12px 10px;display:flex;flex-direction:column;gap:3px}
.c small{color:#AFC0DA;font-size:12px}.c b{font-size:28px}.c span{font-size:11.5px;color:#D3DAE3}
.box{background:#16305E;border-radius:14px;padding:14px;margin-top:12px}.box h2{font-size:15px;margin:0 0 10px;color:#D3DAE3}
.bars{display:flex;align-items:flex-end;gap:4px;height:90px}.bars div{flex:1;background:#C9A94E;border-radius:4px 4px 0 0;min-height:2px;position:relative}
.bars div em{position:absolute;top:-16px;left:0;right:0;text-align:center;font-size:10px;font-style:normal;color:#D3DAE3}
.lab{display:flex;gap:4px;margin-top:4px}.lab span{flex:1;text-align:center;font-size:9px;color:#8A9AB5}
.link{display:flex;gap:8px;align-items:center}.link code{flex:1;background:#0E1E3D;padding:10px;border-radius:10px;font-size:15px;direction:ltr;text-align:left}
button{background:#D3DAE3;color:#12264B;border:0;border-radius:10px;padding:10px 14px;font-weight:700;font-size:14px}
.src{display:flex;flex-wrap:wrap;gap:6px}.src span{background:#0E1E3D;border-radius:20px;padding:5px 10px;font-size:13px}
.tw{overflow-x:auto}table{width:100%;border-collapse:collapse;font-size:12.5px;white-space:nowrap}td,th{padding:8px 6px;border-bottom:1px solid #22406F;text-align:right}th{color:#AFC0DA;font-weight:600}
i{font-style:normal;background:#2E5C3A;border-radius:6px;padding:1px 6px;font-size:11px}p.n{color:#8A9AB5;font-size:12px;line-height:1.6}
</style></head><body>
<div class="top"><h1>زوار السايت</h1><a class="bk" href="/app/">رجوع لـ Zamat</a></div>
<div class="box"><h2>الرابط اللي بتحطّو عالستوري</h2><div class="link"><code id="lk">zamatinsurance.com/?wa</code><button onclick="navigator.clipboard.writeText('https://zamatinsurance.com/?wa').then(()=>this.textContent='تم ✓')">نسخ</button></div>
<p class="n">كل زيارة من هالرابط بتنحسب تحت «ستوري الواتساب». زياراتك انت من هالموبايل ما بتنحسب.</p></div>
<div class="g" style="margin-top:12px">${card("اليوم", T)}${card("آخر ٧ أيام", W)}${card("آخر ٣٠ يوم", M)}</div>
<div class="box"><h2>زيارات آخر ١٤ يوم</h2><div class="bars">${days.map(d => `<div style="height:${Math.round(d.n / mx * 100)}%"><em>${d.n || ""}</em></div>`).join("")}</div>
<div class="lab">${days.map(d => `<span>${d.k.slice(8)}</span>`).join("")}</div></div>
<div class="box"><h2>من وين إجوا (آخر ٣٠ يوم)</h2><div class="src">${Object.entries(bySrc).sort((a, b) => b[1] - a[1]).map(([k, v]) => `<span>${esc(SRC_AR[k] || k)}: <b>${v}</b></span>`).join("") || '<span>لسّا ما في زيارات</span>'}</div></div>
<div class="box"><h2>آخر الزيارات</h2><div class="tw"><table><tr><th>الوقت</th><th>من وين</th><th>المنطقة</th><th>الجهاز</th><th>قعد</th><th></th></tr>${list || '<tr><td colspan="6">لسّا ما في زيارات</td></tr>'}</table></div>
<p class="n">«رجع» = نفس الشخص فات أكتر من مرة. المنطقة تقريبية (حسب شبكة الإنترنت). السايت ما بيعرف أسماء أو أرقام الزوار. قارن الوقت مع مين شاف الستوري على الواتساب.</p></div>
</body></html>`;
  return html(body, 200, { "Set-Cookie": "zamat_me=1; Path=/; Max-Age=34560000; Secure; SameSite=Lax" });
}

const json = (o, status = 200) =>
  new Response(JSON.stringify(o), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });

// One private database (SQLite inside a Durable Object) that every device reads and writes.
// Each saved item keeps the time it was changed; the newest change wins.
const PART = 900000;
export class ZamatStore extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sql = ctx.storage.sql;
    this.sql.exec("CREATE TABLE IF NOT EXISTS docs(col TEXT NOT NULL, id TEXT NOT NULL, data TEXT, ts INTEGER NOT NULL, seq INTEGER NOT NULL, PRIMARY KEY(col,id))");
    this.sql.exec("CREATE INDEX IF NOT EXISTS docs_seq ON docs(seq)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS files(id TEXT NOT NULL, part INTEGER NOT NULL, data TEXT NOT NULL, PRIMARY KEY(id,part))");
    this.sql.exec("CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v INTEGER)");
    this.sql.exec("CREATE TABLE IF NOT EXISTS visits(id TEXT PRIMARY KEY, ts INTEGER NOT NULL, src TEXT, country TEXT, city TEXT, dev TEXT, vis TEXT, dur INTEGER DEFAULT 0, act TEXT DEFAULT '')");
    this.sql.exec("CREATE INDEX IF NOT EXISTS visits_ts ON visits(ts)");
  }
  visitHit(r) {
    const ex = this.sql.exec("SELECT id FROM visits WHERE id=?", r.id).toArray();
    if (ex.length) {
      this.sql.exec("UPDATE visits SET dur=MAX(dur,?), act=CASE WHEN ?<>'' THEN ? ELSE act END WHERE id=?", r.d, r.a, r.a, r.id);
    } else {
      this.sql.exec("INSERT INTO visits(id,ts,src,country,city,dev,vis,dur,act) VALUES(?,?,?,?,?,?,?,?,?)",
        r.id, Date.now(), r.src, r.country, r.city, r.dev, r.vis, r.d, r.a);
      if (Math.random() < 0.05) this.sql.exec("DELETE FROM visits WHERE ts<?", Date.now() - 120 * 86400000);
    }
  }
  getSeq() { const r = this.sql.exec("SELECT v FROM meta WHERE k='seq'").toArray(); return r.length ? r[0].v : 0; }
  setSeq(v) { this.sql.exec("INSERT INTO meta(k,v) VALUES('seq',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", v); }
  put(c, i, d, t, s) {
    this.sql.exec("INSERT INTO docs(col,id,data,ts,seq) VALUES(?,?,?,?,?) ON CONFLICT(col,id) DO UPDATE SET data=excluded.data, ts=excluded.ts, seq=excluded.seq",
      c, i, d === null || d === undefined ? null : JSON.stringify(d), t, s);
  }
  since(n) {
    const q = n > 0 ? this.sql.exec("SELECT col,id,data FROM docs WHERE seq>? ORDER BY seq", n)
                    : this.sql.exec("SELECT col,id,data FROM docs WHERE data IS NOT NULL ORDER BY seq");
    return q.toArray().map(r => ({ c: r.col, i: r.id, d: r.data === null ? null : JSON.parse(r.data) }));
  }
  ok(ch) { return ch && typeof ch.c === "string" && typeof ch.i === "string" && ch.c && ch.i && ch.c.length < 100 && ch.i.length < 200; }

  async fetch(req) {
    const url = new URL(req.url), p = url.pathname.replace(/^\/app\/api\//, "");
    try {
      if (url.pathname === "/__visits/hit") { this.visitHit(await req.json()); return json({ ok: true }); }
      if (url.pathname === "/__visits/stats") {
        const rows = this.sql.exec("SELECT ts,src,country,city,dev,vis,dur,act FROM visits WHERE ts>? ORDER BY ts DESC LIMIT 5000", Date.now() - 31 * 86400000).toArray();
        return json({ rows });
      }
      if (p === "status") {
        const n = this.sql.exec("SELECT COUNT(*) AS n FROM docs WHERE data IS NOT NULL").one().n;
        return json({ count: n, seq: this.getSeq() });
      }
      if (p === "sync" && req.method === "POST") {
        const body = await req.json();
        const since = Math.max(0, +body.since || 0);
        const changes = Array.isArray(body.changes) ? body.changes : [];
        const out = this.ctx.storage.transactionSync(() => {
          let s = this.getSeq();
          for (const ch of changes) {
            if (!this.ok(ch)) continue;
            const t = Math.floor(+ch.t || Date.now());
            const ex = this.sql.exec("SELECT ts FROM docs WHERE col=? AND id=?", ch.c, ch.i).toArray();
            s++;
            if (ex.length && ex[0].ts > t) {
              // the cloud has a newer version: send it back so the device corrects itself
              this.sql.exec("UPDATE docs SET seq=? WHERE col=? AND id=?", s, ch.c, ch.i);
            } else this.put(ch.c, ch.i, ch.d, t, s);
          }
          this.setSeq(s);
          return { seq: s, changes: this.since(since) };
        });
        return json(out);
      }
      if (p === "replace" && req.method === "POST") {
        const body = await req.json();
        const changes = Array.isArray(body.changes) ? body.changes : [];
        const s = this.ctx.storage.transactionSync(() => {
          const s = this.getSeq() + 1, now = Date.now();
          this.sql.exec("UPDATE docs SET data=NULL, ts=?, seq=? WHERE data IS NOT NULL", now, s);
          for (const ch of changes) if (this.ok(ch) && ch.d != null) this.put(ch.c, ch.i, ch.d, Math.max(now, Math.floor(+ch.t || 0)), s);
          this.setSeq(s);
          return s;
        });
        return json({ seq: s });
      }
      if (p === "files") {
        return json({ ids: this.sql.exec("SELECT DISTINCT id FROM files").toArray().map(r => r.id) });
      }
      if (p === "file") {
        const id = url.searchParams.get("id") || "";
        if (!id || id.length > 200) return json({ error: "id" }, 400);
        if (req.method === "PUT") {
          const text = await req.text();
          if (!text.startsWith("data:") || text.length > 30000000) return json({ error: "file" }, 400);
          this.ctx.storage.transactionSync(() => {
            this.sql.exec("DELETE FROM files WHERE id=?", id);
            for (let k = 0, part = 0; k < text.length; k += PART, part++) this.sql.exec("INSERT INTO files(id,part,data) VALUES(?,?,?)", id, part, text.slice(k, k + PART));
          });
          return json({ ok: true });
        }
        const rows = this.sql.exec("SELECT data FROM files WHERE id=? ORDER BY part", id).toArray();
        if (!rows.length) return new Response("not found", { status: 404, headers: { "Cache-Control": "no-store" } });
        return new Response(rows.map(r => r.data).join(""), { headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" } });
      }
      return json({ error: "not found" }, 404);
    } catch (e) {
      return json({ error: String(e && e.message || e) }, 500);
    }
  }
}
