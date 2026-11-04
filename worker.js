import { DurableObject } from "cloudflare:workers";
// Zamat site worker: the public website stays open, the Zamat app (/app) needs the owner's password.
// Only one-way hashes are stored here; the password itself is not in this file.
const LOGIN_HASH = "d9e2f51dcf184f8a405dfa52d073b92f4ef864429dd855531390d0f2a38e05ad";
const COOKIE_HASH = "50e1f2a621ee50fbab7ada8aeced310377b84a974c45bd9ab96ffe9bdaa74f1e";
const COOKIE = "zamat_key";
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
    if (!isApp || OPEN.test(p)) return env.ASSETS.fetch(req);

    if (p === "/app/__login") {
      if (req.method !== "POST") return Response.redirect(url.origin + "/app/", 303);
      let pw = "";
      try { pw = String((await req.formData()).get("password") || "").toUpperCase().replace(/[^A-Z0-9]/g, ""); } catch (e) {}
      // accept it typed with spaces, without dashes or in small letters
      if (pw.length === 16) pw = pw.match(/.{4}/g).join("-");
      if (pw && (await sha(pw + "|zamat-login-v1")) === LOGIN_HASH) {
        const key = await sha(pw + "|zamat-cookie-v1");
        return new Response(null, { status: 303, headers: { Location: "/app/", "Cache-Control": "no-store",
          "Set-Cookie": `${COOKIE}=${key}; Path=/app; Max-Age=34560000; Secure; HttpOnly; SameSite=Lax` } });
      }
      return html(page("Wrong password. Try again."), 401);
    }

    const key = getCookie(req, COOKIE);
    if (key && (await sha(key)) === COOKIE_HASH) {
      if (p.startsWith("/app/api/")) return env.STORE.get(env.STORE.idFromName("main")).fetch(req);
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
