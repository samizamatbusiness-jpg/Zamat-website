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
      try { pw = String((await req.formData()).get("password") || "").trim().toUpperCase(); } catch (e) {}
      if (pw && (await sha(pw + "|zamat-login-v1")) === LOGIN_HASH) {
        const key = await sha(pw + "|zamat-cookie-v1");
        return new Response(null, { status: 303, headers: { Location: "/app/", "Cache-Control": "no-store",
          "Set-Cookie": `${COOKIE}=${key}; Path=/app; Max-Age=34560000; Secure; HttpOnly; SameSite=Lax` } });
      }
      return html(page("Wrong password. Try again."), 401);
    }

    const key = getCookie(req, COOKIE);
    if (key && (await sha(key)) === COOKIE_HASH) {
      const res = await env.ASSETS.fetch(req);
      const r = new Response(res.body, res);
      r.headers.set("Cache-Control", "no-store");
      r.headers.set("X-Robots-Tag", "noindex, nofollow");
      return r;
    }
    return html(page(""), 401);
  }
};
