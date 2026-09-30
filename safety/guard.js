"use strict";

// クライアントIP取得。
//  - Cloudflare配下: BEHIND_CLOUDFLARE=1 で CF-Connecting-IP を採用
//    (オリジンのファイアウォールをCloudflareのIPレンジのみ許可にしないと、ヘッダを偽装される)
//  - Render等のリバースプロキシ配下: TRUSTED_PROXY_HOPS=1 で X-Forwarded-For の「右から1番目」を採用
//    (左側はクライアントが偽装できるため、信頼できる段数だけ右から数える)
//  - どちらでもなければ接続元アドレスそのもの
function stripV6(ip) {
  return String(ip || "").replace(/^::ffff:/, "");
}

function getClientIp(req) {
  if (process.env.BEHIND_CLOUDFLARE === "1" && req.headers["cf-connecting-ip"]) {
    return stripV6(req.headers["cf-connecting-ip"]);
  }
  const hops = Number(process.env.TRUSTED_PROXY_HOPS || 0);
  if (hops > 0) {
    const xff = String(req.headers["x-forwarded-for"] || "")
      .split(",")
      .map((x) => x.trim())
      .filter(Boolean);
    if (xff.length) return stripV6(xff[Math.max(0, xff.length - hops)]);
  }
  return stripV6(req.socket.remoteAddress);
}

// ---- レートリミット(固定ウィンドウ、メモリ内) ----
function createRateLimit({ windowMs, max }) {
  const hits = new Map();
  setInterval(() => {
    const now = Date.now();
    for (const [k, v] of hits) if (v.resetAt <= now) hits.delete(k);
  }, windowMs).unref();

  return function rateLimit(req, res, next) {
    const ip = req.clientIp;
    const now = Date.now();
    let e = hits.get(ip);
    if (!e || e.resetAt <= now) {
      if (hits.size > 200000) hits.clear(); // メモリ保護
      e = { count: 0, resetAt: now + windowMs };
      hits.set(ip, e);
    }
    e.count++;
    if (e.count > max) {
      res.locals.blockedReason = "rate_limit";
      res.set("Retry-After", String(Math.ceil((e.resetAt - now) / 1000)));
      return res.status(429).type("text/plain; charset=utf-8").send("アクセスが多すぎます。しばらく待ってからお試しください。");
    }
    next();
  };
}

// ---- メソッド制限 + 拡張子によるダウンロード遮断 ----
const BLOCKED_EXT = new Set(
  (
    "zip rar 7z tar gz tgz bz2 xz lzh cab iso img dmg pkg deb rpm apk ipa " +
    "exe msi bat cmd com scr ps1 sh jar dll so bin " +
    "pdf doc docx xls xlsx ppt pptx odt ods odp rtf epub " +
    "mp4 m4v mkv avi mov wmv flv webm mpg mpeg mp3 wav flac aac ogg m4a " +
    "torrent swf"
  ).split(" ")
);

function methodAndExtension(req, res, next) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.locals.blockedReason = "method_not_allowed";
    res.set("Allow", "GET, HEAD");
    return res.status(405).type("text/plain; charset=utf-8").send("このサービスでは閲覧(GET/HEAD)のみ利用できます。");
  }
  let p = req.path;
  try {
    p = decodeURIComponent(p);
  } catch (e) {
    /* そのまま使う */
  }
  const m = p.toLowerCase().match(/\.([a-z0-9]+)$/);
  if (m && BLOCKED_EXT.has(m[1])) {
    res.locals.blockedReason = "blocked_extension";
    return res.status(403).type("text/plain; charset=utf-8").send("このファイル形式は取得できません。");
  }
  next();
}

module.exports = { getClientIp, createRateLimit, methodAndExtension, BLOCKED_EXT };
