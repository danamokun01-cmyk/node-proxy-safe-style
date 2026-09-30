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
// 実行ファイル・インストーラ等は常に遮断(悪意あるファイルの配布元としてドメインが警告対象になるのを防ぐ)。
// 書類・圧縮・画像・音声・動画などは ALLOW_DOWNLOADS=0 のときだけ遮断(既定は許可)。
const ALWAYS_BLOCKED_EXT = new Set(
  (
    "exe msi bat cmd scr ps1 sh jar dll so bin apk ipa dmg pkg deb rpm swf vbs lnk hta appx msix torrent"
  ).split(" ")
);
const DOWNLOAD_EXT = (
  "zip rar 7z tar gz tgz bz2 xz lzh cab iso img " +
  "pdf doc docx xls xlsx ppt pptx odt ods odp rtf epub " +
  "mp4 m4v mkv avi mov wmv flv webm mpg mpeg mp3 wav flac aac ogg m4a"
).split(" ");
const ALLOW_DOWNLOADS = process.env.ALLOW_DOWNLOADS !== "0";
const BLOCKED_EXT = new Set([...ALWAYS_BLOCKED_EXT, ...(ALLOW_DOWNLOADS ? [] : DOWNLOAD_EXT)]);

// 「.com」「.sh」「.so」「.zip」「.mov」はドメイン(TLD)でもあるため、URLの「ホスト部分」は拡張子として見ない。
// 例: /proxy/https://example.com (末尾スラッシュなし) をファイル形式 .com と誤判定して遮断してしまう。
function targetPathname(reqPath, prefix) {
  let rest = reqPath.startsWith(prefix) ? reqPath.slice(prefix.length) : reqPath;
  rest = rest.replace(/^https?:\/\//i, "");
  const i = rest.indexOf("/");
  return i === -1 ? "" : rest.slice(i);
}

function extensionOf(pathname) {
  let p = pathname;
  try {
    p = decodeURIComponent(p);
  } catch (e) {
    /* そのまま使う */
  }
  const m = p.toLowerCase().match(/\.([a-z0-9]+)$/);
  return m ? m[1] : "";
}

function methodAndExtension(req, res, next) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    res.locals.blockedReason = "method_not_allowed";
    res.set("Allow", "GET, HEAD");
    return res.status(405).type("text/plain; charset=utf-8").send("このサービスでは閲覧(GET/HEAD)のみ利用できます。");
  }
  const ext = extensionOf(targetPathname(req.path, "/proxy/"));
  if (ext && BLOCKED_EXT.has(ext)) {
    res.locals.blockedReason = "blocked_extension";
    return res.status(403).type("text/plain; charset=utf-8").send("このファイル形式は取得できません。");
  }
  next();
}

module.exports = {
  getClientIp,
  createRateLimit,
  methodAndExtension,
  BLOCKED_EXT,
  ALWAYS_BLOCKED_EXT,
  ALLOW_DOWNLOADS,
  targetPathname,
  extensionOf,
};
