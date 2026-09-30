"use strict";

// 運営ポリシーを実装する層。
//  1) securityHeaders    : 自サイトのページに基本ヘッダを付与 / プロキシ経路には noindex を付与
//  2) createHostBlocklist: 通報・遮断依頼を受けたサイトを BLOCKED_HOSTS で遮断(利用規約7条の約束を実装するもの)
//  3) proxyGate          : /proxy/ への入口を「自サイトの枠ページ(/view)のiframe」に限定する(Cookie不要)
//       ブラウザが付ける Sec-Fetch-Site / Sec-Fetch-Dest はページ側のJSでは偽装できない。これを使い、
//         ・同じオリジン(=閲覧中のページ内の遷移・画像等)は通す
//         ・UI_HOSTの枠ページに埋め込まれたiframeの読み込みは通す
//         ・それ以外(メールやSNSのリンクから直接、URL手入力など)はトップページへ戻す
//       → 他人が作った /proxy/https://悪意あるサイト のリンクで、このドメインが踏み台にされるのを防ぐ。
//       /view はトップページのフォーム(同一オリジンの操作)からしか受け付けない。
//
// 【2ホスト構成】(PROXY_HOST / UI_HOST を設定した場合)
//   UI_HOST   : トップ・規約・枠ページ /view(広告はここだけ)
//   PROXY_HOST: /proxy/ のみ。閲覧先のJSはこのオリジンで動くため、広告・UIとオリジンが分かれる
//   → 閲覧先ページが広告を自動クリックしたり、枠ページを書き換えたりできない。
//   独自ドメインは不要: 同じコードを2つのサービス(例: Renderのサービス2つ)としてデプロイし、
//   それぞれの *.onrender.com をUI_HOST/PROXY_HOSTに設定する(両方に同じ値を入れる)。
// 未設定なら1ホスト(ローカル開発)で動く。

const legacyUrl = require("url");


function isHttps(req) {
  return req.secure || String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
}

// 自サイトのページからの操作(ブラウザが付けるSec-Fetch-Siteは、ページ側のJSでは偽装できない)
function isSameOriginNavigation(req) {
  const site = req.headers["sec-fetch-site"];
  if (site) return site === "same-origin";
  try {
    return new URL(req.headers.referer || req.headers.origin || "").host === req.headers.host;
  } catch (e) {
    return false;
  }
}

function refererHost(req) {
  try {
    return new URL(req.headers.referer || "").host.toLowerCase();
  } catch (e) {
    return "";
  }
}

// /proxy/ に入ってよいリクエストか
function isAllowedProxyRequest(req) {
  const ui = (process.env.UI_HOST || "").toLowerCase();
  const own = String(req.headers.host || "").toLowerCase();
  const site = req.headers["sec-fetch-site"];
  const dest = String(req.headers["sec-fetch-dest"] || "");
  if (site) {
    if (site === "same-origin") return true; // 閲覧中のページ内の遷移・サブリソース
    return (dest === "iframe" || dest === "frame") && !!ui && refererHost(req) === ui; // 枠ページからの最初の読み込み(リダイレクト含む)
  }
  // Sec-Fetch-*未対応の古いブラウザ: Refererで判定
  const rh = refererHost(req);
  return !!rh && (rh === own || rh === ui);
}

function securityHeaders(prefix) {
  return function headers(req, res, next) {
    if (req.path.startsWith(prefix) || req.isProxyHost || req.path === "/view") {
      res.set("X-Robots-Tag", "noindex, nofollow");
    }
    if (!req.path.startsWith(prefix) && !req.isProxyHost) {
      res.set({
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=15552000",
      });
    }
    next();
  };
}

// unblocker の requestMiddleware。例: BLOCKED_HOSTS=bad.example,phish.example.net (サブドメインも対象)
function createHostBlocklist() {
  const list = [process.env.BLOCKED_HOSTS, process.env.PROXY_HOST, process.env.UI_HOST]
    .filter(Boolean)
    .join(",")
    .split(",")
    .map((s) => s.trim().toLowerCase().replace(/^\./, ""))
    .filter(Boolean);

  return function hostBlocklist(data) {
    const res = data.clientResponse;
    if (!list.length || !res || res.headersSent) return;
    const host = (legacyUrl.parse(data.url).hostname || "").toLowerCase().replace(/\.$/, "");
    if (list.some((d) => host === d || host.endsWith("." + d))) {
      res.locals.blockedReason = "blocked_by_operator";
      res.status(403).type("text/plain; charset=utf-8").send("このサイトは運営者の判断により表示できません。");
    }
  };
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const uiBase = () => (process.env.UI_HOST ? "https://" + process.env.UI_HOST : "");

// リクエストのホストで役割を分ける(PROXY_HOST未設定なら何もしない)
function hostRouter(prefix) {
  const proxyHost = (process.env.PROXY_HOST || "").toLowerCase();
  return function router(req, res, next) {
    if (!proxyHost || req.path === "/healthz") return next();
    const host = String(req.headers.host || "").toLowerCase().replace(/:\d+$/, "");
    req.isProxyHost = host === proxyHost;
    const proxyOnly = req.path.startsWith(prefix);
    if (req.isProxyHost && !proxyOnly) return res.redirect(302, uiBase() + "/");
    if (!req.isProxyHost && proxyOnly) return res.status(404).type("text/plain").send("not found");
    next();
  };
}

// GET /view?u=URL (UIホスト): トップのフォームからのみ。広告付きの枠ページを返す。閲覧先はiframeで表示
function createViewHandler(prefix, template) {
  return function view(req, res) {
    const u = String(req.query.u || "").trim();
    if (!/^https?:\/\//i.test(u) || u.length > 2000) return res.redirect(302, "/");
    if (!isSameOriginNavigation(req)) return res.redirect(302, "/?u=" + encodeURIComponent(u));
    const base = process.env.PROXY_HOST ? "https://" + process.env.PROXY_HOST : "";
    res.set("Cache-Control", "no-store");
    res.type("html").send(template.replace(/\{\{SRC\}\}/g, esc(base + prefix + u)).replace(/\{\{URL\}\}/g, esc(u)));
  };
}

// 閲覧先の X-Frame-Options を外し、枠ページ(UI_HOST)以外からのiframe埋め込みを禁止する。responseMiddleware用
function createFrameHeaders() {
  return function frameHeaders(data) {
    if (!data.headers) return;
    delete data.headers["x-frame-options"];
    if (process.env.UI_HOST) data.headers["content-security-policy"] = "frame-ancestors https://" + process.env.UI_HOST;
  };
}

// 閲覧先へ送るRefererに、枠ページ(UI_HOST)のアドレスが混ざらないようにする。requestMiddleware用
function stripUiReferer(data) {
  const ui = (process.env.UI_HOST || "").toLowerCase();
  if (!ui || !data.headers || !data.headers.referer) return;
  try {
    if (new URL(data.headers.referer).host.toLowerCase() === ui) delete data.headers.referer;
  } catch (e) {
    /* そのまま */
  }
}

// /proxy/ 以下は、閲覧中のページ内 または 枠ページのiframe からのみ通す
function proxyGate(prefix) {
  return function gate(req, res, next) {
    if (!req.path.startsWith(prefix) || isAllowedProxyRequest(req)) return next();
    const dest = String(req.headers["sec-fetch-dest"] || "");
    const isPage = !dest || dest === "document" || dest === "iframe" || dest === "frame";
    if (isPage) {
      res.locals.blockedReason = "not_via_frame";
      const target = (req.originalUrl || req.url).slice(prefix.length);
      return res.redirect(302, uiBase() + "/?u=" + encodeURIComponent(target.slice(0, 2000)));
    }
    res.status(403).type("text/plain; charset=utf-8").send("このページ経由でのみ利用できます。");
  };
}

module.exports = {
  securityHeaders,
  createHostBlocklist,
  hostRouter,
  createViewHandler,
  createFrameHeaders,
  stripUiReferer,
  proxyGate,
  isAllowedProxyRequest,
};
