"use strict";

// unblocker の responseMiddleware として使う。
// HTML/CSS/JS/画像/フォント/JSON 以外、強制ダウンロード、巨大ファイルを遮断する。

const ALLOWED_TYPES = [
  /^text\/(html|css|javascript|plain|xml)$/,
  /^application\/(xhtml\+xml|javascript|x-javascript|ecmascript|json|xml)$/,
  /^application\/[\w.-]+\+(json|xml)$/, // manifest+json, ld+json, rss+xml など
  /^image\//,
  /^font\//,
  /^application\/(font-woff2?|x-font-[\w-]+|vnd\.ms-fontobject|font-sfnt)$/,
];

// フォントが octet-stream で配信されるCDN向けの例外(拡張子で判定)
const FONT_EXT = /\.(woff2?|ttf|otf|eot)$/i;

function createContentFilter() {
  const maxBytes = Number(process.env.MAX_BYTES || 15 * 1024 * 1024);

  function deny(data, reason, message) {
    const res = data.clientResponse;
    res.locals.blockedReason = reason;
    if (data.remoteResponse) data.remoteResponse.destroy();
    res.status(403).type("text/plain; charset=utf-8").send(message);
  }

  return function contentFilter(data) {
    const res = data.clientResponse;
    if (!res || res.headersSent || !data.remoteResponse) return;

    const status = data.remoteResponse.statusCode;
    if (status < 200 || status === 204 || status === 304 || (status >= 300 && status < 400)) return;

    const h = data.headers || {};

    if (/^\s*attachment/i.test(String(h["content-disposition"] || ""))) {
      return deny(data, "content_disposition_attachment", "ダウンロードは利用できません。");
    }

    const len = Number(h["content-length"]);
    if (Number.isFinite(len) && len > maxBytes) {
      return deny(data, "too_large", "サイズが大きすぎるため取得できません。");
    }

    const type = String(h["content-type"] || "").split(";")[0].trim().toLowerCase();
    const pathname = String(data.url || "").split(/[?#]/)[0];
    const ok =
      ALLOWED_TYPES.some((re) => re.test(type)) ||
      (type === "application/octet-stream" && FONT_EXT.test(pathname));

    if (!ok) {
      return deny(data, "blocked_content_type:" + (type || "none"), "この種類のコンテンツは取得できません。");
    }
  };
}

module.exports = { createContentFilter, ALLOWED_TYPES };
