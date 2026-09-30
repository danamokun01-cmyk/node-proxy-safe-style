"use strict";

// unblocker の responseMiddleware として使う。
//  ALLOW_DOWNLOADS=0 : HTML/CSS/JS/画像/フォント/JSON 以外と強制ダウンロードを遮断(厳格モード)
//  既定(許可)        : 実行ファイル系のContent-Type・ファイル名だけ遮断し、それ以外(PDF・圧縮・音声・動画等)は通す
//  どちらのモードでも: 1レスポンスの最大サイズ(MAX_BYTES)を超えた分は打ち切る

const { Transform } = require("stream");
const { ALWAYS_BLOCKED_EXT, ALLOW_DOWNLOADS, extensionOf } = require("./guard.js");

const STRICT_TYPES = [
  /^text\/(html|css|javascript|plain|xml)$/,
  /^application\/(xhtml\+xml|javascript|x-javascript|ecmascript|json|xml)$/,
  /^application\/[\w.-]+\+(json|xml)$/, // manifest+json, ld+json, rss+xml など
  /^image\//,
  /^font\//,
  /^application\/(font-woff2?|x-font-[\w-]+|vnd\.ms-fontobject|font-sfnt)$/,
];

// 常に遮断するContent-Type(実行ファイル・インストーラ・Flash・torrent)
const EXECUTABLE_TYPES = [
  /^application\/(x-msdownload|x-dosexec|vnd\.microsoft\.portable-executable|x-msi|x-sh|x-shellscript|x-bat)$/,
  /^application\/(java-archive|vnd\.android\.package-archive|x-apple-diskimage|x-executable|x-mach-binary|x-elf)$/,
  /^application\/(x-shockwave-flash|x-bittorrent)$/,
];

// フォントが octet-stream で配信されるCDN向けの例外(拡張子で判定)
const FONT_EXT = /\.(woff2?|ttf|otf|eot)$/i;

function attachmentFilename(cd) {
  const m = String(cd).match(/filename\*?=(?:UTF-8'')?"?([^";]+)/i);
  if (!m) return "";
  try {
    return decodeURIComponent(m[1]);
  } catch (e) {
    return m[1];
  }
}

// 上限を超えたら、それ以降を捨てて正常に終了させる(errorイベントは出さない=プロセスを落とさない)
function capBytes(max) {
  let total = 0;
  let done = false;
  return new Transform({
    transform(chunk, enc, cb) {
      if (done) return cb();
      total += chunk.length;
      if (total > max) {
        done = true;
        this.push(null);
        return cb();
      }
      cb(null, chunk);
    },
  });
}

function createContentFilter() {
  const maxBytes = Number(process.env.MAX_BYTES || (ALLOW_DOWNLOADS ? 50 : 15) * 1024 * 1024);

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
    const cd = String(h["content-disposition"] || "");

    if (!ALLOW_DOWNLOADS && /^\s*attachment/i.test(cd)) {
      return deny(data, "content_disposition_attachment", "ダウンロードは利用できません。");
    }
    const fname = attachmentFilename(cd);
    if (fname && ALWAYS_BLOCKED_EXT.has(extensionOf(fname))) {
      return deny(data, "blocked_download_ext", "この種類のファイルはダウンロードできません。");
    }

    const len = Number(h["content-length"]);
    if (Number.isFinite(len) && len > maxBytes) {
      return deny(data, "too_large", "サイズが大きすぎるため取得できません。");
    }

    const type = String(h["content-type"] || "").split(";")[0].trim().toLowerCase();
    const pathname = String(data.url || "").split(/[?#]/)[0];
    let ok;
    if (ALLOW_DOWNLOADS) {
      ok = !EXECUTABLE_TYPES.some((re) => re.test(type));
    } else {
      ok =
        STRICT_TYPES.some((re) => re.test(type)) ||
        (type === "application/octet-stream" && FONT_EXT.test(pathname));
    }
    if (!ok) {
      return deny(data, "blocked_content_type:" + (type || "none"), "この種類のコンテンツは取得できません。");
    }

    if (data.stream) data.stream = data.stream.pipe(capBytes(maxBytes));
  };
}

module.exports = { createContentFilter, STRICT_TYPES };
