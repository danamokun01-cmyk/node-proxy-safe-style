"use strict";

try {
  require("dotenv").config();
} catch (e) {
  /* dotenv未導入でも環境変数から読める */
}

const fs = require("fs");
const path = require("path");
const express = require("express");
const Unblocker = require("./lib/unblocker.js");

const { getClientIp, createRateLimit, methodAndExtension } = require("./safety/guard.js");
const { httpAgent, httpsAgent, createSsrfGuard } = require("./safety/ssrf.js");
const { createContentFilter } = require("./safety/content-filter.js");
const { createLogger } = require("./safety/logger.js");
const {
  securityHeaders,
  createHostBlocklist,
  hostRouter,
  createViewHandler,
  createFrameHeaders,
  stripUiReferer,
  proxyGate,
} = require("./safety/policy.js");

const PREFIX = "/proxy/";
const logger = createLogger();
const app = express();
app.disable("x-powered-by");

const unblocker = Unblocker({
  prefix: PREFIX,
  httpAgent, // DNS解決後の実IPを検査するAgent(内部IP遮断)
  httpsAgent,
  requestMiddleware: [createSsrfGuard(), createHostBlocklist(), stripUiReferer],
  responseMiddleware: [createFrameHeaders(), createContentFilter()],
});

// 1. クライアントIP → アクセスログ → レートリミット(全リクエスト対象)
app.use((req, res, next) => {
  req.clientIp = getClientIp(req);
  next();
});
app.use(logger.middleware(PREFIX));
app.use(
  createRateLimit({
    windowMs: Number(process.env.RATE_LIMIT_WINDOW_SEC || 60) * 1000,
    max: Number(process.env.RATE_LIMIT_MAX || 300), // ページ1枚で数十リクエスト発生するため余裕を持たせる
  })
);

// 2ホスト構成(PROXY_HOST/UI_HOST)。未設定なら1ホストで動く
if (process.env.PROXY_HOST && !process.env.UI_HOST) console.warn("[config] PROXY_HOST を使う場合は UI_HOST も設定してください");
if (!process.env.PROXY_HOST) console.warn("[config] PROXY_HOST未設定: 1ホスト構成(閲覧先と広告が同一オリジン。本番は2ホスト推奨)");
app.use(hostRouter(PREFIX));
app.use(securityHeaders(PREFIX));

app.get("/healthz", (req, res) => res.send("ok"));

// AGPL-3.0 第13条: ネットワーク越しに利用する全ての人へ、改変版のソースコードを提供する
if (!process.env.SOURCE_URL) console.warn("[license] SOURCE_URL未設定: AGPL-3.0のソース提供リンク(/source)が機能しません");
app.get("/source", (req, res) =>
  process.env.SOURCE_URL ? res.redirect(302, process.env.SOURCE_URL) : res.status(404).type("text/plain").send("not configured")
);

// 広告付きの枠ページ(閲覧先はiframeで表示)
const viewTemplate = fs.readFileSync(path.join(__dirname, "views", "view.html"), "utf8");
app.get("/view", createViewHandler(PREFIX, viewTemplate));

// 2. 自サイトの静的ページ(トップ・利用規約・robots.txt)
app.use(express.static(path.join(__dirname, "public"), { index: "index.html" }));

// 3. ここから先はすべてプロキシ経路: GET/HEADのみ、バイナリ拡張子は遮断、枠ページ経由のみ
app.use(methodAndExtension);
app.use(proxyGate(PREFIX));
app.use(unblocker);

// エラー(内部IPブロック・接続失敗など)
app.use((err, req, res, next) => {
  const blocked = err && err.code === "EBLOCKED";
  res.locals.blockedReason = res.locals.blockedReason || (blocked ? "private_ip" : "upstream_error");
  if (res.headersSent) return res.destroy();
  res
    .status(blocked ? 403 : 502)
    .type("text/plain; charset=utf-8")
    .send(blocked ? "このアドレスにはアクセスできません。" : "接続先に接続できませんでした。");
});

// WebSocketは中継しない(onUpgradeを登録しない → upgrade要求は切断される)
const port = process.env.PORT || 8080;
const server = app.listen(port, () => console.log(`listening on :${port}`));

function shutdown() {
  logger.flush().finally(() => server.close(() => process.exit(0)));
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
