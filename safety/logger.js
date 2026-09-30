"use strict";

// アクセスログ。
//  - 記録対象(HTML本体・遮断イベント。画像/CSS等は除外)をまずローカルの日次ファイル(logs/access-YYYY-MM-DD.jsonl)へ追記(取りこぼし防止)
//  - Supabaseが設定されていれば、バッチでINSERT(失敗時は再試行のためバッファに保持)
//  - 日付が変わった古いファイルは gzip 圧縮、LOCAL_KEEP_DAYS 日を過ぎたら削除

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");

let createClient = null;
try {
  ({ createClient } = require("@supabase/supabase-js"));
} catch (e) {
  /* 未インストールならローカルのみ */
}

function createLogger(opts = {}) {
  const dir = opts.dir || process.env.LOG_DIR || path.join(process.cwd(), "logs");
  const table = opts.table || process.env.SUPABASE_TABLE || "access_logs";
  const keepDays = Number(process.env.LOCAL_KEEP_DAYS || 14);
  const flushMs = Number(process.env.LOG_FLUSH_SEC || 10) * 1000; // 10秒ごと
  const batchMax = Number(process.env.LOG_BATCH_MAX || 100); // または100件たまったら
  const bufferCap = 5000;

  // "https://xxxx.supabase.co/rest/v1/" のようなREST URLが入っていても、ベースURLに直す
  const url = (process.env.SUPABASE_URL || "").replace(/\/rest\/v1\/?$/, "").replace(/\/+$/, "");
  // 推奨: secret / service_role キー。anon(publishable)キーの場合は schema.sql の「INSERT専用ポリシー」が必要
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
  const sb = url && key && createClient ? createClient(url, key, { auth: { persistSession: false } }) : null;
  if (!sb) console.warn("[logger] Supabase未設定: ローカルファイルと標準出力(Renderのログ画面)に記録します");

  fs.mkdirSync(dir, { recursive: true });

  const today = () => new Date().toISOString().slice(0, 10);

  function writeLocal(row) {
    fs.appendFile(path.join(dir, `access-${today()}.jsonl`), JSON.stringify(row) + "\n", (err) => {
      if (err) console.error("[logger] local write failed:", err.message);
    });
  }

  // ---- ローテーション ----
  function rotate() {
    const t = today();
    const cutoff = Date.now() - keepDays * 86400000;
    let files = [];
    try {
      files = fs.readdirSync(dir);
    } catch (e) {
      return;
    }
    for (const f of files) {
      const m = f.match(/^access-(\d{4}-\d{2}-\d{2})\.jsonl(\.gz)?$/);
      if (!m) continue;
      const full = path.join(dir, f);
      const date = m[1];
      try {
        if (Date.parse(date + "T00:00:00Z") < cutoff) {
          fs.unlinkSync(full);
        } else if (!m[2] && date < t) {
          fs.writeFileSync(full + ".gz", zlib.gzipSync(fs.readFileSync(full)));
          fs.unlinkSync(full);
        }
      } catch (e) {
        console.error("[logger] rotate failed:", f, e.message);
      }
    }
  }
  rotate();
  setInterval(rotate, 6 * 3600 * 1000).unref();

  // ---- Supabase ----
  let buf = [];
  let flushing = false;

  async function flush() {
    if (!sb || flushing || !buf.length) return;
    flushing = true;
    const rows = buf.splice(0, buf.length);
    try {
      const { error } = await sb.from(table).insert(rows);
      if (error) throw error;
    } catch (e) {
      console.error("[logger] supabase insert failed:", e.message || e);
      buf.unshift(...rows);
      if (buf.length > bufferCap) buf.splice(0, buf.length - bufferCap);
    } finally {
      flushing = false;
    }
  }
  if (sb) setInterval(flush, flushMs).unref();

  // Supabase未設定のときは標準出力にも1行出す(Renderの Logs 画面で見られる。ローカルファイルは再起動で消えるため)。LOG_STDOUT=0 で無効
  const toStdout = process.env.LOG_STDOUT ? process.env.LOG_STDOUT === "1" : !sb;

  function log(row) {
    row.created_at = new Date().toISOString();
    writeLocal(row);
    if (toStdout) console.log("[access] " + JSON.stringify(row));
    if (sb) {
      buf.push(row);
      if (buf.length >= batchMax) flush();
    }
  }

  // ---- 記録対象の絞り込み ----
  // 画像・CSS・JS・フォント等のサブリソースは記録しない(行数の節約)。記録するのは:
  //   1) HTML(ページ本体)のレスポンス
  //   2) ブラウザがページ遷移として送ったリクエスト(Sec-Fetch-Dest: document/iframe/frame)
  //      → リダイレクトや、遮断された(HTMLではない)ページ要求も残る
  //   3) 遮断・制限が発動したリクエスト(セキュリティ調査用)。ただしレート制限は
  //      ボット大量アクセス時に行が爆発するため、同一IPにつき1分に1行まで
  const logAll = process.env.LOG_ALL === "1";
  const stripQuery = process.env.LOG_STRIP_QUERY === "1"; // 1: URLの「?」以降を記録しない(プライバシー重視)
  const rateLogged = new Map();
  setInterval(() => rateLogged.clear(), 60000).unref();

  function shouldLog(req, res) {
    if (logAll) return true;
    const reason = res.locals.blockedReason;
    if (reason === "rate_limit") {
      if (rateLogged.has(req.clientIp)) return false;
      rateLogged.set(req.clientIp, 1);
      return true;
    }
    if (reason) return true;
    const dest = String(req.headers["sec-fetch-dest"] || "");
    if (dest === "document" || dest === "iframe" || dest === "frame") return true;
    const type = String(res.getHeader("content-type") || "").toLowerCase();
    return type.includes("text/html") || type.includes("application/xhtml+xml");
  }

  // Expressミドルウェア: レスポンス完了時に、対象なら1行記録
  function middleware(prefix) {
    return function accessLog(req, res, next) {
      if (req.path === "/healthz") return next();
      res.on("finish", () => {
        if (!shouldLog(req, res)) return;
        let original = req.originalUrl || req.url;
        if (stripQuery) original = original.split("?")[0];
        log({
          ip: req.clientIp,
          method: req.method,
          path: original.slice(0, 2000),
          target_url: original.startsWith(prefix) ? original.slice(prefix.length).slice(0, 2000) : null,
          referer: String(req.headers.referer || "").slice(0, 2000) || null,
          user_agent: String(req.headers["user-agent"] || "").slice(0, 500) || null,
          status: res.statusCode,
          blocked_reason: res.locals.blockedReason || null,
        });
      });
      next();
    };
  }

  return { log, middleware, flush };
}

module.exports = { createLogger };
