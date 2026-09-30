"use strict";

// 30日で自動削除される前に、Supabaseのログを日別の CSV.gz に退避する。
//   node scripts/archive-logs.js
// - 直近 ARCHIVE_DAYS 日(既定28日)のうち、前日までの各日を対象に、まだ退避していない日だけ出力(何度実行しても安全)
// - 出力先: ARCHIVE_DIR (既定 ./log-archive)/access-YYYY-MM-DD.csv.gz  (日付はUTC基準)
// - SUPABASE_ARCHIVE_BUCKET を設定すると、同じファイルを Supabase Storage(非公開バケット)にもアップロード
// - このスクリプトは削除しない。削除は schema.sql の pg_cron が行う。毎日実行すること(cronの例は SAFETY.md)。

try {
  require("dotenv").config();
} catch (e) {
  /* dotenv未導入でも環境変数から読める */
}

const fs = require("fs");
const path = require("path");
const zlib = require("zlib");
const { createClient } = require("@supabase/supabase-js");

const url = (process.env.SUPABASE_URL || "").replace(/\/rest\/v1\/?$/, "").replace(/\/+$/, "");
const key = process.env.SUPABASE_SERVICE_ROLE_KEY; // 読み取りが必要なため、anon/publishableキーでは動きません
if (!url || !key) {
  console.error("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY(secretキー)が未設定です");
  process.exit(1);
}
const sb = createClient(url, key, { auth: { persistSession: false } });

const table = process.env.SUPABASE_TABLE || "access_logs";
const dir = process.env.ARCHIVE_DIR || path.join(process.cwd(), "log-archive");
const bucket = process.env.SUPABASE_ARCHIVE_BUCKET || "";
const days = Number(process.env.ARCHIVE_DAYS || 28);
const PAGE = 1000;

const COLS = ["id", "created_at", "ip", "method", "path", "target_url", "referer", "user_agent", "status", "blocked_reason"];

function csvCell(v) {
  if (v === null || v === undefined) return "";
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // Excelで開いたときの数式実行を防ぐ
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}

async function exportDay(dayStart) {
  const dayEnd = new Date(dayStart.getTime() + 86400000);
  const name = `access-${dayStart.toISOString().slice(0, 10)}.csv.gz`;
  const file = path.join(dir, name);
  if (fs.existsSync(file)) return "skip";

  const lines = ["\uFEFF" + COLS.join(",")];
  let lastId = 0;
  for (;;) {
    const { data, error } = await sb
      .from(table)
      .select(COLS.join(","))
      .gte("created_at", dayStart.toISOString())
      .lt("created_at", dayEnd.toISOString())
      .gt("id", lastId)
      .order("id", { ascending: true })
      .limit(PAGE);
    if (error) throw error;
    if (!data.length) break;
    for (const r of data) lines.push(COLS.map((c) => csvCell(r[c])).join(","));
    lastId = data[data.length - 1].id;
    if (data.length < PAGE) break;
  }

  const rows = lines.length - 1;
  if (rows === 0) return "empty"; // 0件の日はファイルを作らない(後でログが追いついた場合に再取得できる)

  const gz = zlib.gzipSync(Buffer.from(lines.join("\n") + "\n", "utf8"));
  fs.mkdirSync(dir, { recursive: true });
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, gz);

  if (bucket) {
    const { error } = await sb.storage.from(bucket).upload(name, gz, { contentType: "application/gzip", upsert: true });
    if (error) {
      fs.unlinkSync(tmp);
      throw error;
    }
  }
  fs.renameSync(tmp, file); // アップロード成功後に確定 → 失敗時は次回やり直し
  return rows + "行";
}

(async () => {
  const now = new Date();
  const todayUtc = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  let failed = false;
  for (let i = days; i >= 1; i--) {
    const day = new Date(todayUtc.getTime() - i * 86400000);
    try {
      const r = await exportDay(day);
      if (r !== "skip") console.log(day.toISOString().slice(0, 10), r);
    } catch (e) {
      failed = true;
      console.error(day.toISOString().slice(0, 10), "失敗:", e.message || e);
    }
  }
  process.exit(failed ? 1 : 0);
})();
