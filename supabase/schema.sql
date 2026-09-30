-- Supabase の SQL Editor で実行してください。

create table if not exists public.access_logs (
  id            bigint generated always as identity primary key,
  created_at    timestamptz not null default now(),
  ip            text,
  method        text,
  path          text,
  target_url    text,
  referer       text,
  user_agent    text,
  status        int,
  blocked_reason text
);

create index if not exists access_logs_created_at_idx on public.access_logs (created_at desc);
create index if not exists access_logs_ip_idx on public.access_logs (ip, created_at desc);

-- RLSを有効化し、ポリシーは作らない。
-- → anon/authenticatedキーからは一切読み書きできず、service_roleキー(サーバー側のみ)だけがアクセス可能。
alter table public.access_logs enable row level security;

-- 【任意】secret(service_role)キーを使わず anon / publishable キーでログを書き込む場合のみ実行。
-- INSERTだけ許可(SELECT/UPDATE/DELETEは不可)。ただし anon キーは公開前提のキーなので、
-- 第三者がキーを知ればログ表にゴミ行を大量投入できます。可能なら secret キーの利用を推奨します。
-- create policy "anon can insert logs" on public.access_logs
--   for insert to anon
--   with check (
--     length(coalesce(path,'')) <= 2000 and length(coalesce(user_agent,'')) <= 500
--   );

-- ログのローテーション: 30日より古い行を毎日自動削除(無料枠の容量対策)
-- 先に Database > Extensions で pg_cron を有効化してから実行してください。
create extension if not exists pg_cron;

select cron.schedule(
  'purge-access-logs',
  '0 3 * * *', -- 毎日 03:00 UTC (日本時間 12:00)
  $$ delete from public.access_logs where created_at < now() - interval '30 days' $$
);

-- 解除する場合: select cron.unschedule('purge-access-logs');
-- 使用容量の確認: select pg_size_pretty(pg_total_relation_size('public.access_logs'));
