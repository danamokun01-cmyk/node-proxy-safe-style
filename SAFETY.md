# 安全対策の構成

| 対策 | 場所 |
|---|---|
| アクセスログ(Supabase + ローカル日次JSONL、gzip、自動削除) | safety/logger.js, supabase/schema.sql |
| GET/HEADのみ許可、バイナリ拡張子の遮断 | safety/guard.js (methodAndExtension) |
| Content-Type許可リスト / attachment遮断 / サイズ上限 | safety/content-filter.js |
| IP単位レートリミット | safety/guard.js (createRateLimit) |
| 内部IP・localhost・メタデータIP遮断(DNS解決後も検査) | safety/ssrf.js |
| WebSocket中継なし | server.js (onUpgrade未登録) |
| 利用規約・免責の掲示 | public/index.html, public/terms.html |
| /proxy/ への入口を枠ページ(/view)のiframe経由に限定(外部リンクからの直行を防止)。閲覧先と広告を別オリジンに分離 | safety/policy.js (proxyGate, hostRouter), views/view.html |
| 通報・遮断依頼サイトのブロック(BLOCKED_HOSTS) | safety/policy.js (createHostBlocklist) |
| セキュリティヘッダ / プロキシ経路のnoindex / robots.txt | safety/policy.js, public/robots.txt |
| AGPL-3.0のソース提供リンク(/source → SOURCE_URL) | server.js |

## セットアップ
1. `npm install`
2. Supabase の SQL Editor で `supabase/schema.sql` を実行
3. `.env.example` を `.env` にコピーして SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY を設定
4. `npm start`

## Cloudflare
- `.env` に `BEHIND_CLOUDFLARE=1`
- オリジンのファイアウォールはCloudflareのIPレンジからの80/443のみ許可(直接アクセスされるとCF-Connecting-IPを偽装できてしまう)

## ログの退避(30日で消える前に)
`npm run archive-logs` で、前日までの各日を `log-archive/access-YYYY-MM-DD.csv.gz` に出力します(出力済みの日はスキップ)。
- 毎日実行してください(削除の30日より短い間隔なら取りこぼしません)。cron例: `10 3 * * * cd /path/to/app && npm run archive-logs >> archive.log 2>&1`
- `.env` の `SUPABASE_ARCHIVE_BUCKET` に非公開バケット名を入れると、Supabase Storageにも保存されます(要: バケットを Private で作成)。
- 退避ファイルにもIPアドレス等が含まれます。保管場所のアクセス権限を絞り、保管期間(例: 1年)を決めて、期限が来たら削除してください。

## Renderへのデプロイ(独自ドメイン不要の2サービス構成)
同じリポジトリから `wv-ui` と `wv-proxy` の2つのWeb Serviceを作る(render.yamlのBlueprintで両方作られる)。
トップ・広告付き枠ページは wv-ui、閲覧先の中継は wv-proxy が担当する。閲覧先のJSと広告が別オリジンになる。

1. **GitHubの公開リポジトリ**にこのフォルダをpush(AGPL-3.0のため、改変版のソースを利用者に提供する必要がある。非公開だと満たせない。`.env` は `.gitignore` 済みなので入らないが、pushの前に `git status` で確認)→ Render で New > Web Service(または `render.yaml` の Blueprint)
2. Build: `npm install` / Start: `npm start`
3. Environment に次を設定(キーはコードやGitに入れない)
   - `SUPABASE_URL` = `https://YOUR-PROJECT-REF.supabase.co`(`/rest/v1/` は付けない)
   - `SUPABASE_SERVICE_ROLE_KEY` = Supabase の Project Settings > API Keys の secret キー(`sb_secret_...`)
   - `TRUSTED_PROXY_HOPS` = `1`
   - `SOURCE_URL` = 公開したGitHubリポジトリのURL
   - `BLOCKED_HOSTS` = 遮断するドメイン(最初は空でよい)
   - `UI_HOST` / `PROXY_HOST` = 下記の2サービスのホスト名(**両方のサービスに同じ値**。`https://` は付けない)
4. デプロイ後、自分のスマホ(モバイル回線)でトップページ→適当なサイトを開き、Supabase の `access_logs` に**自分の実IP**が入っているか確認。
   Render / Cloudflare の段数が想定と違うと、全員が同じIPに見えてレートリミットが全員に効いてしまうため、必ず確認すること。
5. Renderの無料プランは一定時間アクセスがないと停止し、ディスクも再起動で消える。ローカルログは一時的なもので、正本はSupabase。
