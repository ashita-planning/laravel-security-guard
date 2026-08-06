# Laravel Security Guard

[![tests](https://github.com/ashita-planning/laravel-security-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/ashita-planning/laravel-security-guard/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[English](README.md) | [日本語](README.ja.md) | [詳細設定・運用リファレンス](docs/ja/configuration-and-operations.md)

Laravelアプリケーションへ、不正アクセス対策のアプリケーション層を追加するComposerパッケージです。既知攻撃パスの検知、IPの永続遮断、任意で有効化するレート制限、管理IP許可リスト、ワンタイム送信トークン、安全なセキュリティ通知を提供します。

このパッケージは**WAF・CDN・Webサーバーの防御設定・安全なアプリケーション実装の代替ではありません**。多層防御の一層として併用してください。

## 動作要件

- PHP `^8.2`
- Laravel `12.61.1+` または `13.12.0+`
- パッケージ用テーブルを作成できるDB接続
- 複数プロセス・複数台で動かす場合は、共有かつatomic lock対応のcache store

## サポートポリシー

Laravel公式のセキュリティ修正期間内にあるメジャーバージョンだけを正式にサポートします。

| Laravel | PHP | 状態 |
| --- | --- | --- |
| 13.x | 8.3 / 8.4 / 8.5 | 正式対応 |
| 12.x | 8.2 / 8.3 / 8.4 | 正式対応 |
| 11.x | — | 対応対象外 |
| 10.x | — | 対応対象外 |

## インストール

```bash
composer require apkk/laravel-security-guard
php artisan vendor:publish --tag=security-guard-config --no-interaction
php artisan migrate --no-interaction
```

migrationはパッケージから読み込まれます。migrationファイルをアプリケーション側で管理したい場合だけ、公開してください。

```bash
php artisan vendor:publish --tag=security-guard-migrations --no-interaction
```

インストールしただけではリクエスト処理は変わりません。公開リクエスト保護は、middlewareを明示的に登録して初めて有効になります。

## 最初の安全な導入

本番へ適用する前にstagingで確認し、機能は一つずつ有効化してください。

### 1. パッケージ専用のcache名前空間を設定する

`config/security-guard.php` の既定値 `security-guard` を、アプリケーションと環境で一意な値へ変更します。

```php
'cache' => [
    'store' => env('SECURITY_GUARD_CACHE_STORE'),
    'prefix' => 'my-application:production',
],
```

これにより、同じcacheサーバーを共有する別アプリケーションや別環境と、遮断状態・通知上限・ワンタイムトークンが衝突しません。

### 2. クライアントIPを安全に解決する

既定の `laravel_request` driver はLaravelの `Request::ip()` を使います。PHPの手前にreverse proxy、CDN、load balancerがある場合は、公開middlewareを有効にする**前**にLaravelのtrusted proxyを設定してください。信頼するのは実際のproxyのIPまたはCIDRだけです。任意のforwarded headerを信頼してはいけません。

```php
// bootstrap/app.php の withMiddleware(...) 内
$middleware->trustProxies(at: [
    '192.0.2.0/24', // 実際のproxyのIPまたはCIDRに置き換える
]);
```

PHPがクライアントから直接接続を受ける構成では、`REMOTE_ADDR` を使います。

```php
'ip_resolver' => [
    'driver' => 'remote_addr',
],
```

stagingで実リクエストを通し、解決されたIPが期待どおりであることを確認してください。`security-guard:status <ip>` は指定したIPの遮断・レート制限状態を表示するコマンドであり、HTTPリクエストから解決したIPを表示するものではありません。

### 3. 設定診断を実行する

```bash
php artisan security-guard:doctor --strict
```

次へ進む前にwarningも含めて解消してください。`--strict` 指定時はwarningで終了コード `2`、failureで終了コード `1` となるため、CIやデプロイ時の検査にも使えます。

### 4. 公開リクエスト保護を登録する

既知攻撃パスの検知と永続遮断は、未定義ルートへのアクセスも含めて判定する必要があります。`bootstrap/app.php` でglobal middlewareとして登録してください。

```php
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;
use Illuminate\Foundation\Configuration\Middleware;

->withMiddleware(function (Middleware $middleware): void {
    $middleware->prepend(GuardPublicRequests::class);

    // アプリケーション既存のmiddleware設定をここに残す
})
```

本番前に、必要に応じて監視・社内・保守元IPを `permanent_block.ignored_ips` へ登録し、stagingで遮断・解除・再遮断を確認してください。

## 提供機能

| 機能 | 初期状態 | 用途 |
| --- | --- | --- |
| 既知攻撃パス検知・IP永続遮断 | 公開middleware登録後に利用可能 | よくある探索パスや継続的な不正アクセスの遮断 |
| 公開レート制限 | 無効 | 公開リクエストをIP単位で制限 |
| 正規クローラー対応 | 無効 | 検証済みGooglebot/Bingbotに永続遮断しない専用上限を適用 |
| 管理IP許可リスト | 無効 | 認証済み管理主体をIP/CIDRで制限 |
| センシティブルート制限 | 無効 | ログイン・パスワード再設定などをIPと識別子で制限 |
| ワンタイム送信トークン | 無効 | 確認画面を経由するPOSTの重複実行を防止 |
| セキュリティイベント通知 | 無効 | 上限付き・queue経由のセキュリティ通知 |
| 管理UI | 無効 | 認証・認可の背後で遮断IPを確認・解除 |

各機能は有効化方法と除外条件が独立しています。レート制限、許可リスト、通知、クローラー対応は、依存設定と障害時の挙動を確認してから有効にしてください。

## CIDRの安全上の注意

`ignored_ips` と管理IP許可リストは、個別IPアドレスとCIDRネットワークの両方を受け付けます。IPv4ルールは**ファミリを跨ぎません**。つまり、IPv4-mapped IPv6アドレスには一致しません。不正または解析できないルールは、すべてのアドレスではなく**何にも一致しません**。

## よく使うコマンド

```bash
# デプロイ前の設定診断
php artisan security-guard:doctor --strict --json

# 遮断中IPの一覧と解除
php artisan security-guard:blocked:list --active
php artisan security-guard:blocked:release 203.0.113.10 --actor=ops

# 指定IPの保存済み状態を確認
php artisan security-guard:status 203.0.113.10
```

管理IP許可リストや正規クローラー範囲の更新を含む全コマンドは、`php artisan list security-guard` で確認できます。

## 詳細ドキュメント

このREADMEは最初の安全な導入に絞っています。設定リファレンス、モジュール別の運用手順、障害時の方針は、ドキュメントサイトとして整備します。

それまでの既定値の正本は、公開済みの `config/security-guard.php` です。現在の詳細な日本語資料は[詳細設定・運用リファレンス](docs/ja/configuration-and-operations.md)にあります。

## サポートと脆弱性報告

- 再現可能な不具合・機能要望は[GitHub Issues](https://github.com/ashita-planning/laravel-security-guard/issues)へ登録してください。
- Pull Requestの前に[CONTRIBUTING.md](CONTRIBUTING.md)を確認してください。
- 脆弱性を公開Issueへ投稿しないでください。[SECURITY.md](SECURITY.md)の手順に従ってください。
- 更新前に[CHANGELOG.md](CHANGELOG.md)を確認してください。

## 開発

```bash
composer check
```

## ライセンス

Laravel Security Guardは、[MITライセンス](LICENSE)で公開しています。
