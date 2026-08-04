# Laravel Security Guard

不正アクセス対策をLaravelアプリケーションへ追加するComposerパッケージです。既知攻撃パスの検知、IPの永続遮断、公開レート制限、管理領域のIP許可リスト、ワンタイム送信トークン、無害化された通知を提供します。

[![tests](https://github.com/ashita-planning/laravel-security-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/ashita-planning/laravel-security-guard/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

- Composer package: `apkk/laravel-security-guard`
- PHP namespace: `Apkk\LaravelSecurityGuard`
- 対応: PHP `^8.2` / Laravel `12` `13`
- 変更履歴: [CHANGELOG.md](CHANGELOG.md) ／ 脆弱性報告: [SECURITY.md](SECURITY.md) ／ 開発: [CONTRIBUTING.md](CONTRIBUTING.md)

このパッケージは**WAF・CDN・Webサーバー設定の代替ではありません**。アプリケーション層の1レイヤーとして併用してください。

## インストール

```bash
composer require apkk/laravel-security-guard
```

```bash
php artisan vendor:publish --tag=security-guard-config --no-interaction
```

```bash
php artisan vendor:publish --tag=security-guard-migrations --no-interaction
```

```bash
php artisan migrate --no-interaction
```

migrationはパッケージから自動読み込みされるため、テーブル定義を自分で管理したい場合のみpublishしてください。config、migration、viewはそれぞれ独立したtagです。

インストール直後は**リクエストの挙動が変わりません**。公開middlewareはグローバル登録されず、任意モジュールはすべて無効です。

## モジュールと初期状態

| モジュール | 初期状態 | 責務 |
| --- | --- | --- |
| IP Resolver | 有効 | 信頼できるクライアントIPの取得とIPv4/IPv6正規化 |
| Attack Path Detector | 有効 | exact / prefix / regexによる既知攻撃パス判定 |
| Persistent IP Block | 有効 | DB永続化、キャッシュ、遮断、再検知、解除 |
| Public Rate Limit | 無効 | 公開リクエストのIP単位計数と上限超過時の処理 |
| Admin IP Allowlist | 無効 | 認証主体ごとの許可IP判定 |
| Sensitive Route Limit | 無効 | ルート用途ごとのIP・識別子単位制限 |
| One-time Submission Token | 無効 | 確認画面を伴うPOSTの一回限り実行 |
| Security Event Notification | 無効 | 遮断イベントの非同期通知、集約、日次上限 |
| Error Notification Guard | 無効 | ホスト側エラーイベントの集約、無害化、送信制限 |
| Management UI | 無効 | 標準の遮断一覧・解除画面 |

## 段階的な導入手順

1. configを公開し、全機能を無効のまま`php artisan security-guard:doctor`で設定を検査する
2. trusted proxyとclient IP解決結果を`php artisan security-guard:status <ip>`で確認する
3. `permanent_block.ignored_ips`へ監視・社内・保守元IPを登録する
4. 公開middlewareを登録し、attack path detectorと永続遮断のみ有効化する
5. stagingで遮断、継続、解除、再遮断を確認する
6. 公開レート制限をstagingで有効化する
7. webhook、認証callback、管理画面などを`excluded_paths`へ登録する
8. 管理者許可IPをCLIで登録してから管理IP制限を有効化する
9. センシティブルルートへprofileを個別適用する
10. queue workerと送信上限を確認してから通知を有効化する
11. 各段階の前後で`php artisan security-guard:doctor --strict`を実行する
12. 本番では低リスクな時間帯に適用し、403・429件数とアプリケーションエラーを監視する

## 公開リクエストの保護

`Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests`をグローバル登録します。ルートが存在しないパスへの探索も検知するため、**ルートmiddlewareではなくグローバル登録**を推奨します。

`bootstrap/app.php`:

```php
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;

->withMiddleware(function (Middleware $middleware) {
    $middleware->prepend(GuardPublicRequests::class);
})
```

エイリアス`security-guard`も登録済みなので、特定のルートグループだけに適用することもできます。

### 評価順序

1. 除外パス判定
2. クライアントIP解決・正規化
3. ignored IP判定
4. 既存の永続遮断判定
5. 既知攻撃パス判定
6. 公開レート制限判定

### reverse proxy配下での注意

パッケージは`X-Forwarded-For`を独自に参照しません。proxy配下では**先にLaravelのtrusted proxy設定を完了**させ、`security-guard:status`で解決結果を確認してから有効化してください。設定を誤ると全リクエストが同一IPと判定され、レート制限が誤作動します。

## 既知攻撃パス検知

初期パターンは`wordpress_probe`、`secret_file_probe`、`database_admin_probe`、`phpunit_probe`、`server_probe`の5カテゴリです。判定前にパスを正規化し（前後スラッシュ除去、連続スラッシュ統合、バックスラッシュ変換、NUL除去、小文字化、percent decode最大2回）、クエリ文字列とリクエスト本文は判定に使用しません。

```php
'permanent_block' => [
    'use_default_patterns' => true,
    'attack_patterns' => [
        // カテゴリを無効化
        'phpunit_probe' => false,

        // カテゴリを追加
        'legacy_probe' => [
            'exact' => ['legacy/install.php'],
            'prefix' => ['legacy/setup/'],
            'regex' => ['#(^|/)legacy-[^/]+\.php$#'],
        ],
    ],
],
```

regexは設定者が追加できるため、ReDoSを避ける観点でレビューしてください。無効なregexはそのパターンのみ無視し、警告を1回だけ記録します。

## 公開レート制限

```php
'public_rate_limit' => [
    'enabled' => true,
    'requests_per_minute' => 120,
    'action' => 'permanent_block', // permanent_block | temporary_block | reject_only
    'excluded_paths' => [
        'admin',
        'admin/*',
        'api/*/webhook',
        'auth/*/callback',
    ],
],
```

有効化する前に、サーバー間通信を行うルート（webhook、認証callback、トラッキング、ヘルスチェック）を棚卸しして除外してください。

### 除外リストはモジュールごとに独立しています

`public_rate_limit.excluded_paths` が無効化するのは**回数カウントだけ**です。除外したパスでも、遮断済みIPは403のままで、攻撃パス検知も動作し続けます。

レート制限は「容量の制御」、遮断は「セキュリティの制御」であり、webhookをレート制限から外したい要求が、そのパスの防御まで外す理由にはならないためです。

遮断と攻撃パス検知そのものを免除したい場合は、別のリストを明示的に使います。

```php
'permanent_block' => [
    // 既定は空。ここへ追加したパスでは、遮断済みIPも通常どおり応答されます
    'excluded_paths' => [],
],
```

## 管理領域IP許可リスト

特定のUserモデルや主キー型に依存しません。認証主体は`subject_type`と`subject_id`で識別します。

```php
'admin_ip' => [
    'enabled' => true,
    'guard' => 'admin',
    'subject_type' => 'admin',
    'empty_policy' => 'deny', // deny | allow_when_empty
],
```

**有効化前に必ず許可IPを登録してください。**

```bash
php artisan security-guard:admin-ip:allow 1234 203.0.113.10 --type=admin --label=office
```

`empty_policy`が`deny`の場合、許可IPが0件の主体はログインできません。移行期間のみ`allow_when_empty`を利用できます。

middlewareはホスト側の認証middlewareの**後**に配置してください。未認証リクエストはそのまま通過させ、判断はホストのauth middlewareへ委譲します。

```php
Route::middleware(['web', 'auth:admin', 'security-guard.admin-ip'])->group(function () {
    // ...
});
```

ログイン処理の前に判定したい場合はサービスを直接呼び出せます。

```php
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Services\AdminIpAccessService;

$allowed = app(AdminIpAccessService::class)->isAllowed(
    new AdminSubjectData('admin', (string) $user->getKey()),
    $request->ip(),
);
```

拒否時は固定メッセージのみを返し、登録IPやアカウントの存在を漏らしません。監査ログは`AdminIpAccessDenied`イベントで連携してください。

## センシティブルルート制限

profileごとに名前付きRateLimiterが登録されます。対象ルートへ`throttle:<profile>`を明示的に付けてください。

```php
'sensitive_routes' => [
    'enabled' => true,
    'profiles' => [
        'customer_login' => [
            'decay_minutes' => 10,
            'ip_attempts' => 20,
            'identifiers' => [
                'email' => ['field' => 'email', 'attempts' => 5],
            ],
        ],
        'contact_submit' => [
            'decay_minutes' => 60,
            'ip_attempts' => 5,
            'identifiers' => [
                'email' => ['field' => 'email', 'attempts' => 3],
            ],
        ],
        'password_reset_request' => [
            'decay_minutes' => 60,
            'ip_attempts' => 5,
            'identifiers' => [
                'email' => ['field' => 'email', 'attempts' => 3],
            ],
        ],
    ],
],
```

```php
Route::post('/login', LoginController::class)->middleware('throttle:customer_login');
```

識別子はtrim・小文字化後にSHA-256でhash化され、cache keyにもログにも平文で残りません。リクエストフィールド以外から取り出す場合は`IdentifierResolverContract`実装を`'resolver' => MyResolver::class`で指定します。

## ワンタイム送信トークン

CSRF対策の**代替ではなく併用**です。確認画面を挟むPOSTの二重送信を防ぎます。

```php
use Apkk\LaravelSecurityGuard\Services\SubmissionTokenService;

// 確認画面の表示時
$token = app(SubmissionTokenService::class)->issue($request, 'contact');

// 送信処理
if (! app(SubmissionTokenService::class)->consume($request, 'contact', $request->input('submission_token'))) {
    return back()->withErrors(['submission_token' => '送信内容が無効になりました。最初からやり直してください。']);
}
```

検証結果にかかわらずトークンは再利用できません。使用済みhashは共有cacheに保存されるため、並行送信でも成功するのは1回だけです。

## 共有キャッシュでの名前空間

複数アプリで1台のRedisを共有する場合、`cache.prefix` をアプリごとに変えてください。既定値のままだと、stagingが日次通知上限を使い切ると本番の通知が止まり、片方での解除がもう片方の遮断キャッシュにも影響します。

```php
'cache' => [
    'store' => env('SECURITY_GUARD_CACHE_STORE'),
    'prefix' => env('APP_NAME', 'security-guard'),
],
```

キーにIPやメールアドレスの平文は入りません（SHA-256でhash化されます）。

## 通知

```php
'notifications' => [
    'enabled' => true,
    'queue' => 'default',
    'channels' => ['log', 'mail'],
    'daily_limit' => 10,
    'mask_ip' => false,
    'mail' => [
        'to' => ['ops@example.com'],
    ],
],
```

通知本文に含まれるのは、イベント種別、判断基準ラベル、正規化済みIP（設定によりmask）、パターン名、検知日時、遮断ID、固定の対応案内のみです。**URL、path、query、request body、header、cookie、例外メッセージ、traceは含まれません。**これはDTO側で構造的に保証されています。

- 日次上限はatomic lockで管理し、消費単位は「イベント単位」です。受信者数で重複加算しません
- 通知の失敗は遮断の失敗になりません
- jobは遮断IDでuniqueです
- 独自channel（LINE、Slackなど）は`NotifierRegistry`へ登録します

```php
use Apkk\LaravelSecurityGuard\Notifications\NotifierRegistry;

app(NotifierRegistry::class)->registerSecurityChannel('line', LineSecurityNotifier::class);
```

`array`キャッシュは日次上限・重複排除・レート制限に使用しないでください。複数ノード構成では全ノードが共有するatomic lock対応キャッシュが必要です。

## エラー通知ガード

ホスト側のエラー記録を受け取り、集約・クールダウン・channel別日次上限を適用します。

```php
use Apkk\LaravelSecurityGuard\Data\ErrorEventData;
use Apkk\LaravelSecurityGuard\Services\ErrorNotificationGuard;

app(ErrorNotificationGuard::class)->report(new ErrorEventData(
    environment: app()->environment(),
    area: 'front',
    notificationType: 'front_error',
    reportReference: $report->id,
    exceptionClass: $exception::class,
    occurredAt: new DateTimeImmutable(),
));
```

`ErrorEventData`には環境、領域、通知種別、レポート参照ID、例外クラス、発生日時しか入りません。URLや例外本文は自分のDBに保存し、参照IDだけを渡してください。URLを保存する場合は機密query keyのmaskと列サイズへの切り詰めに`sanitizeUrl()`が使えます。

```php
$url = app(ErrorNotificationGuard::class)->sanitizeUrl($request->fullUrl());
```

上限到達時の扱い（`mark_handled` / `hold`）と送信結果は`ErrorNotificationOutcomeHandlerContract`を実装してバインドすると受け取れます。

集約バッファには保持件数の上限があります。エラー嵐で最も速く膨らむのがこのバッファのため、上限超過分は保持されませんが**件数としては数え続け**、通知本文には実際の発生件数が出ます（`Occurrences: 1200 (showing 50)`）。

```php
'error_notifications' => [
    'aggregation_delay_seconds' => 60,
    'cooldown_minutes' => 10,
    'daily_limits' => ['line' => 4, 'mail' => 4],
    'on_limit' => 'mark_handled', // mark_handled | hold
    'max_aggregated_events' => 50,
],
```

通知の送信失敗はqueueのリトライ対象になります。成功済みchannelは記録されるため、再送は**失敗したchannelだけ**を対象とし、日次上限もイベントごとに1回しか消費しません。宛先未設定などリトライで解決しない失敗は再送されません。

## 診断ログの注意

ドライバの例外メッセージにはDSNや文の bind 値が含まれることがあります。ログを外部へ転送している場合は次で本文を落とせます（例外クラスは常に記録されます）。

```php
'logging' => [
    'include_exception_messages' => false,
],
```

## 管理UI

```php
'management_ui' => [
    'enabled' => true,
    'prefix' => 'security-guard',
    'middleware' => ['web', 'auth', 'can:manage-security'],
],
```

有効化した場合のみルートを登録します。解除はPOST・CSRF・認可・FormRequest検証が必須です。viewは`security-guard-views`タグでpublishして差し替えられます。

## 導入前診断 (doctor)

有効化の前に設定の妥当性を検査します。このパッケージの誤設定はほとんど例外を出さず、**黙って防御が効かなくなる**か、**誰かがログインしようとした瞬間に全管理者が締め出される**形で現れるため、事前に可視化するためのコマンドです。

```bash
php artisan security-guard:doctor
```

検査対象:

| 項目 | 内容 |
| --- | --- |
| Laravelバージョン | 対応範囲内か。12は`12.61.1`以上、13は`13.12.0`以上か |
| DB | 接続可否、必要テーブルの存在 |
| cache | プロセス間共有か、atomic lock対応か、`add()`がtest-and-setとして動くか |
| cache prefix | 未設定または既定値のままでないか |
| IP resolver | driverの妥当性、trusted proxyの設定有無 |
| 攻撃パスregex | コンパイル可能か（無効なものは実行時に黙って無視されるため） |
| レート制限の整合性 | `permanent_block`無効時に`action=permanent_block`になっていないか、遮断除外パスの有無 |
| 管理IP許可リスト | 有効かつ0件で`deny`（＝全員締め出し）になっていないか |
| 通知 | channelの解決可否、mail宛先、日次上限、queue接続 |
| 管理UI | 認証・認可middlewareが両方あるか |
| ワンタイムトークン | 共有cacheを使っているか |

### CI・デプロイでの利用

```bash
php artisan security-guard:doctor --strict --json
```

終了コード:

| コード | 意味 |
| --- | --- |
| `0` | 問題なし |
| `1` | failureあり |
| `2` | warningあり、かつ`--strict`指定時 |

#### 結果スキーマ

各検査結果は「**実行状態**」と「**重大度**」を分けて持ちます。実行されなかった検査に重大度はありません。`ok`と扱えば誰も検証していない保証を主張することになり、warningと扱えば有効化していない機能への対応を求めることになるためです。

| フィールド | 値 | 意味 |
| --- | --- | --- |
| `state` | `executed` / `skipped` | 検査が実行されたか |
| `severity` | `ok` / `warning` / `failure` | 実行された場合の重大度。`skipped`のときは`null` |

重大度が3値なのは、「動作するが本番では脆い」と「壊れている・危険」を区別するためです。同一視すると`--strict`が使い物にならないか、実用にならないかのどちらかになります。

```json
{
  "healthy": false,
  "strict": false,
  "exit_code": 1,
  "summary": { "total": 16, "executed": 12, "skipped": 4, "failures": 1, "warnings": 3 },
  "results": [
    {
      "check": "admin_ip_allowlist",
      "state": "executed",
      "severity": "failure",
      "message": "The allowlist is enabled with no entries and empty_policy is \"deny\".",
      "remedy": "Register an address first: `php artisan security-guard:admin-ip:allow <subject> <ip>`. Nobody can sign in until you do.",
      "context": { "entries": "0", "empty_policy": "deny" }
    },
    {
      "check": "submission_token",
      "state": "skipped",
      "severity": null,
      "message": "One-time submission tokens are disabled.",
      "remedy": null,
      "context": {}
    }
  ]
}
```

出力に秘密情報は含まれません。cache prefixやdriver名などの設定値のみを表示します。

### 管理許可IPの閲覧画面

管理領域の許可ルールを一覧するだけの**閲覧専用**画面です。既定で無効、かつ**独立した設定**が必要です。

```php
'management_ui' => [
    'enabled' => true,
    'admin_allowed_ips' => [
        'enabled' => true,   // これも true のときだけルート登録
    ],
],
```

`management_ui.enabled` だけでは有効になりません。v0.1.x で管理UIを有効にしていた導入先へ、アップデートだけで「どの主体にどの範囲を許可しているか」という機密情報の画面が増えないようにするためです。

`security-guard/admin-allowed-ips` に登録され、middlewareは既存の管理UI設定を継承します。

表示項目は `subject_type`、`subject_id`、canonical化されたルール、種別（`Exact` / `CIDR`）、許可アドレス数、ラベル、有効状態、作成・更新日時です。doctorと同じ観点の警告（解析不能、非canonical、過度に広い、semantic duplicate）を該当行に添えて表示します。解析不能な行があっても画面全体は落ちません。

主体、ルール文字列、種別、有効状態で絞り込みでき、ページネーションに対応します。

**書き込みルートは存在しません。** 追加・削除はCLI（`admin-ip:allow` / `admin-ip:revoke`）のみです。UIから権限付与できると、認可設定の誤りがそのまま管理アクセス権の付与につながるためです。ホストのユーザーテーブルとは結合せず、`subject_type` と `subject_id` は保存値のみを表示します。

## Artisanコマンド

```bash
php artisan security-guard:doctor --strict
```

```bash
php artisan security-guard:blocked:list --active
```

```bash
php artisan security-guard:blocked:release 203.0.113.10 --actor=ops
```

```bash
php artisan security-guard:status 203.0.113.10
```

```bash
php artisan security-guard:admin-ip:allow 1234 203.0.113.10 --type=admin --label=office
```

```bash
php artisan security-guard:admin-ip:list 1234 --type=admin
```

```bash
php artisan security-guard:admin-ip:revoke 1234 203.0.113.10 --type=admin
```

対話待ちはありません。無効なIPは非ゼロ終了コードとなり、DBへ書き込みません。

## 障害時の方針

| 障害 | 動作 | 理由 |
| --- | --- | --- |
| IPを解決できない | 通過 | 誤遮断防止 |
| 遮断cache read失敗 | DB参照 | 遮断状態の維持 |
| 遮断DB read失敗 | 通過し警告 | アプリ全停止の回避 |
| RateLimiter / cache失敗 | 通過し警告 | 500増幅の回避 |
| 既知攻撃パスの遮断DB write失敗 | 固定403、保存失敗を警告 | 明確な攻撃を処理しつつ障害を記録 |
| 通知dispatch・送信失敗 | 遮断は維持 | 防御と通知の分離 |
| 日次上限lock失敗 | 通知しない | 通知洪水防止 |
| 管理IP DB判定失敗 | deny | 管理領域を安全側へ |
| 無効regex | 該当regexを無視し警告 | 全リクエスト500の回避 |

方針は機能ごとに固定です。全体を一括で切り替える設定は提供しません。

## イベント

ホスト側の監査テーブルへ履歴を残す場合は、次のイベントを購読してください。遮断行は1IPにつき1行を再利用するため、完全な履歴はイベント側で保持します。

- `Apkk\LaravelSecurityGuard\Events\IpBlocked`
- `Apkk\LaravelSecurityGuard\Events\IpReleased`
- `Apkk\LaravelSecurityGuard\Events\AdminIpAccessDenied`

## 差し替え可能なContract

| Contract | 標準実装 |
| --- | --- |
| `ClientIpResolverContract` | `LaravelRequestIpResolver` / `RemoteAddrIpResolver` |
| `AttackPathMatcherContract` | `ConfigAttackPathMatcher` |
| `BlockedIpRepositoryContract` | `EloquentBlockedIpRepository` |
| `AdminAllowedIpRepositoryContract` | `EloquentAdminAllowedIpRepository` |
| `AdminSubjectResolverContract` | `ConfigAdminSubjectResolver` |
| `SecurityEventDispatcherContract` | `QueuedSecurityEventDispatcher` |
| `SecurityEventNotifierContract` | `LogSecurityEventNotifier` / `MailSecurityEventNotifier` |
| `ErrorEventNotifierContract` | `LogErrorEventNotifier` / `MailErrorEventNotifier` |
| `IpMatcherContract` | `ExactIpMatcher` |

## このパッケージが行わないこと

- WAF、CDN、Apache、Nginx、ロードバランサーの設定代替
- SQLインジェクション、XSS、認可不備の自動修正
- **公開ルートの入力検証**（商品ID、カテゴリ、検索条件などの型・形式・存在確認は、導入先でFormRequestを用意してください）
- CAPTCHA、Turnstile、MFA
- 攻撃元IPの地理情報取得や外部レピュテーション判定

## IP照合とCIDR

`permanent_block.ignored_ips` と管理領域の許可IPは、**個別アドレスとCIDRネットワークの両方**に対応しています。

```php
'ignored_ips' => [
    '203.0.113.10',      // 個別アドレス
    '198.51.100.0/24',   // IPv4ネットワーク
    '2001:db8::/48',     // IPv6ネットワーク
],
```

### 保存時の正規化

`/32`・`/128` は完全一致を意味するためsuffixを落とします。次はすべて同一ルールです。

```text
203.0.113.10
203.0.113.10/32
```

host bitを含む表記はネットワークへ丸められます。**書いたアドレスより広い範囲を許可することになる**ため、CLIは変換内容を警告し、doctorも検出します。

```text
203.0.113.42/24  ->  203.0.113.0/24
```

### ファミリを跨ぎません

IPv4ルールはIPv4-mapped IPv6アドレスを許可しません。`203.0.113.0/24` の許可は、同じ数字をエンコードしたv6クライアント（`::ffff:203.0.113.10`）を通す同意ではないためです。

### 解析できない値は何にも一致しません

`203.0.113.*` のような非対応記法や不正な値は、ワイルドカードではなく**何にも一致しない**扱いです。許可リストのtypoが全員を通す事態を避けるためです。ignore listでは意図した除外が効かず、管理許可IPでは本人がログインできなくなるため、`security-guard:doctor` が検出します。

### 広すぎるルールの検出

doctorは既定より広いルールを警告します。照合動作には影響しません。

```php
'ip_rules' => [
    'minimum_prefix' => ['v4' => 16, 'v6' => 32],
],
```

`security-guard:admin-ip:allow` は `/0` を既定で拒否します（`--force` で上書き可能）。全アドレスを許可するルールは許可リストとして機能しないためです。

### 完全一致のみに戻す

CIDRを一切受け付けない運用にする場合は `ExactIpMatcher` を明示的にバインドします。ただし**CIDRを書いても黙って何にも一致しなくなる**ため、doctorがその状態を検出します。

```php
$this->app->singleton(IpMatcherContract::class, ExactIpMatcher::class);
```

## サポートポリシー

正式対応は、**Laravel公式のセキュリティ修正期間内にあるメジャーバージョン**に限定します。

| Laravel | PHP | 状態 | Laravel公式のセキュリティ修正期限 |
| --- | --- | --- | --- |
| 13.x | 8.3 / 8.4 / 8.5 | 正式対応 | 2028-03-17 |
| 12.x | 8.2 / 8.3 / 8.4 | 正式対応 | 2027-02-24 |
| 11.x | — | 対応対象外 | 2026-03-12 に終了 |
| 10.x | — | 対応対象外 | 2025-02-04 に終了 |

Composerの制約下限は、メジャーの `.0` ではなく**セキュリティ勧告の対象外となる最古のパッチバージョン**です（`^12.61.1 || ^13.12.0`）。

### Laravel 10・11を対応対象外とする理由

両系統は上流のセキュリティ修正期間を終えており、**全リリースが未修正の勧告の対象**です（10.x: 5件、11.x: 7件）。Composer 2.9以降は既定でこれらの解決を拒否します。

回避には利用者側でセキュリティブロックの無効化が必要になりますが、セキュリティ対策パッケージの導入手順としてそれを案内することはしません。またlegacyブランチや別パッケージも提供しません。Laravel本体の未修正脆弱性は、このパッケージでは解消できないためです。

「コード上は動作する可能性がある」といった記載も行いません。動作可能であることと安全に利用できることは別だからです。

### 今後の変更

- Laravel 12は**2027-02-24**をもって正式対応から外します。それ以降に公開するバージョンはLaravel 13以降のみを対象とします
- CIで依存解決できないバージョンは、正式対応対象に含めません

## 運用上の前提

- 複数プロセス・複数台構成では、全ノードが共有するatomic lock対応キャッシュを使用する
- `array`キャッシュを本番の日次上限、重複排除、レート制限に使用しない
- 非同期通知を利用する場合はqueue workerを常時稼働させる
- reverse proxy配下ではtrusted proxy設定を完了させ、IP解決結果を事前に確認する

## 開発

```bash
composer install
```

```bash
composer check
```

`composer check` はCIと同じ3つのゲート（Pint、PHPStan level 6、PHPUnit）を実行します。

```bash
SECURITY_GUARD_TEST_DB=mysql DB_HOST=127.0.0.1 DB_PORT=3306 DB_USERNAME=root DB_PASSWORD=secret vendor/bin/phpunit
```

`composer.lock` は意図的にコミットしていません。ライブラリのため、1つの依存解決だけを検証するのではなく、対応範囲全体を検証します。

詳細は [CONTRIBUTING.md](CONTRIBUTING.md) を参照してください。

## License

MIT
