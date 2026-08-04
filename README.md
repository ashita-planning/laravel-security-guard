# Laravel Security Guard

不正アクセス対策をLaravelアプリケーションへ追加するComposerパッケージです。既知攻撃パスの検知、IPの永続遮断、公開レート制限、管理領域のIP許可リスト、ワンタイム送信トークン、無害化された通知を提供します。

- Composer package: `apkk/laravel-security-guard`
- PHP namespace: `Apkk\LaravelSecurityGuard`
- 対応: PHP `^8.1` / Laravel `10` `11` `12` `13`

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

1. configを公開し、全機能を無効のまま設定値を確認する
2. trusted proxyとclient IP解決結果を`php artisan security-guard:status <ip>`で確認する
3. `permanent_block.ignored_ips`へ監視・社内・保守元IPを登録する
4. 公開middlewareを登録し、attack path detectorと永続遮断のみ有効化する
5. stagingで遮断、継続、解除、再遮断を確認する
6. 公開レート制限をstagingで有効化する
7. webhook、認証callback、管理画面などを`excluded_paths`へ登録する
8. 管理者許可IPをCLIで登録してから管理IP制限を有効化する
9. センシティブルルートへprofileを個別適用する
10. queue workerと送信上限を確認してから通知を有効化する
11. 本番では低リスクな時間帯に適用し、403・429件数とアプリケーションエラーを監視する

## 公開リクエストの保護

`Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests`をグローバル登録します。ルートが存在しないパスへの探索も検知するため、**ルートmiddlewareではなくグローバル登録**を推奨します。

Laravel 11 / 12 / 13 (`bootstrap/app.php`):

```php
use Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests;

->withMiddleware(function (Middleware $middleware) {
    $middleware->prepend(GuardPublicRequests::class);
})
```

Laravel 10 (`app/Http/Kernel.php`):

```php
protected $middleware = [
    \Apkk\LaravelSecurityGuard\Http\Middleware\GuardPublicRequests::class,
    // ...
];
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

## 管理UI

```php
'management_ui' => [
    'enabled' => true,
    'prefix' => 'security-guard',
    'middleware' => ['web', 'auth', 'can:manage-security'],
],
```

有効化した場合のみルートを登録します。解除はPOST・CSRF・認可・FormRequest検証が必須です。viewは`security-guard-views`タグでpublishして差し替えられます。

## Artisanコマンド

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

v1のIP照合は完全一致のみです。CIDR、IPv6 subnet、trusted internal networkは含みません。将来の追加は`IpMatcherContract`の実装差し替えで行えます。

## 運用上の前提

- 複数プロセス・複数台構成では、全ノードが共有するatomic lock対応キャッシュを使用する
- `array`キャッシュを本番の日次上限、重複排除、レート制限に使用しない
- 非同期通知を利用する場合はqueue workerを常時稼働させる
- reverse proxy配下ではtrusted proxy設定を完了させ、IP解決結果を事前に確認する

## 開発

```bash
composer test
```

```bash
composer lint
```

## License

MIT
