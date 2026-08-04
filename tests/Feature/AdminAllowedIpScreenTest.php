<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Contracts\AdminAllowedIpRepositoryContract;
use Apkk\LaravelSecurityGuard\Data\AdminSubjectData;
use Apkk\LaravelSecurityGuard\Models\AdminAllowedIp;
use Apkk\LaravelSecurityGuard\Tests\Fixtures\TestUser;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Facades\Route;

/**
 * The bundled allowlist screen.
 *
 * Which networks reach the admin area, and for whom, is more sensitive than
 * the block list. The screen is therefore off by default, needs its own
 * opt-in, and has no route that changes anything — granting administrative
 * access stays in the CLI, where a misconfigured `can:` rule cannot reach it.
 */
class AdminAllowedIpScreenTest extends TestCase
{
    use RefreshDatabase;

    private const URL = '/security-guard/admin-allowed-ips';

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        tap($app->make(Repository::class), function (Repository $config): void {
            $config->set('auth.providers.test_users', ['driver' => 'eloquent', 'model' => TestUser::class]);
            $config->set('auth.guards.web.provider', 'test_users');
            $config->set('security-guard.management_ui.enabled', true);
            $config->set('security-guard.management_ui.admin_allowed_ips.enabled', true);
            $config->set('security-guard.management_ui.middleware', ['web', 'auth', 'can:manage-security']);
        });
    }

    protected function defineRoutes($router): void
    {
        Route::get('/login', fn (): string => 'login')->name('login');
    }

    protected function setUp(): void
    {
        parent::setUp();

        Gate::define('manage-security', fn (TestUser $user): bool => $user->email === 'admin@example.test');
    }

    private function operator(string $email = 'admin@example.test'): TestUser
    {
        return TestUser::query()->firstOrCreate(
            ['email' => $email],
            ['name' => 'Operator', 'password' => bcrypt('secret')],
        );
    }

    private function rule(string $ip, string $subjectId = '1', ?string $label = null): void
    {
        $this->app->make(AdminAllowedIpRepositoryContract::class)
            ->allow(new AdminSubjectData('admin', $subjectId), $ip, $label);
    }

    // -----------------------------------------------------------------
    // Exposure is opt-in
    // -----------------------------------------------------------------

    // The opt-out case lives in AdminAllowedIpScreenDisabledTest, which boots
    // with the screen switched off.

    public function test_the_route_exists_when_both_switches_are_on(): void
    {
        $this->assertTrue(Route::has('security-guard.admin-allowed-ips.index'));
    }

    public function test_it_requires_authentication(): void
    {
        $this->get(self::URL)->assertRedirect('/login');
    }

    public function test_it_requires_authorization(): void
    {
        $this->actingAs($this->operator('intruder@example.test'))
            ->get(self::URL)
            ->assertForbidden();
    }

    public function test_an_authorised_operator_can_read_it(): void
    {
        $this->rule('203.0.113.0/24');

        $this->actingAs($this->operator())
            ->get(self::URL)
            ->assertOk()
            ->assertSee('203.0.113.0/24');
    }

    // -----------------------------------------------------------------
    // Read-only
    // -----------------------------------------------------------------

    public function test_no_write_route_exists_for_the_allowlist(): void
    {
        $registered = [];

        foreach (Route::getRoutes()->getRoutes() as $route) {
            $uri = $route->uri();

            if (! str_contains($uri, 'admin-allowed-ips')) {
                continue;
            }

            foreach ($route->methods() as $method) {
                $registered[] = $method;
            }
        }

        $this->assertNotEmpty($registered, 'The screen should be registered.');
        // GET and HEAD only. A route that grants administrative access must
        // not exist behind a `can:` rule someone might get wrong.
        $this->assertSame(['GET', 'HEAD'], array_values(array_unique($registered)));
    }

    public function test_write_verbs_are_rejected(): void
    {
        $operator = $this->operator();

        foreach (['post', 'put', 'patch', 'delete'] as $verb) {
            $this->actingAs($operator)->{$verb}(self::URL)->assertStatus(405);
        }
    }

    public function test_the_page_offers_no_form_that_changes_a_rule(): void
    {
        $this->rule('203.0.113.0/24');

        $body = (string) $this->actingAs($this->operator())->get(self::URL)->getContent();

        // The only form on the page is the GET filter.
        $this->assertSame(1, substr_count($body, '<form'));
        $this->assertStringContainsString('method="GET"', $body);
        $this->assertStringNotContainsString('method="POST"', $body);
    }

    // -----------------------------------------------------------------
    // What it shows
    // -----------------------------------------------------------------

    public function test_it_distinguishes_exact_rules_from_networks(): void
    {
        $this->rule('203.0.113.10');
        $this->rule('198.51.100.0/24');

        $response = $this->actingAs($this->operator())->get(self::URL);

        $response->assertOk()
            ->assertSee('Exact')
            ->assertSee('CIDR')
            ->assertSee('203.0.113.10')
            ->assertSee('198.51.100.0/24');
    }

    public function test_it_shows_ipv6_rules(): void
    {
        $this->rule('2001:db8::1');
        $this->rule('2001:db8::/48');

        $this->actingAs($this->operator())->get(self::URL)
            ->assertOk()
            ->assertSee('2001:db8::1')
            ->assertSee('2001:db8::/48');
    }

    public function test_it_shows_the_canonical_value_not_what_was_typed(): void
    {
        $this->rule('203.0.113.42/24');

        $this->actingAs($this->operator())->get(self::URL)
            ->assertOk()
            ->assertSee('203.0.113.0/24')
            ->assertDontSee('203.0.113.42/24');
    }

    public function test_it_shows_subject_label_and_state(): void
    {
        $this->rule('203.0.113.10', '4242', 'Tokyo office');

        $this->actingAs($this->operator())->get(self::URL)
            ->assertOk()
            ->assertSee('admin')
            ->assertSee('4242')
            ->assertSee('Tokyo office')
            ->assertSee('enabled');
    }

    public function test_it_does_not_join_host_account_attributes(): void
    {
        $operator = $this->operator();
        $this->rule('203.0.113.10', (string) $operator->getKey());

        $body = (string) $this->actingAs($operator)->get(self::URL)->getContent();

        // subject_id is shown as stored; the screen must not become a way to
        // read the host's user table.
        $this->assertStringNotContainsString('admin@example.test', $body);
        $this->assertStringNotContainsString('Operator', $body);
    }

    // -----------------------------------------------------------------
    // Warnings
    // -----------------------------------------------------------------

    private function writeRawRule(string $ip, string $subjectId = '1'): void
    {
        AdminAllowedIp::query()->create([
            'subject_type' => 'admin',
            'subject_id' => $subjectId,
            'ip_address' => $ip,
            'enabled' => true,
        ]);
    }

    public function test_an_unparseable_row_is_flagged_without_breaking_the_page(): void
    {
        $this->writeRawRule('203.0.113.1-50');
        $this->rule('198.51.100.0/24');

        $this->actingAs($this->operator())->get(self::URL)
            ->assertOk()
            ->assertSee('invalid')
            ->assertSee('matches nothing')
            // The healthy rule still renders.
            ->assertSee('198.51.100.0/24');
    }

    public function test_a_non_canonical_row_is_flagged(): void
    {
        $this->writeRawRule('203.0.113.42/24');

        $this->actingAs($this->operator())->get(self::URL)
            ->assertOk()
            ->assertSee('Not canonical', false);
    }

    public function test_an_excessively_wide_rule_is_flagged(): void
    {
        $this->writeRawRule('10.0.0.0/8');

        $this->actingAs($this->operator())->get(self::URL)
            ->assertOk()
            ->assertSee('Unusually wide');
    }

    public function test_a_semantic_duplicate_is_flagged(): void
    {
        $this->writeRawRule('203.0.113.0/24');
        $this->writeRawRule('203.0.113.7/24');

        $this->actingAs($this->operator())->get(self::URL)
            ->assertOk()
            ->assertSee('means the same thing');
    }

    // -----------------------------------------------------------------
    // Filtering and pagination
    // -----------------------------------------------------------------

    public function test_it_filters_by_subject(): void
    {
        $this->rule('203.0.113.10', '111');
        $this->rule('198.51.100.10', '222');

        $this->actingAs($this->operator())->get(self::URL.'?subject_id=111')
            ->assertOk()
            ->assertSee('203.0.113.10')
            ->assertDontSee('198.51.100.10');
    }

    public function test_it_filters_by_kind(): void
    {
        $this->rule('203.0.113.10');
        $this->rule('198.51.100.0/24');

        $this->actingAs($this->operator())->get(self::URL.'?kind=cidr')
            ->assertOk()
            ->assertSee('198.51.100.0/24')
            ->assertDontSee('203.0.113.10');

        $this->actingAs($this->operator())->get(self::URL.'?kind=exact')
            ->assertOk()
            ->assertSee('203.0.113.10')
            ->assertDontSee('198.51.100.0/24');
    }

    public function test_it_filters_by_state(): void
    {
        $this->rule('203.0.113.10');
        $this->rule('198.51.100.10');
        AdminAllowedIp::query()->where('ip_address', '198.51.100.10')->update(['enabled' => false]);

        $this->actingAs($this->operator())->get(self::URL.'?enabled=0')
            ->assertOk()
            ->assertSee('198.51.100.10')
            ->assertDontSee('203.0.113.10');
    }

    public function test_it_filters_by_rule_text(): void
    {
        $this->rule('203.0.113.10');
        $this->rule('198.51.100.10');

        $this->actingAs($this->operator())->get(self::URL.'?ip=203.0.113')
            ->assertOk()
            ->assertSee('203.0.113.10')
            ->assertDontSee('198.51.100.10');
    }

    public function test_a_wildcard_in_the_filter_is_searched_literally(): void
    {
        $this->rule('203.0.113.10');

        // '%' must not behave as a SQL wildcard from the query string.
        $this->actingAs($this->operator())->get(self::URL.'?ip=%')
            ->assertOk()
            ->assertSee('No rules match.');
    }

    public function test_it_paginates_per_subject(): void
    {
        config()->set('security-guard.management_ui.per_page', 5);

        for ($i = 1; $i <= 12; $i++) {
            $this->rule("203.0.113.{$i}", '777');
        }

        $first = $this->actingAs($this->operator())->get(self::URL.'?subject_id=777');
        $first->assertOk()->assertSee('Page 1 of 3')->assertSee('12 rules');

        $this->actingAs($this->operator())->get(self::URL.'?subject_id=777&page=3')
            ->assertOk()
            ->assertSee('Page 3 of 3');
    }

    // -----------------------------------------------------------------
    // Doctor
    // -----------------------------------------------------------------

    public function test_the_doctor_reports_the_screen_as_enabled(): void
    {
        Artisan::call('security-guard:doctor', ['--json' => true]);
        $report = json_decode(Artisan::output(), true);

        $checks = array_column($report['results'], 'severity', 'check');

        $this->assertSame('ok', $checks['management_ui.admin_allowed_ips'] ?? null);
    }

    public function test_the_doctor_fails_when_the_screen_has_no_authorization(): void
    {
        config()->set('security-guard.management_ui.middleware', ['web', 'auth']);

        Artisan::call('security-guard:doctor', ['--json' => true]);
        $report = json_decode(Artisan::output(), true);

        $management = null;

        foreach ($report['results'] as $result) {
            if ($result['check'] === 'management_ui') {
                $management = $result;
            }
        }

        $this->assertSame('failure', $management['severity']);
        $this->assertStringContainsString('allowlist screen', (string) $management['remedy']);
    }
}
