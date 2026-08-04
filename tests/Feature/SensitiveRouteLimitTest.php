<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Route;

class SensitiveRouteLimitTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        tap($app->make(Repository::class), function (Repository $config): void {
            $config->set('security-guard.sensitive_routes.enabled', true);
            $config->set('security-guard.sensitive_routes.profiles', [
                'customer_login' => [
                    'decay_minutes' => 10,
                    'ip_attempts' => 5,
                    'identifiers' => [
                        'email' => ['field' => 'email', 'attempts' => 2],
                    ],
                ],
                'contact_confirm' => [
                    'decay_minutes' => 10,
                    'ip_attempts' => 2,
                ],
            ]);
        });
    }

    protected function defineRoutes($router): void
    {
        Route::post('/login', fn (): string => 'ok')->middleware('throttle:customer_login');
        Route::post('/contact/confirm', fn (): string => 'ok')->middleware('throttle:contact_confirm');
    }

    public function test_the_ip_axis_limits_a_profile_without_identifiers(): void
    {
        $this->fromIp('203.0.113.10')->post('/contact/confirm')->assertOk();
        $this->fromIp('203.0.113.10')->post('/contact/confirm')->assertOk();

        $this->fromIp('203.0.113.10')->post('/contact/confirm')
            ->assertStatus(429)
            ->assertHeader('Retry-After');
    }

    public function test_clients_with_an_unresolvable_address_do_not_share_one_budget(): void
    {
        // A shared "unresolved" bucket turns a proxy misconfiguration into a
        // site-wide 429: the first few visitors spend the budget and everyone
        // else is locked out of login entirely.
        for ($i = 0; $i < 8; $i++) {
            $this->withServerVariables(['REMOTE_ADDR' => 'unknown'])
                ->post('/contact/confirm')
                ->assertOk();
        }
    }

    public function test_identifier_limits_still_apply_when_the_address_is_unknown(): void
    {
        // Dropping the IP axis must not leave the route unprotected: the
        // e-mail axis is what stops credential stuffing here.
        $this->withServerVariables(['REMOTE_ADDR' => 'unknown'])
            ->post('/login', ['email' => 'victim@example.test'])->assertOk();
        $this->withServerVariables(['REMOTE_ADDR' => 'unknown'])
            ->post('/login', ['email' => 'victim@example.test'])->assertOk();

        $this->withServerVariables(['REMOTE_ADDR' => 'unknown'])
            ->post('/login', ['email' => 'victim@example.test'])
            ->assertStatus(429);
    }

    public function test_a_different_address_has_its_own_budget(): void
    {
        $this->fromIp('203.0.113.10')->post('/contact/confirm')->assertOk();
        $this->fromIp('203.0.113.10')->post('/contact/confirm')->assertOk();
        $this->fromIp('203.0.113.10')->post('/contact/confirm')->assertStatus(429);

        $this->fromIp('203.0.113.11')->post('/contact/confirm')->assertOk();
    }

    public function test_the_identifier_axis_limits_before_the_ip_axis_is_reached(): void
    {
        // Two attempts on one address are fine, but not two on one e-mail.
        $this->fromIp('203.0.113.20')->post('/login', ['email' => 'victim@example.test'])->assertOk();
        $this->fromIp('203.0.113.20')->post('/login', ['email' => 'victim@example.test'])->assertOk();

        $this->fromIp('203.0.113.20')->post('/login', ['email' => 'victim@example.test'])->assertStatus(429);

        // The address still has budget left for a different account.
        $this->fromIp('203.0.113.20')->post('/login', ['email' => 'other@example.test'])->assertOk();
    }

    public function test_the_identifier_is_matched_after_trimming_and_lowercasing(): void
    {
        $this->fromIp('203.0.113.30')->post('/login', ['email' => 'victim@example.test'])->assertOk();
        $this->fromIp('203.0.113.30')->post('/login', ['email' => '  VICTIM@Example.TEST '])->assertOk();

        // Case and padding must not buy an attacker a fresh bucket.
        $this->fromIp('203.0.113.30')->post('/login', ['email' => 'Victim@Example.test'])->assertStatus(429);
    }

    public function test_a_distributed_attempt_still_hits_the_identifier_limit(): void
    {
        $this->fromIp('203.0.113.40')->post('/login', ['email' => 'victim@example.test'])->assertOk();
        $this->fromIp('198.51.100.40')->post('/login', ['email' => 'victim@example.test'])->assertOk();

        // Rotating the source address does not reset the per-account counter.
        $this->fromIp('192.0.2.40')->post('/login', ['email' => 'victim@example.test'])->assertStatus(429);
    }

    public function test_a_request_without_the_identifier_is_limited_by_ip_only(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->fromIp('203.0.113.50')->post('/login')->assertOk();
        }

        $this->fromIp('203.0.113.50')->post('/login')->assertStatus(429);
    }

    public function test_disabling_the_module_removes_every_limit(): void
    {
        config()->set('security-guard.sensitive_routes.enabled', false);

        for ($i = 0; $i < 10; $i++) {
            $this->fromIp('203.0.113.60')->post('/contact/confirm')->assertOk();
        }
    }

    public function test_the_rejection_body_is_a_fixed_string(): void
    {
        $this->fromIp('203.0.113.70')->post('/contact/confirm', ['email' => 'x@example.test']);
        $this->fromIp('203.0.113.70')->post('/contact/confirm', ['email' => 'x@example.test']);

        $response = $this->fromIp('203.0.113.70')->post('/contact/confirm', ['email' => 'x@example.test']);

        $this->assertSame('Too Many Requests', $response->getContent());
    }
}
