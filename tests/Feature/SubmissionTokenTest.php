<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Feature;

use Apkk\LaravelSecurityGuard\Services\SubmissionTokenService;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Store;

class SubmissionTokenTest extends TestCase
{
    private function service(): SubmissionTokenService
    {
        return $this->app->make(SubmissionTokenService::class);
    }

    private function request(): Request
    {
        $request = Request::create('/contact/confirm', 'POST');
        $request->setLaravelSession(new Store('test-session', new ArraySessionHandler(60)));

        return $request;
    }

    public function test_a_freshly_issued_token_is_accepted_once(): void
    {
        $service = $this->service();
        $request = $this->request();

        $token = $service->issue($request, 'contact');

        $this->assertTrue($service->consume($request, 'contact', $token));
    }

    public function test_a_token_cannot_be_replayed(): void
    {
        $service = $this->service();
        $request = $this->request();

        $token = $service->issue($request, 'contact');

        $this->assertTrue($service->consume($request, 'contact', $token));
        $this->assertFalse($service->consume($request, 'contact', $token));
    }

    public function test_a_missing_token_is_rejected(): void
    {
        $service = $this->service();
        $request = $this->request();

        $service->issue($request, 'contact');

        $this->assertFalse($service->consume($request, 'contact', null));
        $this->assertFalse($service->consume($request, 'contact', ''));
    }

    public function test_a_mismatched_token_is_rejected(): void
    {
        $service = $this->service();
        $request = $this->request();

        $service->issue($request, 'contact');

        $this->assertFalse($service->consume($request, 'contact', str_repeat('a', 64)));
    }

    public function test_a_failed_attempt_burns_the_stored_token(): void
    {
        $service = $this->service();
        $request = $this->request();

        $token = $service->issue($request, 'contact');

        // A wrong guess must not leave the real token available for a retry.
        $this->assertFalse($service->consume($request, 'contact', 'wrong'));
        $this->assertFalse($service->consume($request, 'contact', $token));
    }

    public function test_tokens_are_scoped_to_their_purpose(): void
    {
        $service = $this->service();
        $request = $this->request();

        $contactToken = $service->issue($request, 'contact');
        $service->issue($request, 'application');

        $this->assertFalse($service->consume($request, 'application', $contactToken));
        $this->assertTrue($service->consume($request, 'contact', $contactToken));
    }

    public function test_two_simultaneous_submissions_of_one_token_produce_one_success(): void
    {
        $service = $this->service();
        $request = $this->request();

        $token = $service->issue($request, 'contact');

        // Both requests carry the same confirmed token; the shared cache entry
        // is what makes exactly one of them win.
        $secondRequest = $this->request();
        $secondRequest->session()->put('security-guard.submission_token.contact', $token);

        $results = [
            $service->consume($request, 'contact', $token),
            $service->consume($secondRequest, 'contact', $token),
        ];

        $this->assertSame([true, false], $results);
    }

    public function test_the_token_is_long_and_unpredictable(): void
    {
        $service = $this->service();

        $first = $service->issue($this->request(), 'contact');
        $second = $service->issue($this->request(), 'contact');

        $this->assertSame(64, strlen($first));
        $this->assertNotSame($first, $second);
    }
}
