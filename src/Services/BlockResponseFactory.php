<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Symfony\Component\HttpFoundation\Response;

/**
 * Builds the rejection responses.
 *
 * The body is always a configured constant. No part of the request — path,
 * query, header or IP — is reflected back, so the response cannot be turned
 * into an echo primitive or a probe oracle.
 */
class BlockResponseFactory
{
    public function __construct(private readonly ConfigRepository $config) {}

    public function blocked(): Response
    {
        $status = (int) $this->config->get('security-guard.permanent_block.response_status', 403);
        $body = (string) $this->config->get('security-guard.permanent_block.response_body', 'Forbidden');

        return new Response(
            $body,
            $this->isValidStatus($status) ? $status : 403,
            ['Content-Type' => 'text/plain; charset=UTF-8'],
        );
    }

    public function tooManyRequests(int $retryAfter = 0): Response
    {
        $headers = ['Content-Type' => 'text/plain; charset=UTF-8'];

        if ($retryAfter > 0) {
            $headers['Retry-After'] = (string) $retryAfter;
        }

        return new Response('Too Many Requests', Response::HTTP_TOO_MANY_REQUESTS, $headers);
    }

    /**
     * For crawler overload, where a host prefers 503 to 429.
     *
     * Retry-After is mandatory here rather than optional: telling a crawler
     * to back off without saying for how long tells it nothing it can act on.
     */
    public function serviceUnavailable(int $retryAfter): Response
    {
        return new Response('Service Unavailable', Response::HTTP_SERVICE_UNAVAILABLE, [
            'Content-Type' => 'text/plain; charset=UTF-8',
            'Retry-After' => (string) max(1, $retryAfter),
        ]);
    }

    private function isValidStatus(int $status): bool
    {
        return $status >= 400 && $status <= 599;
    }
}
