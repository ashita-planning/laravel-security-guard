<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Support;

use Illuminate\Contracts\Foundation\Application;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * Degraded-mode logging.
 *
 * A cache or database outage happens on every request, not once, so the same
 * cause is logged a single time per process. The exception message is included
 * because it comes from infrastructure, never from request input.
 */
class FailureLogger
{
    /** @var array<string, true> */
    private array $logged = [];

    public function __construct(private readonly LoggerInterface $logger) {}

    /**
     * @param  array<string, mixed>  $context
     */
    public function once(string $message, ?Throwable $exception = null, array $context = []): void
    {
        if (isset($this->logged[$message])) {
            return;
        }

        $this->logged[$message] = true;
        $this->always($message, $exception, $context);
    }

    /**
     * @param  array<string, mixed>  $context
     */
    public function always(string $message, ?Throwable $exception = null, array $context = []): void
    {
        if ($exception !== null) {
            $context['exception'] = $exception->getMessage();
        }

        $this->logger->warning('[security-guard] '.$message, $context);
    }

    public function reset(): void
    {
        $this->logged = [];
    }

    public static function make(Application $app): self
    {
        return new self($app->make(LoggerInterface::class));
    }
}
