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
    private const MAX_EXCEPTION_MESSAGE_CHARS = 300;

    /** @var array<string, true> */
    private array $logged = [];

    public function __construct(
        private readonly LoggerInterface $logger,
        private readonly bool $includeExceptionMessages = true,
    ) {}

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
            $context += $this->describe($exception);
        }

        $this->logger->warning('[security-guard] '.$message, $context);
    }

    /**
     * Reduce an exception to what is safe to write to a log.
     *
     * The class name is always useful and never sensitive. The message is not
     * so reliable: a database driver puts the DSN and the bound values of the
     * failing statement into it, and a mail transport echoes credentials, so it
     * is truncated and can be turned off entirely for hosts that ship logs to a
     * third party.
     *
     * @return array<string, string>
     */
    private function describe(Throwable $exception): array
    {
        $described = ['exception_class' => $exception::class];

        if (! $this->includeExceptionMessages) {
            return $described;
        }

        $described['exception'] = mb_strimwidth(
            $exception->getMessage(),
            0,
            self::MAX_EXCEPTION_MESSAGE_CHARS,
            '…',
        );

        return $described;
    }

    public function reset(): void
    {
        $this->logged = [];
    }

    public static function make(Application $app): self
    {
        return new self(
            $app->make(LoggerInterface::class),
            (bool) $app->make('config')->get('security-guard.logging.include_exception_messages', true),
        );
    }
}
