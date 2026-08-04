<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Notifications;

use Apkk\LaravelSecurityGuard\Contracts\ErrorEventNotifierContract;
use Apkk\LaravelSecurityGuard\Contracts\SecurityEventNotifierContract;
use Apkk\LaravelSecurityGuard\Support\FailureLogger;
use Illuminate\Contracts\Container\Container;
use Throwable;

/**
 * Channel name to notifier resolution.
 *
 * `log` and `mail` ship with the package; anything else — LINE, Slack, a
 * pager — is registered by the host or an adapter package under its own name.
 */
class NotifierRegistry
{
    /** @var array<string, class-string|callable> */
    private array $securityChannels = [];

    /** @var array<string, class-string|callable> */
    private array $errorChannels = [];

    public function __construct(
        private readonly Container $container,
        private readonly FailureLogger $failureLogger,
    ) {}

    public function registerSecurityChannel(string $channel, string|callable $resolver): void
    {
        $this->securityChannels[$channel] = $resolver;
    }

    public function registerErrorChannel(string $channel, string|callable $resolver): void
    {
        $this->errorChannels[$channel] = $resolver;
    }

    public function securityNotifier(string $channel): ?SecurityEventNotifierContract
    {
        $notifier = $this->resolve($this->securityChannels[$channel] ?? null, $channel);

        return $notifier instanceof SecurityEventNotifierContract ? $notifier : null;
    }

    public function errorNotifier(string $channel): ?ErrorEventNotifierContract
    {
        $notifier = $this->resolve($this->errorChannels[$channel] ?? null, $channel);

        return $notifier instanceof ErrorEventNotifierContract ? $notifier : null;
    }

    public function hasErrorChannel(string $channel): bool
    {
        return isset($this->errorChannels[$channel]);
    }

    private function resolve(string|callable|null $resolver, string $channel): ?object
    {
        if ($resolver === null) {
            $this->failureLogger->once('Unknown notification channel configured.', null, ['channel' => $channel]);

            return null;
        }

        try {
            return is_callable($resolver)
                ? $resolver($this->container)
                : $this->container->make($resolver);
        } catch (Throwable $exception) {
            $this->failureLogger->once('Notification channel could not be resolved.', $exception, [
                'channel' => $channel,
            ]);

            return null;
        }
    }
}
