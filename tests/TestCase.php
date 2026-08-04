<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests;

use Apkk\LaravelSecurityGuard\SecurityGuardServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Orchestra\Testbench\Concerns\WithLaravelMigrations;
use Orchestra\Testbench\TestCase as BaseTestCase;
use Symfony\Component\Mailer\SentMessage;

abstract class TestCase extends BaseTestCase
{
    // Gives tests a `users` table to stand in for a host's administrator model.
    use WithLaravelMigrations;

    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [SecurityGuardServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        tap($app->make(Repository::class), function (Repository $config): void {
            // Required by the `web` group (cookie encryption) in feature tests.
            $config->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
            $config->set('database.default', 'testing');
            $config->set('database.connections.testing', $this->databaseConnectionConfig());
            $config->set('cache.default', 'array');
            $config->set('mail.default', 'array');
            $config->set('queue.default', 'sync');
        });
    }

    /**
     * SQLite in memory by default; MySQL when CI asks for it, so that the
     * migrations and repository queries are proven against a real server too.
     *
     * @return array<string, mixed>
     */
    protected function databaseConnectionConfig(): array
    {
        if (getenv('SECURITY_GUARD_TEST_DB') !== 'mysql') {
            return [
                'driver' => 'sqlite',
                'database' => ':memory:',
                'prefix' => '',
            ];
        }

        return [
            'driver' => 'mysql',
            'host' => getenv('DB_HOST') ?: '127.0.0.1',
            'port' => getenv('DB_PORT') ?: '3306',
            'database' => getenv('DB_DATABASE') ?: 'security_guard_test',
            'username' => getenv('DB_USERNAME') ?: 'root',
            'password' => getenv('DB_PASSWORD') ?: '',
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => '',
        ];
    }

    /**
     * Send a request as if it originated from a specific client address.
     */
    protected function fromIp(string $ipAddress): static
    {
        return $this->withServerVariables(['REMOTE_ADDR' => $ipAddress]);
    }

    /**
     * Messages captured by the array mail transport.
     *
     * The package sends raw text rather than Mailables, which Mail::fake()
     * does not record, so assertions read the transport directly.
     *
     * @return array<int, SentMessage>
     */
    protected function sentMails(): array
    {
        return $this->app->make('mailer')->getSymfonyTransport()->messages()->all();
    }

    /**
     * @return array<int, string>
     */
    protected function sentMailBodies(): array
    {
        return array_map(
            static fn ($sent): string => $sent->getOriginalMessage()->getTextBody() ?? '',
            $this->sentMails(),
        );
    }
}
