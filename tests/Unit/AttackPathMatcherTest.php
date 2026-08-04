<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Contracts\AttackPathMatcherContract;
use Apkk\LaravelSecurityGuard\Data\AttackMatch;
use Apkk\LaravelSecurityGuard\Tests\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

class AttackPathMatcherTest extends TestCase
{
    private function matcher(): AttackPathMatcherContract
    {
        return $this->app->make(AttackPathMatcherContract::class);
    }

    #[DataProvider('attackPaths')]
    public function test_it_detects_known_attack_paths(string $path, string $expectedCategory): void
    {
        $match = $this->matcher()->match($path);

        $this->assertNotNull($match, "Expected {$path} to match.");
        $this->assertSame($expectedCategory, $match->category);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function attackPaths(): array
    {
        return [
            'wordpress exact' => ['wp-admin', 'wordpress_probe'],
            'wordpress nested' => ['wp-admin/setup-config.php', 'wordpress_probe'],
            'wordpress xmlrpc' => ['xmlrpc.php', 'wordpress_probe'],
            'env file' => ['.env', 'secret_file_probe'],
            'env variant' => ['.env.production', 'secret_file_probe'],
            'git config' => ['.git/config', 'secret_file_probe'],
            'phpmyadmin' => ['phpmyadmin/index.php', 'database_admin_probe'],
            'adminer' => ['adminer.php', 'database_admin_probe'],
            'phpunit eval stdin' => ['vendor/phpunit/phpunit/src/util/php/eval-stdin.php', 'phpunit_probe'],
            'server status' => ['server-status', 'server_probe'],
            'cgi-bin' => ['cgi-bin/test.cgi', 'server_probe'],
        ];
    }

    #[DataProvider('evasionAttempts')]
    public function test_it_sees_through_encoding_and_separator_tricks(string $path): void
    {
        $this->assertNotNull($this->matcher()->match($path), "Expected {$path} to match.");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function evasionAttempts(): array
    {
        return [
            'uppercase' => ['WP-ADMIN'],
            'mixed case' => ['Wp-Admin/Setup-Config.php'],
            'leading slash' => ['/wp-admin'],
            'trailing slash' => ['wp-admin/'],
            'duplicate slashes' => ['wp-admin//setup-config.php'],
            'backslashes' => ['wp-admin\\setup-config.php'],
            'null byte' => ["wp-admin\0"],
            'single percent encoding' => ['%77p-admin'],
            'double percent encoding' => ['%2577p-admin'],
            'encoded separator' => ['.git%2Fconfig'],
        ];
    }

    #[DataProvider('benignPaths')]
    public function test_it_ignores_legitimate_paths(string $path): void
    {
        $this->assertNull($this->matcher()->match($path), "Expected {$path} not to match.");
    }

    /**
     * @return array<string, array{string}>
     */
    public static function benignPaths(): array
    {
        return [
            'root' => [''],
            'home' => ['/'],
            'products' => ['products/1234'],
            'contains but does not start with wp' => ['news/swp-administration'],
            'environment word in a page' => ['about/environment'],
            'admin panel of the host' => ['admin-panel/login'],
        ];
    }

    public function test_triple_encoding_is_not_decoded(): void
    {
        // Decoding is capped at two passes on purpose; a third layer stays encoded
        // rather than inviting unbounded decode work on every request.
        $this->assertNull($this->matcher()->match('%252577p-admin'));
    }

    public function test_a_category_can_be_disabled_by_the_host(): void
    {
        config()->set('security-guard.permanent_block.attack_patterns', [
            'wordpress_probe' => false,
        ]);

        $this->assertNull($this->matcher()->match('wp-admin'));
        $this->assertNotNull($this->matcher()->match('.env'));
    }

    public function test_a_host_can_add_its_own_category(): void
    {
        config()->set('security-guard.permanent_block.attack_patterns', [
            'custom_probe' => ['exact' => ['legacy/install.php']],
        ]);

        $match = $this->matcher()->match('legacy/install.php');

        $this->assertNotNull($match);
        $this->assertSame('custom_probe', $match->category);
        $this->assertSame(AttackMatch::TYPE_EXACT, $match->type);
    }

    public function test_an_invalid_regex_is_skipped_instead_of_raising(): void
    {
        config()->set('security-guard.permanent_block.use_default_patterns', false);
        config()->set('security-guard.permanent_block.attack_patterns', [
            'broken' => ['regex' => ['#(unclosed#']],
            'valid' => ['exact' => ['danger.php']],
        ]);

        // A typo in one host-supplied pattern must not turn every request into a 500.
        $this->assertNull($this->matcher()->match('anything'));
        $this->assertNotNull($this->matcher()->match('danger.php'));
    }

    public function test_query_strings_are_not_part_of_the_decision(): void
    {
        // The middleware passes Request::path(), which excludes the query, and
        // the matcher must not compensate by matching one that is handed in.
        $this->assertNull($this->matcher()->match('products?file=.env'));
    }
}
