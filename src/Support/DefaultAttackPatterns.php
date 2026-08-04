<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Support;

/**
 * Known attack path patterns shipped with the package.
 *
 * Host applications extend, replace or disable categories through
 * `security-guard.permanent_block.attack_patterns`.
 */
final class DefaultAttackPatterns
{
    /**
     * @return array<string, array{exact?: array<int, string>, prefix?: array<int, string>, regex?: array<int, string>}>
     */
    public static function all(): array
    {
        return [
            'wordpress_probe' => [
                'exact' => ['xmlrpc.php', 'wp-admin', 'wp-content', 'wp-includes', 'wp-login.php'],
                'prefix' => ['wp-admin/', 'wp-content/', 'wp-includes/'],
                'regex' => [
                    '#(^|/)wp-(admin|content|includes)(/|$)#',
                    '#(^|/)wp-[^/]+\.php$#',
                ],
            ],
            'secret_file_probe' => [
                'exact' => [
                    '.env',
                    '.env.backup',
                    '.env.local',
                    '.env.production',
                    '.git/config',
                    '.git/head',
                    '.aws/credentials',
                    '.ssh/id_rsa',
                ],
                'prefix' => ['.git/'],
                'regex' => [
                    '#(^|/)\.env(?:\.[^/]*)?$#',
                    '#(^|/)\.git/(config|head)$#',
                ],
            ],
            'database_admin_probe' => [
                'exact' => ['adminer.php', 'phpmyadmin', 'pma'],
                'prefix' => ['phpmyadmin/', 'pma/'],
                'regex' => [
                    '#(^|/)(phpmyadmin|pma)(/|$)#',
                    '#(^|/)adminer(?:-[0-9.]+)?\.php$#',
                ],
            ],
            'phpunit_probe' => [
                'exact' => [
                    'vendor/phpunit/phpunit/src/util/php/eval-stdin.php',
                    'phpunit/phpunit/src/util/php/eval-stdin.php',
                ],
                'regex' => ['#(^|/)vendor/phpunit/phpunit/src/util/php/eval-stdin\.php$#'],
            ],
            'server_probe' => [
                'exact' => [
                    'server-status',
                    'server-info',
                    'actuator/env',
                    'actuator/heapdump',
                    'boaform/admin/formlogin',
                    'cgi-bin',
                    'solr/admin',
                ],
                'prefix' => ['cgi-bin/', 'solr/admin/'],
            ],
        ];
    }
}
