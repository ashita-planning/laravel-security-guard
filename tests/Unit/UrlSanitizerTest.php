<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Tests\Unit;

use Apkk\LaravelSecurityGuard\Support\UrlSanitizer;
use PHPUnit\Framework\TestCase;

class UrlSanitizerTest extends TestCase
{
    public function test_it_masks_sensitive_query_values(): void
    {
        $sanitized = UrlSanitizer::sanitize(
            'https://example.test/reset?token=abc123&email=user@example.test',
            ['token'],
            255,
        );

        $this->assertSame(
            'https://example.test/reset?token=[FILTERED]&email=user@example.test',
            $sanitized,
        );
    }

    public function test_masking_is_case_insensitive_on_the_key(): void
    {
        $this->assertSame(
            'https://example.test/x?API_KEY=[FILTERED]',
            UrlSanitizer::sanitize('https://example.test/x?API_KEY=live-key', ['api_key'], 255),
        );
    }

    public function test_it_leaves_a_url_without_a_query_untouched(): void
    {
        $this->assertSame(
            'https://example.test/products/1',
            UrlSanitizer::sanitize('https://example.test/products/1', ['token'], 255),
        );
    }

    public function test_it_truncates_to_the_byte_budget(): void
    {
        $url = 'https://example.test/'.str_repeat('a', 400);

        $this->assertSame(255, strlen(UrlSanitizer::sanitize($url, [], 255)));
    }

    public function test_truncation_never_leaves_a_broken_multibyte_character(): void
    {
        // 21 ASCII bytes + 3-byte characters; cutting at 25 lands mid-character.
        $url = 'https://example.test/'.str_repeat('あ', 20);

        $truncated = UrlSanitizer::sanitize($url, [], 25);

        $this->assertLessThanOrEqual(25, strlen($truncated));
        $this->assertTrue(mb_check_encoding($truncated, 'UTF-8'));
        $this->assertSame('https://example.test/あ', $truncated);
    }
}
