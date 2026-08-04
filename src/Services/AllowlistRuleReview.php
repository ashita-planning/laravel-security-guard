<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Services;

use Apkk\LaravelSecurityGuard\Data\AdminAllowedIpRecord;
use Apkk\LaravelSecurityGuard\Support\IpRange;
use Illuminate\Contracts\Config\Repository as ConfigRepository;

/**
 * Explains what one stored allowlist rule actually does.
 *
 * The same findings the doctor reports, rendered per row so an operator
 * looking at the screen sees them against the rule that caused them rather
 * than in a separate command's output.
 */
class AllowlistRuleReview
{
    public const KIND_EXACT = 'Exact';

    public const KIND_CIDR = 'CIDR';

    public const KIND_INVALID = 'invalid';

    public function __construct(private readonly ConfigRepository $config) {}

    /**
     * @param  array<string, int>  $canonicalCounts  keyed by subjectType|subjectId|rule
     * @return array{kind: string, admits: string, warnings: array<int, string>}
     */
    public function review(AdminAllowedIpRecord $record, array $canonicalCounts = []): array
    {
        $range = IpRange::parse($record->ipAddress);

        if ($range === null) {
            return [
                'kind' => self::KIND_INVALID,
                'admits' => 'nothing',
                // Fails closed: this rule grants nothing, so its owner is
                // locked out rather than anyone being let in.
                'warnings' => ['Cannot be parsed. This rule matches nothing and its subject is locked out by it.'],
            ];
        }

        $canonical = $range->toString();
        $warnings = [];

        if ($canonical !== $record->ipAddress) {
            // Only reachable for rows written straight to the table; the
            // repository canonicalises everything it stores.
            $warnings[] = "Not canonical. Matching treats this as {$canonical}.";
        }

        if (! $range->wasCanonical()) {
            $warnings[] = 'Host bits were set, so this admits the whole network, not one address.';
        }

        if ($range->prefixLength() < $this->minimumPrefixFor($range->family())) {
            $warnings[] = 'Unusually wide: admits '.number_format($range->size()).' addresses.';
        }

        $key = $record->subjectType.'|'.$record->subjectId.'|'.$canonical;

        if (($canonicalCounts[$key] ?? 0) > 1) {
            $warnings[] = 'Another rule for this subject means the same thing.';
        }

        return [
            'kind' => $range->isSingleHost() ? self::KIND_EXACT : self::KIND_CIDR,
            'admits' => number_format($range->size()),
            'warnings' => $warnings,
        ];
    }

    private function minimumPrefixFor(int $family): int
    {
        $configured = (array) $this->config->get('security-guard.ip_rules.minimum_prefix', []);

        return $family === IpRange::FAMILY_V4
            ? (int) ($configured['v4'] ?? 16)
            : (int) ($configured['v6'] ?? 32);
    }
}
