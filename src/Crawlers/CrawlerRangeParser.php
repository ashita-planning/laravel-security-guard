<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Crawlers;

use Apkk\LaravelSecurityGuard\Support\IpRange;
use InvalidArgumentException;
use JsonException;

/**
 * Parses and validates a published range document.
 *
 * Google's crawler file and Bing's bingbot.json share one shape: a
 * `creationTime` string and a `prefixes` array whose entries carry exactly
 * one of `ipv4Prefix` / `ipv6Prefix`. The fixture test pins that shape.
 *
 * Validation is deliberately all-or-nothing. A single entry that fails to
 * parse rejects the whole document, because a partially-understood range file
 * means either upstream changed the format or the transfer was corrupted —
 * and in both cases the safe move is to keep yesterday's known-good data,
 * not to store whatever subset happened to look right. This data decides who
 * gets crawler treatment; it is not a place for best-effort parsing.
 */
final class CrawlerRangeParser
{
    /** A range document is tens of KB; a megabyte-scale one is not one. */
    private const MAX_BODY_BYTES = 5_000_000;

    /** Google publishes a few hundred prefixes. Thousands means breakage. */
    private const MAX_PREFIXES = 5_000;

    /**
     * @return array{creation_time: string|null, v4: array<int, string>, v6: array<int, string>}
     *
     * @throws InvalidArgumentException with a fixed reason; never echoes
     *                                  document content into the message
     */
    public static function parse(string $body): array
    {
        if (strlen($body) > self::MAX_BODY_BYTES) {
            throw new InvalidArgumentException('The range document is implausibly large.');
        }

        try {
            $document = json_decode($body, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw new InvalidArgumentException('The range document is not valid JSON.');
        }

        if (! is_array($document) || ! isset($document['prefixes']) || ! is_array($document['prefixes'])) {
            throw new InvalidArgumentException('The range document has no prefixes array.');
        }

        $prefixes = $document['prefixes'];

        if ($prefixes === []) {
            // An empty list would silently un-verify every crawler; if a
            // provider genuinely publishes one, that deserves eyes, not
            // an automatic write.
            throw new InvalidArgumentException('The range document contains no prefixes.');
        }

        if (count($prefixes) > self::MAX_PREFIXES) {
            throw new InvalidArgumentException('The range document contains implausibly many prefixes.');
        }

        $v4 = [];
        $v6 = [];

        foreach ($prefixes as $index => $entry) {
            if (! is_array($entry)) {
                throw new InvalidArgumentException("Prefix entry {$index} is not an object.");
            }

            $keys = array_intersect(array_keys($entry), ['ipv4Prefix', 'ipv6Prefix']);

            if (count($keys) !== 1) {
                throw new InvalidArgumentException("Prefix entry {$index} does not carry exactly one prefix key.");
            }

            $isV4 = array_key_exists('ipv4Prefix', $entry);
            $value = $entry['ipv4Prefix'] ?? $entry['ipv6Prefix'];

            if (! is_string($value)) {
                throw new InvalidArgumentException("Prefix entry {$index} is not a string.");
            }

            $range = IpRange::parse($value);

            if ($range === null) {
                throw new InvalidArgumentException("Prefix entry {$index} does not parse as a CIDR network.");
            }

            if (! $range->wasCanonical()) {
                // Host bits in published data mean corruption or format
                // drift; masking them silently would store a different
                // network than the provider wrote.
                throw new InvalidArgumentException("Prefix entry {$index} carries host bits.");
            }

            if ($range->family() !== ($isV4 ? IpRange::FAMILY_V4 : IpRange::FAMILY_V6)) {
                throw new InvalidArgumentException("Prefix entry {$index} sits under the wrong family key.");
            }

            if ($isV4) {
                $v4[] = $range->toString();
            } else {
                $v6[] = $range->toString();
            }
        }

        $creationTime = isset($document['creationTime']) && is_string($document['creationTime'])
            ? $document['creationTime']
            : null;

        return [
            'creation_time' => $creationTime,
            'v4' => array_values(array_unique($v4)),
            'v6' => array_values(array_unique($v6)),
        ];
    }
}
