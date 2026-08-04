<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Support;

/**
 * A single address or a CIDR network, parsed once and compared on bytes.
 *
 * Storage is deliberately a canonical string in the existing `varchar(45)`
 * column rather than a new binary schema. The longest value this can produce is
 * `ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128` at 43 characters, so v0.1.x
 * rows need no migration and the unique constraint keeps working.
 *
 * `/32` and `/128` are dropped on the way in, so `203.0.113.10` and
 * `203.0.113.10/32` are the same stored rule rather than two rows that both
 * match and neither of which is obviously redundant.
 *
 * Families never cross. An IPv4 rule cannot match an IPv6 address even when
 * that address is IPv4-mapped (`::ffff:203.0.113.10`), because an operator
 * allowlisting `203.0.113.0/24` has not agreed to admit a v6 client that
 * happens to encode the same digits.
 */
final class IpRange
{
    public const FAMILY_V4 = 4;

    public const FAMILY_V6 = 6;

    private const MAX_PREFIX = [self::FAMILY_V4 => 32, self::FAMILY_V6 => 128];

    private function __construct(
        private readonly string $network,
        private readonly int $prefixLength,
        private readonly int $family,
        private readonly bool $canonical,
    ) {}

    /**
     * Parse an allowlist entry. Returns null for anything unusable.
     *
     * An entry whose host bits are set (`203.0.113.10/24`) still parses — it is
     * masked down to its network — but reports `wasCanonical() === false` so the
     * doctor can point out that the written form is wider than it looks.
     */
    public static function parse(string $entry): ?self
    {
        $entry = trim($entry);

        if ($entry === '') {
            return null;
        }

        $slashes = substr_count($entry, '/');

        if ($slashes === 0) {
            return self::singleHost($entry);
        }

        if ($slashes > 1) {
            return null;
        }

        [$address, $prefix] = explode('/', $entry, 2);

        // Reject "/08" and "/ 24": a silently reinterpreted prefix is worse
        // than a rejected one when the result is an access rule.
        if (preg_match('/^(0|[1-9][0-9]*)$/', $prefix) !== 1) {
            return null;
        }

        $packed = self::pack($address);

        if ($packed === null) {
            return null;
        }

        $family = strlen($packed) === 4 ? self::FAMILY_V4 : self::FAMILY_V6;
        $prefixLength = (int) $prefix;

        if ($prefixLength > self::MAX_PREFIX[$family]) {
            return null;
        }

        $masked = self::applyMask($packed, $prefixLength);
        $network = (string) inet_ntop($masked);

        return new self(
            $network,
            $prefixLength,
            $family,
            $masked === $packed,
        );
    }

    /**
     * Does this rule admit the given address?
     */
    public function contains(string $ipAddress): bool
    {
        $packed = self::pack($ipAddress);

        if ($packed === null) {
            return false;
        }

        $candidateFamily = strlen($packed) === 4 ? self::FAMILY_V4 : self::FAMILY_V6;

        if ($candidateFamily !== $this->family) {
            return false;
        }

        $networkPacked = self::pack($this->network);

        if ($networkPacked === null) {
            return false;
        }

        return self::applyMask($packed, $this->prefixLength) === $networkPacked;
    }

    /**
     * The form stored in the database and shown in listings.
     */
    public function toString(): string
    {
        return $this->isSingleHost()
            ? $this->network
            : $this->network.'/'.$this->prefixLength;
    }

    public function isSingleHost(): bool
    {
        return $this->prefixLength === self::MAX_PREFIX[$this->family];
    }

    public function family(): int
    {
        return $this->family;
    }

    public function prefixLength(): int
    {
        return $this->prefixLength;
    }

    public function network(): string
    {
        return $this->network;
    }

    /**
     * False when the entry carried host bits, e.g. `203.0.113.10/24`.
     */
    public function wasCanonical(): bool
    {
        return $this->canonical;
    }

    /**
     * How many addresses this rule admits, as a float because a v6 range
     * overflows int. Used to flag rules that are wider than intended.
     */
    public function size(): float
    {
        return 2 ** (self::MAX_PREFIX[$this->family] - $this->prefixLength);
    }

    public function equals(self $other): bool
    {
        return $this->toString() === $other->toString();
    }

    private static function singleHost(string $address): ?self
    {
        $packed = self::pack($address);

        if ($packed === null) {
            return null;
        }

        $family = strlen($packed) === 4 ? self::FAMILY_V4 : self::FAMILY_V6;

        return new self(
            (string) inet_ntop($packed),
            self::MAX_PREFIX[$family],
            $family,
            true,
        );
    }

    private static function pack(string $address): ?string
    {
        $address = trim($address);

        if ($address === '' || filter_var($address, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $packed = @inet_pton($address);

        return $packed === false ? null : $packed;
    }

    /**
     * Zero every bit after the prefix.
     */
    private static function applyMask(string $packed, int $prefixLength): string
    {
        $bytes = strlen($packed);

        for ($index = 0; $index < $bytes; $index++) {
            $bitOffset = $index * 8;

            if ($bitOffset >= $prefixLength) {
                $packed[$index] = "\0";

                continue;
            }

            $remaining = $prefixLength - $bitOffset;

            if ($remaining < 8) {
                $mask = (0xFF << (8 - $remaining)) & 0xFF;
                $packed[$index] = chr(ord($packed[$index]) & $mask);
            }
        }

        return $packed;
    }
}
