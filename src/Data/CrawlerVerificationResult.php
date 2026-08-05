<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

/**
 * The outcome of classifying one request against the known search crawlers.
 *
 * Three states, because two would force a lie somewhere:
 *
 *  - `verified`   — the User-Agent claims a known crawler AND the client
 *    address sits inside that provider's published ranges. Only this state may
 *    ever receive crawler treatment.
 *  - `unverified` — the User-Agent claims a known crawler but the address
 *    could not be confirmed. This is NOT an accusation: DNS trouble, a stale
 *    range list or an empty cache all land here, so the only safe consequence
 *    is the normal public policy — neither crawler privileges nor punishment.
 *  - `unknown`    — the request does not claim to be a crawler at all.
 *
 * A User-Agent string on its own never produces `verified`. Both Google and
 * Bing document their UA as spoofable; the UA is candidate extraction only,
 * and the decision belongs to the published address data.
 */
final class CrawlerVerificationResult
{
    public const VERIFIED = 'verified';

    public const UNVERIFIED = 'unverified';

    public const UNKNOWN = 'unknown';

    /** The address sits inside the provider's published ranges. */
    public const REASON_ADDRESS_IN_PUBLISHED_RANGE = 'address_in_published_range';

    /** The address is provably outside every published range. */
    public const REASON_ADDRESS_OUTSIDE_PUBLISHED_RANGES = 'address_outside_published_ranges';

    /** No usable range data: never fetched, expired, or unreadable. */
    public const REASON_NO_RANGE_DATA = 'no_range_data';

    /** The client address itself could not be resolved. */
    public const REASON_UNRESOLVED_CLIENT_ADDRESS = 'unresolved_client_address';

    /**
     * @param  self::VERIFIED|self::UNVERIFIED|self::UNKNOWN  $state
     */
    private function __construct(
        public readonly string $state,
        public readonly ?string $provider,
        public readonly ?string $reason,
    ) {}

    public static function verified(string $provider): self
    {
        return new self(self::VERIFIED, $provider, self::REASON_ADDRESS_IN_PUBLISHED_RANGE);
    }

    /**
     * @param  string  $reason  One of the REASON_* constants — a fixed code,
     *                          never free text, because this reaches logs.
     */
    public static function unverified(string $provider, string $reason): self
    {
        return new self(self::UNVERIFIED, $provider, $reason);
    }

    public static function unknown(): self
    {
        return new self(self::UNKNOWN, null, null);
    }

    public function isVerified(): bool
    {
        return $this->state === self::VERIFIED;
    }

    /**
     * Did the request claim to be a crawler, whether or not that held up?
     */
    public function claimsToBeACrawler(): bool
    {
        return $this->state !== self::UNKNOWN;
    }

    /**
     * @return array<string, string>
     */
    public function toArray(): array
    {
        return [
            'state' => $this->state,
            'provider' => $this->provider ?? '',
            'reason' => $this->reason ?? '',
        ];
    }
}
