<?php

declare(strict_types=1);

namespace Apkk\LaravelSecurityGuard\Data;

/**
 * The outcome of a block write, including whether this caller is the one that
 * actually transitioned the address into a blocked state.
 *
 * `isNewBlock` must be decided by the storage layer, not by a read performed
 * beforehand: with a check-then-write, two workers racing on the same address
 * both read "not blocked" and both announce a new block. Here the database
 * decides, so exactly one caller sees `true`.
 */
final class BlockOperationResult
{
    public function __construct(
        public readonly BlockedIpRecord $record,
        public readonly bool $isNewBlock,
    ) {}
}
