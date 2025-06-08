<?php
require_once __DIR__ . '/CidrscanFFI.php';

function cidr_open(string $name, int $capacity): int {
    return CidrscanFFI::open($name, $capacity);
}

function cidr_close(int $handle): bool {
    return CidrscanFFI::close($handle);
}

function cidr_insert(int $handle, string $cidr, int $ttl, ?string $tag): bool {
    return CidrscanFFI::insert($handle, $cidr, $ttl, $tag);
}

function cidr_delete(int $handle, string $cidr): bool {
    return CidrscanFFI::delete($handle, $cidr);
}

function cidr_lookup(int $handle, string $addr): bool {
    return CidrscanFFI::lookup($handle, $addr);
}

function cidr_lookup_full(int $handle, string $addr): ?CidrMatch {
    return CidrscanFFI::lookupMatch($handle, $addr);
}

function cidr_available_capacity(int $handle): int {
    return CidrscanFFI::availableCapacity($handle);
}

function cidr_flush(int $handle): bool {
    return CidrscanFFI::flush($handle);
}

function cidr_clear(int $handle): bool {
    return CidrscanFFI::clear($handle);
}

function cidr_resize(int $handle, int $new_capacity): bool {
    return CidrscanFFI::resize($handle, $new_capacity);
}

function cidr_error_message(int $error_code): string {
    return CidrscanFFI::strerror($error_code);
}

function cidr_force_destroy(string $name): bool {
    return CidrscanFFI::forceDestroy($name);
}