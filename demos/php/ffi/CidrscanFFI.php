<?php
/**
 * Thin PHP wrapper around the C API exposed by cidrscan-rs.
 * Provides helpers that mimic the cidrscan_php extension API.
 */

class CidrMatch
{
    public function __construct(
        public int $key_high,
        public int $key_low,
        public int $prefix_length,
        public string $tag    ) {}

    public function getCidrString(): string
    {
        // For IPv4, check if this looks like an IPv4 address (prefix <= 32 and key_low == 0)
        if ($this->key_low == 0 && $this->prefix_length <= 32) {
            // IPv4 case - the address is in key_high, but we need to handle signed/unsigned
            $ipInt = $this->key_high;
            
            // Convert from signed 64-bit to unsigned if needed
            if ($ipInt < 0) {
                // For PHP, we need to handle the conversion differently
                // The IP is likely in the lower 32 bits, but stored as signed 64-bit
                $ipInt = ($ipInt & 0xFFFFFFFF00000000) >> 32;
                if ($ipInt == 0) {
                    // Try the full value as unsigned
                    $ipInt = $this->key_high & 0xFFFFFFFF;
                } else {
                    $ipInt = $ipInt & 0xFFFFFFFF;
                }
            } else {
                $ipInt = $ipInt & 0xFFFFFFFF;
            }
            
            // Convert to dotted decimal notation
            $a = ($ipInt >> 24) & 0xFF;
            $b = ($ipInt >> 16) & 0xFF;
            $c = ($ipInt >> 8) & 0xFF;
            $d = $ipInt & 0xFF;
            
            return sprintf('%d.%d.%d.%d/%d', $a, $b, $c, $d, $this->prefix_length);
        } else {            // IPv6 or other case - keep original format for now
            return sprintf('%d:%d/%d', $this->key_high, $this->key_low, $this->prefix_length);
        }
    }

    public function getTag(): ?string
    {
        return $this->tag === '' ? null : $this->tag;
    }
}

class CidrscanFFI
{
    /** @var \FFI|null */
    private static $ffi = null;

    /** Path to the shared library. Adjust if necessary. */
    private const LIB_NAME = '/libcidrscan_core.so';

    /** Load FFI bindings. */
    private static function ffi(): \FFI
    {
        if (self::$ffi === null) {
            $header = file_get_contents(__DIR__ . '/cidrscan.h');
            self::$ffi = \FFI::cdef($header, __DIR__ . self::LIB_NAME);
        }
        return self::$ffi;
    }

    // ──────────────── Error codes for convenience ──────────────── //
    public const SUCCESS            = 0;
    public const NOT_FOUND          = 12;

    // ─────────────────────── API helpers ──────────────────────── //

    public static function open(string $name, int $capacity): int
    {
        $ffi = self::ffi();
        $out = $ffi->new('PatriciaHandle');
        $res = $ffi->cidr_open($name, $capacity, \FFI::addr($out));
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return $out->cdata ?? $out[0];
    }

    public static function close(int $handle): bool
    {
        $ffi = self::ffi();
        $res = $ffi->cidr_close($handle);
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return true;
    }

    public static function insert(int $handle, string $cidr, int $ttl, ?string $tag = null): bool
    {
        $ffi = self::ffi();
        $tagPtr = $tag === null ? null : $tag;
        $res = $ffi->cidr_insert($handle, $cidr, $ttl, $tagPtr);
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return true;
    }

    public static function delete(int $handle, string $cidr): bool
    {
        $ffi = self::ffi();
        $res = $ffi->cidr_delete($handle, $cidr);
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return true;
    }

    public static function lookup(int $handle, string $addr): bool
    {
        $ffi = self::ffi();
        $found = $ffi->new('bool');        $res = $ffi->cidr_lookup($handle, $addr, \FFI::addr($found));
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return (bool)($found->cdata ?? $found[0]);
    }

    public static function lookupMatch(int $handle, string $addr): ?CidrMatch
    {
        $ffi = self::ffi();
        $out = $ffi->new('PatriciaMatchT');
        $res = $ffi->cidr_lookup_full($handle, $addr, \FFI::addr($out));
        if ($res === self::NOT_FOUND) {
            return null;
        }
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return new CidrMatch(
            (int)$out->key_high,
            (int)$out->key_low,
            (int)$out->plen,
            \FFI::string($out->tag)
        );
    }

    public static function availableCapacity(int $handle): int
    {
        $ffi = self::ffi();
        $out = $ffi->new('uint64_t');        $res = $ffi->cidr_available_capacity($handle, \FFI::addr($out));
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return (int)($out->cdata ?? $out[0]);
    }

    public static function flush(int $handle): bool
    {
        $ffi = self::ffi();
        $res = $ffi->cidr_flush($handle);
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return true;
    }

    public static function clear(int $handle): bool
    {
        $ffi = self::ffi();
        $res = $ffi->cidr_clear($handle);
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return true;
    }

    public static function resize(int $handle, int $newCapacity): bool
    {
        $ffi = self::ffi();
        $res = $ffi->cidr_resize($handle, $newCapacity);
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return true;
    }

    public static function forceDestroy(string $name): bool
    {
        $ffi = self::ffi();
        $res = $ffi->cidr_force_destroy($name);
        if ($res !== self::SUCCESS) {
            throw new \RuntimeException(self::strerror($res));
        }
        return true;
    }

    public static function strerror(int $code): string
    {
        $ffi = self::ffi();
        return \FFI::string($ffi->cidr_strerror($code));
    }
}