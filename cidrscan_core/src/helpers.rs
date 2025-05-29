//! Helper functions for Patricia tree operations

#[inline]
pub fn v4_key(addr: u32) -> u128 {
    (addr as u128) << 96
}

#[inline]
pub fn v4_plen(plen: u8) -> u8 {
    plen.saturating_add(96)
}

pub fn fnv1a_64(s: &str) -> u64 {
    use crate::constants::{FNV_OFFSET, FNV_PRIME};
    let mut h = FNV_OFFSET;
    for &b in s.as_bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[inline(always)]
pub const fn align_up(n: usize, align: usize) -> usize {
    (n + align - 1) & !(align - 1)
}

pub fn common_prefix_len(key1: u128, key2: u128, max_len: u8) -> u8 {
    if max_len == 0 {
        return 0;
    }
    let mask = if max_len == 128 {
        !0u128
    } else {
        !(!0u128 >> max_len)
    };
    let diff = (key1 & mask) ^ (key2 & mask);
    if diff == 0 {
        return max_len;
    }
    let lz = diff.leading_zeros().min(128) as u8;
    lz.min(max_len)
}

#[inline]
pub fn get_bit(key: u128, index: u8) -> u8 {
    debug_assert!(index <= 127);
    ((key >> (127 - index)) & 1) as u8
}

#[inline]
pub fn mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else if prefix_len >= 128 {
        !0u128
    } else {
        !(!0u128 >> prefix_len)
    }
}

// Canonicalise a key: zero host bits beyond `plen`.
#[inline(always)]
pub fn canonical(key: u128, plen: u8) -> u128 {
    key & mask(plen)
}

// Packs an offset and generation into a single u64 for ABA-safe pointers.
#[inline]
pub fn pack(offset: u32, gen: u32) -> u64 {
    ((gen as u64) << 32) | (offset as u64)
}

#[inline]
pub fn unpack(ptr: u64) -> (u32, u32) {
    (ptr as u32, (ptr >> 32) as u32)
}

