#![cfg_attr(windows, feature(abi_vectorcall))]

use cidrscan_core::types::PatriciaTree;
use ext_php_rs::{exception::PhpException, prelude::*};
use ipnetwork::IpNetwork;
use std::sync::Arc;

mod helpers {
    use super::*;
    pub fn parse_cidr(input: &str) -> PhpResult<(u128, u8)> {
        let net: IpNetwork = input
            .parse()
            .map_err(|_| PhpException::from("Invalid CIDR"))?;
        let key = match net.network() {
            std::net::IpAddr::V4(addr) => u32::from(addr) as u128,
            std::net::IpAddr::V6(addr) => u128::from(addr),
        };
        Ok((key, net.prefix()))
    }
}

#[php_class(name = "TheRealMkadmi\\Citadel\\CidrScan\\CidrScan")]
#[derive(Clone)]
pub struct CidrScan {
    inner: Arc<PatriciaTree>,
}

#[php_impl]
impl CidrScan {
    /// Open or create a shared-memory tree.
    #[constructor]
    pub fn __construct(name: &str, capacity: i64) -> PhpResult<Self> {
        PatriciaTree::open(name, capacity as usize)
            .map(|t| Self { inner: Arc::new(t) })
            .map_err(|e| PhpException::from(format!("Failed to open PatriciaTree: {}", e)))
    }

    /// Insert any CIDR (`1.2.3.0/24`, `2001:db8::/32`, …).
    /// TTL = 0 means “never expire”.
    pub fn insert(&self, cidr: &str, ttl: i64, tag: Option<String>) -> PhpResult<bool> {
        let (key, plen) = helpers::parse_cidr(cidr)?;
        self.inner
            .insert(key, plen, ttl as u64, tag.as_deref())
            .map(|_| true)
            .map_err(|e| PhpException::from(format!("Insert error: {}", e)))
    }

    /// Remove an exact stored prefix.
    pub fn delete(&self, cidr: &str) -> PhpResult<bool> {
        let (key, plen) = helpers::parse_cidr(cidr)?;
        self.inner
            .delete(key, plen)
            .map(|_| true)
            .map_err(|e| PhpException::from(format!("Delete error: {}", e)))
    }

    /// Point look-up. Returns `null` on miss / expired.
    pub fn lookup(&self, ip: &str) -> PhpResult<Option<LookupResult>> {
        let ip = ip
            .parse::<IpNetwork>()
            .map_err(|_| PhpException::from("Invalid IP"))?; // accepts v4 & v6 host notation
        let key = match ip.ip() {
            std::net::IpAddr::V4(addr) => u32::from(addr) as u128,
            std::net::IpAddr::V6(addr) => u128::from(addr),
        };
        Ok(self.inner.lookup(key).map(|m| {
            LookupResult::new(
                format!("{}/{}", m.cidr_key, m.plen), // canonical string
                m.tag.to_string(),
            )
        }))
    }

    /// Flush epoch-reclaimed nodes.
    pub fn flush(&self) {
        self.inner.flush();
    }

    /// Resize in-place; new capacity > current.
    pub fn resize(&mut self, new_capacity: i64) -> PhpResult<bool> {
        Arc::get_mut(&mut self.inner)
            .ok_or_else(|| PhpException::from("Cannot resize: still referenced"))?
            .resize(new_capacity as usize)
            .map(|_| true)
            .map_err(|e| PhpException::from(format!("Resize error: {}", e)))
    }

    /// Free + recycled nodes left.
    #[php(getter)]
    pub fn available_capacity(&self) -> i64 {
        self.inner.available_capacity() as i64
    }
}

#[php_class(name = "TheRealMkadmi\\Citadel\\CidrScan\\LookupResult")]
pub struct LookupResult {
    #[prop]
    cidr: String,
    #[prop]
    tag: String,
}

impl LookupResult {
    pub fn new(cidr: String, tag: String) -> Self {
        Self { cidr, tag }
    }
}

#[php_module]
pub fn get_module(module: ModuleBuilder) -> ModuleBuilder {
    module
}
