#![cfg_attr(windows, feature(abi_vectorcall))]
use ext_php_rs::prelude::*;

include!(concat!(env!("OUT_DIR"), "/ffi_gen.rs"));

#[php_module]
pub fn get_module(m: ModuleBuilder) -> ModuleBuilder { m }