use std::{env, path::PathBuf};

fn main() {
    // Determine the shared target directory
    let target_dir = env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../target"));
    let profile = env::var("PROFILE").unwrap();
    let lib_dir = target_dir.join(&profile);

    // Tell Rust to search this directory for native libraries
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    // Instruct it to link the static cidrscan_core library
    println!("cargo:rustc-link-lib=static=cidrscan_core");
    // Re-run build if core’s sources change
    println!("cargo:rerun-if-changed=../cidrscan_core/src");
}
