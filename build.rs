fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_triple = std::env::var("TARGET").unwrap_or_else(|_| "".to_string());
    let host_target = std::env::var("HOST").unwrap_or_default();
    let is_cross = !target_triple.is_empty() && target_triple != host_target && !host_target.is_empty();

    // Place .h file exactly where the shared library goes
    let out_path = if is_cross {
        std::path::Path::new(&target)
            .join(&target_triple)
            .join(&profile)
            .join("cidrscan.h")
    } else {
        std::path::Path::new(&target)
            .join(&profile)
            .join("cidrscan.h")
    };

    // Ensure the output directory exists
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create output directory for header");
    }

    cbindgen::generate(&crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file(&out_path);

    println!("cargo:warning=Header generated at {}", out_path.display());
}