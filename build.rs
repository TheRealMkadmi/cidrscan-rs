fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let target_triple = std::env::var("TARGET").unwrap_or_else(|_| "".to_string());
    let host_target = std::env::var("HOST").unwrap_or_default();
    let is_cross = !target_triple.is_empty() && target_triple != host_target && !host_target.is_empty();

    // Determine output directory path
    let out_dir = if is_cross {
        std::path::Path::new(&target)
            .join(&target_triple)
            .join(&profile)
    } else {
        std::path::Path::new(&target)
            .join(&profile)
    };

    // Ensure the output directory exists
    std::fs::create_dir_all(&out_dir).expect("Failed to create output directory for headers");

    // Generate minimal FFI header with just method definitions
    let ffi_header_path = out_dir.join("cidrscan_ffi.h");
    cbindgen::generate(&crate_dir)
        .expect("Unable to generate FFI bindings")
        .write_to_file(&ffi_header_path);
    
    // Generate full featured header with C++ compat macros and include guards
    let full_header_path = out_dir.join("cidrscan.h");
    let mut config = cbindgen::Config::from_file(format!("{}/cbindgen.toml", crate_dir))
        .expect("Unable to load cbindgen.toml");
    
    // Modify config for the full header
    config.language = cbindgen::Language::C;
    config.include_guard = Some("CIDRSCAN_H".to_string());
    config.sys_includes = vec!["stdint.h".to_string(), "stdbool.h".to_string()];
    config.no_includes = false;
    config.cpp_compat = true;
    config.pragma_once = true;
    
    // Generate the full featured header
    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_config(config)
        .generate()
        .expect("Unable to generate full bindings")
        .write_to_file(&full_header_path);

    println!("cargo:warning=FFI Header generated at {}", ffi_header_path.display());
    println!("cargo:warning=Full Header generated at {}", full_header_path.display());
}