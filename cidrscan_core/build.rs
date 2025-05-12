fn main() {
    use std::env;
    use std::path::PathBuf;

    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = PathBuf::from(&crate_dir).join("include");
    std::fs::create_dir_all(&out_dir).expect("Failed to create include directory");

    let config = cbindgen::Config::from_file(PathBuf::from(&crate_dir).join("cbindgen.toml"))
        .expect("Failed to read cbindgen.toml");

    cbindgen::Builder::new()
        .with_config(config)
        .with_crate(&crate_dir)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_dir.join("cidrscan.h"));
}