use std::{fs, path::Path, io::Write};

fn main() {
    // 1. Read the C header that already exists
    let hdr = fs::read_to_string("../cidrscan_core/include/cidrscan.h").unwrap();

    // 2. Dumb regex →   extern items + wrapper list
    let re = regex::Regex::new(r#"^\s*([a-zA-Z_][\w\s\*]*?)\s+(\w+)\(([^)]*)\);"#).unwrap();
    let mut out = String::from("macro_rules! expose_php {( $( fn $name:ident ( $($p:ident : $t:ty),* ) -> $r:ty ; )* )=>{$(\n    #[php_function]\n    pub fn $name($($p:$t),*) -> $r { unsafe { _ffi::$name($($p),*) } }\n)*}}\n\nmod _ffi { extern \"C\" {");
    for cap in re.captures_iter(&hdr) {
        // cap[1] = return type, cap[2] = name, cap[3] = param list
        out.push_str(&format!("\n    #[link_name = \"{0}\"] pub fn {0}({1}) -> {2};",
                              &cap[2], &cap[3], &cap[1]));
    }
    out.push_str("\n}}\n\nexpose_php!{");
    for cap in re.captures_iter(&hdr) {
        out.push_str(&format!("\n    fn {0}({1}) -> {2};",
                              &cap[2], &cap[3], &cap[1]));
    }
    out.push_str("\n}\n");

    let dst = Path::new(&std::env::var("OUT_DIR").unwrap()).join("ffi_gen.rs");
    fs::File::create(dst).unwrap().write_all(out.as_bytes()).unwrap();
}
