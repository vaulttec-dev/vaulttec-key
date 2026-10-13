use std::path::PathBuf;
use std::{env, fs};

fn main() {
    // cortex-m-rt's link.x includes memory.x; this puts the board's copy where the
    // linker looks for it.
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    fs::write(out.join("memory.x"), include_bytes!("memory.x")).expect("OUT_DIR is writable");
    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rustc-link-arg=-Tlink.x");
    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=build.rs");
}
