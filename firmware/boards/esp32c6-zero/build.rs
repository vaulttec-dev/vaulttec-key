fn main() {
    // esp-hal ships the linker scripts; linkall.x pulls in the memory map for the
    // chip selected by the esp-hal feature.
    println!("cargo:rustc-link-arg=-Tlinkall.x");
    println!("cargo:rerun-if-changed=build.rs");
}
