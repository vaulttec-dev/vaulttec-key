//! Every folder under firmware/boards with a board.toml becomes a board the CLI knows:
//! its chip, its USB identity, and the images `vkey setup` flashes, embedded into
//! the binary. Adding a board is adding a folder; nothing here is edited.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let boards_dir = manifest.join("../firmware/boards");
    println!("cargo:rerun-if-changed={}", boards_dir.display());

    let mut dirs: Vec<PathBuf> = fs::read_dir(&boards_dir)
        .unwrap_or_else(|e| panic!("{}: {e}", boards_dir.display()))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.join("board.toml").is_file())
        .collect();
    dirs.sort();
    assert!(
        !dirs.is_empty(),
        "no board folders with a board.toml under firmware/boards"
    );

    let mut out = String::from("pub static BOARDS: &[Board] = &[\n");
    for dir in dirs {
        let toml_path = dir.join("board.toml");
        println!("cargo:rerun-if-changed={}", toml_path.display());
        let text = fs::read_to_string(&toml_path).expect("board.toml is readable");
        let t: toml::Table = text
            .parse()
            .unwrap_or_else(|e| panic!("{}: {e}", toml_path.display()));
        let missing = |k: &str| -> ! { panic!("{}: missing `{k}`", toml_path.display()) };
        let string = |k: &str| {
            t.get(k)
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| missing(k))
                .to_string()
        };
        let int = |k: &str| {
            t.get(k)
                .and_then(toml::Value::as_integer)
                .unwrap_or_else(|| missing(k))
        };

        let mut images = String::new();
        let list = t
            .get("image")
            .and_then(toml::Value::as_array)
            .unwrap_or_else(|| missing("[[image]]"));
        for img in list {
            let offset = img
                .get("offset")
                .and_then(toml::Value::as_integer)
                .unwrap_or_else(|| missing("image.offset"));
            let rel = img
                .get("file")
                .and_then(toml::Value::as_str)
                .unwrap_or_else(|| missing("image.file"));
            let secure_boot = match img.get("secure_boot") {
                None => "None".to_string(),
                Some(v) => format!(
                    "Some({})",
                    v.as_bool().unwrap_or_else(|| panic!(
                        "{}: image.secure_boot is not a bool",
                        toml_path.display()
                    ))
                ),
            };
            let file = dir.join(rel);
            println!("cargo:rerun-if-changed={}", file.display());
            let abs = file.canonicalize().unwrap_or_else(|e| {
                panic!(
                    "{}: {e} (tools/build-vaultkey.sh builds vaultkey.bin, \
                     tools/build-bootloader.sh the bootloaders, tools/sign-vaultkey.sh the signed ones)",
                    file.display()
                )
            });
            write!(
                images,
                "Image {{ addr: {offset:#x}, data: include_bytes!({:?}), secure_boot: {secure_boot} }}, ",
                abs.display().to_string()
            )
            .expect("writing to a String cannot fail");
        }
        writeln!(
            out,
            "    Board {{ name: {:?}, chip: {:?}, button: {:?}, usb_vid: {:#x}, usb_pid: {:#x}, images: &[{images}] }},",
            string("name"),
            string("chip"),
            string("button"),
            int("usb_vid"),
            int("usb_pid")
        )
        .expect("writing to a String cannot fail");
    }
    out.push_str("];\n");

    let dest = Path::new(&env::var("OUT_DIR").expect("OUT_DIR")).join("boards.rs");
    fs::write(&dest, out).expect("write boards.rs");
}
