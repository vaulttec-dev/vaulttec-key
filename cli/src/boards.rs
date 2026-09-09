//! The boards this binary can set up: generated at build time from every
//! firmware/boards/*/board.toml, images included. No chip is named in code.

pub struct Board {
    pub name: &'static str,
    /// As espflash names the chip, e.g. "esp32c6".
    pub chip: &'static str,
    /// What is printed on the button the user is told to press.
    pub button: &'static str,
    pub usb_vid: u16,
    pub usb_pid: u16,
    /// Everything `setup` may write, in flash order.
    pub images: &'static [Image],
}

/// One file to flash. `secure_boot` says which chips it is for: `Some(true)` only
/// where the Secure Boot eFuse is burned, `Some(false)` only where it is not, `None`
/// for both. The two kinds of bootloader and of app image share an offset and are
/// told apart by this alone.
pub struct Image {
    pub addr: u32,
    pub data: &'static [u8],
    pub secure_boot: Option<bool>,
}

impl Board {
    /// The images for a chip whose Secure Boot state is `secure`.
    pub fn images_for(&self, secure: bool) -> impl Iterator<Item = &'static Image> {
        self.images
            .iter()
            .filter(move |i| i.secure_boot.is_none_or(|s| s == secure))
    }
}

include!(concat!(env!("OUT_DIR"), "/boards.rs"));

pub fn by_name(name: &str) -> Option<&'static Board> {
    BOARDS.iter().find(|b| b.name.eq_ignore_ascii_case(name))
}

/// Boards built for a chip, as detected by the bootloader handshake.
pub fn for_chip(chip: &str) -> Vec<&'static Board> {
    BOARDS
        .iter()
        .filter(|b| b.chip.eq_ignore_ascii_case(chip))
        .collect()
}

pub fn names() -> String {
    BOARDS.iter().map(|b| b.name).collect::<Vec<_>>().join(", ")
}

/// How to name the button to someone looking at the board, given what INFO answered
/// (it ends with the board's folder name). A board this binary does not know gets the
/// vague version rather than a wrong label.
pub fn button(version: Option<&str>) -> String {
    match version.and_then(|v| v.rsplit(' ').next()).and_then(by_name) {
        Some(b) => format!("the {} button", b.button),
        None => "the button".to_string(),
    }
}
