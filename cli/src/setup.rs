//! Turning a bare board into a key: flash the images built into this binary for the
//! board's folder and wait for it to answer. espflash does the talking to the ROM
//! bootloader and tells us which chip it found; that picks the board.

use std::borrow::Cow;
use std::time::{Duration, Instant};

use espflash::connection::{Connection, ResetAfterOperation, ResetBeforeOperation};
use espflash::flasher::{Flasher, SpiAttachParams};
use espflash::image_format::Segment;
use espflash::target::ProgressCallbacks;
use serialport::SerialPortType;

use crate::boards::{self, Board, Image};
use crate::device::{Device, Error, find_port, open_port, port_or_find};

/// Bit 0 of the ROM's `GET_SECURITY_INFO` flags: the Secure Boot eFuse is burned.
/// The same bit espflash reads as `SECURE_BOOT_EN`; every chip that answers the
/// command lays the flags out this way.
const SECURE_BOOT_EN: u32 = 1 << 0;

struct Progress<'a> {
    log: &'a mut dyn FnMut(&str),
    images: &'a [&'static Image],
    addr: u32,
    total: usize,
}

impl ProgressCallbacks for Progress<'_> {
    fn init(&mut self, addr: u32, total: usize) {
        self.addr = addr;
        self.total = total;
    }
    fn update(&mut self, _current: usize) {}
    fn verifying(&mut self) {}
    fn finish(&mut self, skipped: bool) {
        // `total` counts blocks, not bytes; the images know their own sizes.
        let bytes = self
            .images
            .iter()
            .find(|i| i.addr == self.addr)
            .map_or(self.total, |i| i.data.len());
        (self.log)(&format!(
            "  {:#08x}  {bytes} bytes{}",
            self.addr,
            if skipped {
                "  (already there)"
            } else {
                "  written and verified"
            }
        ));
    }
}

/// The board folder for the chip the bootloader reported: the one named, if it fits,
/// or the only one built for that chip.
fn pick_board(chip: &str, name: Option<&str>) -> Result<&'static Board, Error> {
    if let Some(name) = name {
        let b = boards::by_name(name).ok_or_else(|| {
            Error::Value(format!(
                "unknown board '{name}'; known: {}",
                boards::names()
            ))
        })?;
        if !b.chip.eq_ignore_ascii_case(chip) {
            return Err(Error::Value(format!(
                "board '{name}' is for {}, but this is an {chip}",
                b.chip
            )));
        }
        return Ok(b);
    }
    match boards::for_chip(chip).as_slice() {
        [one] => Ok(one),
        [] => Err(Error::Value(format!(
            "no board folder for chip {chip}; known: {}",
            boards::names()
        ))),
        many => {
            let names: Vec<&str> = many.iter().map(|b| b.name).collect();
            Err(Error::Value(format!(
                "several boards use {chip}: {} - pass --board",
                names.join(", ")
            )))
        }
    }
}

/// Flashes `board` (or whichever board matches the detected chip) over the port. The
/// stored secrets survive unless `erase` is set. Caller must not hold the port open.
fn flash(
    port: &str,
    board: Option<&str>,
    erase: bool,
    log: &mut dyn FnMut(&str),
) -> Result<&'static Board, Error> {
    let info = serialport::available_ports()?
        .into_iter()
        .find(|p| p.port_name == port)
        .and_then(|p| {
            if let SerialPortType::UsbPort(u) = p.port_type {
                Some(u)
            } else {
                None
            }
        })
        .ok_or_else(|| Error::Value(format!("{port} is not a USB serial port")))?;

    let serial = open_port(port, || {
        serialport::new(port, 115_200)
            .timeout(Duration::from_secs(3))
            .open_native()
    })?;
    let connection = Connection::new(
        serial,
        info,
        ResetAfterOperation::HardReset,
        ResetBeforeOperation::DefaultReset,
        115_200,
    );
    // No flasher stub: the ROM loader alone. Whether a chip with Secure Boot still
    // runs the stub is not documented for this chip family, and the one moment
    // `setup` matters most is right after the eFuse is burned, when nothing else
    // boots. The ROM path is slower by seconds and needs nothing from the chip.
    let mut flasher = Flasher::connect(connection, false, true, false, None, Some(460_800))
        .map_err(|e| Error::Value(format!("cannot talk to the bootloader: {e}")))?;

    // The bootloader says which chip this is; the board folders say what fits it.
    let chip = format!("{:?}", flasher.chip()).to_ascii_lowercase();
    let board = pick_board(&chip, board)?;
    // Which bootloader and which app image go on depends on the chip's Secure Boot
    // eFuse, and the ROM is the one to ask: the Secure Boot bootloader on a plain
    // chip would burn the eFuses itself, and that is the developer's hand only.
    let secure = flasher
        .security_info()
        .map_err(|e| Error::Value(format!("the chip did not say its security state: {e}")))?
        .flags
        & SECURE_BOOT_EN
        != 0;
    log(&format!(
        "  chip {chip}, board {}, secure boot {}",
        board.name,
        if secure { "on" } else { "off" }
    ));

    if erase {
        log("  erasing the whole flash - every secret and the PIN are gone");
        flasher
            .erase_flash()
            .map_err(|e| Error::Value(format!("erase failed: {e}")))?;
    }
    let images: Vec<&'static Image> = board.images_for(secure).collect();
    let chip_id = flasher.chip();
    let mut progress = Progress {
        log,
        images: &images,
        addr: 0,
        total: 0,
    };
    // The segment loop by hand rather than `write_bins_to_flash`: that one ends with
    // FLASH_END, which the ROM loader answers with an error once the data is written
    // (esptool skips it for the same reason: "it causes the loader to exit"). Every
    // segment is verified by MD5 as it lands; the reset below boots the board.
    let flashing = |e: espflash::Error| Error::Value(format!("flashing failed: {e}"));
    let mut target = chip_id.flash_target(SpiAttachParams::default(), false, true, false);
    let connection = flasher.connection();
    target.begin(connection).map_err(flashing)?;
    for i in &images {
        let segment = Segment {
            addr: i.addr,
            data: Cow::Borrowed(i.data),
        };
        target
            .write_segment(connection, segment, &mut progress)
            .map_err(flashing)?;
    }
    connection
        .reset_after(false, chip_id)
        .map_err(|e| Error::Value(format!("reset failed: {e}")))?;
    Ok(board)
}

/// After flashing, the board resets and its port may change number; give it a moment
/// and come back with a device that answers.
pub fn wait_for_firmware(port_hint: &str, timeout: Duration) -> Result<Device, Error> {
    let deadline = Instant::now() + timeout;
    let mut last = Error::Value("board did not come back after flashing".into());
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_secs(1));
        let port = find_port().unwrap_or_else(|| port_hint.to_string());
        let mut dev = match Device::open(Some(&port)) {
            Ok(d) => d,
            Err(e) => {
                last = e;
                continue;
            }
        };
        if dev.probe().is_some() {
            return Ok(dev);
        }
        last = Error::Value("board is up but does not answer the protocol".into());
    }
    Err(last)
}

/// The whole thing: find the board, flash, wait. Returns the answering device.
pub fn flash_new_board(
    port: Option<&str>,
    board: Option<&str>,
    erase: bool,
    log: &mut dyn FnMut(&str),
) -> Result<Device, Error> {
    let port = port_or_find(port)?;
    log(&format!("  board on {port}"));
    flash(&port, board, erase, log)?;
    let mut dev = wait_for_firmware(&port, Duration::from_secs(15))?;
    log(&format!("  running {}", dev.info()?));
    Ok(dev)
}

/// The three answers provisioning needs from a person, given differently by the
/// plain terminal and by the shell.
pub trait ProvisionUi {
    fn say(&mut self, line: &str);
    /// The board already has a PIN and maybe credentials: keep them?
    fn keep_existing(&mut self) -> bool;
    /// Asks for a new PIN and sets it.
    fn set_pin(&mut self, dev: &mut Device) -> Result<(), Error>;
    /// Asks for the existing PIN until the board unlocks.
    fn unlock(&mut self, dev: &mut Device) -> Result<(), Error>;
}

/// What `setup` does once the board answers: a re-flashed key keeps its PIN unless
/// its owner says otherwise, a new one gets a PIN right here, and one live code
/// proves the whole path. Ok(whether the self-test passed).
pub fn provision(dev: &mut Device, button: &str, ui: &mut dyn ProvisionUi) -> Result<bool, Error> {
    if dev.pin_status()?.has_pin {
        if ui.keep_existing() {
            ui.say("  keeping the existing PIN");
        } else {
            ui.say(&format!(
                "  hold {button} on the board down for five seconds to wipe it"
            ));
            dev.wipe()?;
        }
    }
    let st = dev.pin_status()?;
    if !st.has_pin {
        ui.set_pin(dev)?; // and that unlocks
    } else if !st.unlocked {
        ui.unlock(dev)?; // a kept PIN is a locked board
    }
    ui.say("  checking one live code on the device");
    crate::totp::selftest(dev, button, |line| ui.say(line))
}
