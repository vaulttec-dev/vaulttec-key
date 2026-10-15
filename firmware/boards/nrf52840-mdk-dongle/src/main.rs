//! Makerdiary nRF52840 MDK USB Dongle: the board-specific half of the key. Pins, chip
//! crates, flash layout - and nothing else. The key itself is `vaultkey_core`; this file
//! only hands it the hardware through the traits in `vaultkey_core::hal`.
//!
//! Runs on the board: `vkey check --wipe-everything` passed on 2026-10-13, flashed
//! through the factory UF2 bootloader, which sits at 0xF4000 behind Nordic's MBR at 0x0
//! (docs/makerdiary.md).

#![no_std]
#![no_main]

mod fido;

use core::cell::{Cell, RefCell};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering, compiler_fence};

use cortex_m::peripheral::SCB;
use cortex_m::peripheral::syst::SystClkSource;
use cortex_m_rt::{entry, exception};
use critical_section::Mutex;
use ctaphid_dispatch::app::App;
use ctaphid_dispatch::{Channel, Dispatch};
use embedded_hal::digital::{InputPin, OutputPin};
use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
use nrf52840_hal::clocks::{Clocks, ExternalOscillator, Internal, LfOscStopped};
use nrf52840_hal::gpio::{Input, Level, Output, Pin, PullUp, PushPull, p0};
use nrf52840_hal::nvmc::{Nvmc, NvmcError};
use nrf52840_hal::pac;
use nrf52840_hal::rng::Rng;
use nrf52840_hal::usbd::{UsbPeripheral, Usbd};
use ref_swap::OptionRefSwap;
use static_cell::{ConstStaticCell, StaticCell};
use trussed_core::InterruptFlag;
use usb_device::UsbError;
use usb_device::bus::UsbBusAllocator;
use usb_device::device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid};
use usbd_ctaphid::CtapHid;
use usbd_serial::SerialPort;
use vaultkey_core::device::{self, Device};
use vaultkey_core::hal::{Clock, DeviceKey, Port, Ui};
use vaultkey_core::proto::Proto;
use vaultkey_core::store::{self, Layout, Store};
use vaultkey_core::ui::State;
use vaultkey_core::vault::Cost;

/// The first line of INFO; the version number lives in the core crate.
const VERSION: &str = vaultkey_core::version!("nrf52840-mdk-dongle");

/// What INFO answers: `VERSION`, then `chip_report`. Built once at boot, because the
/// reset cause is cleared as it is read.
static INFO: StaticCell<heapless::String<256>> = StaticCell::new();

/// RESETREAS bits, named as the product specification names them. None set means a
/// power-on reset, which also clears them all.
const RESET_CAUSES: [(u32, &str); 9] = [
    (1 << 0, "reset pin"),
    (1 << 1, "watchdog"),
    (1 << 2, "soft reset"),
    (1 << 3, "lockup"),
    (1 << 16, "wake from off"),
    (1 << 17, "lpcomp"),
    (1 << 18, "debug interface"),
    (1 << 19, "nfc"),
    (1 << 20, "vbus"),
];

/// pid.codes' test pair, for a key nobody else gets. board.toml names the same pair so
/// the CLI finds the port.
const USB_VID: u16 = 0x1209;
const USB_PID: u16 = 0x0001;

/// The vault's flash, 0x97000..0xC8000: past the end of FLASH in memory.x and the
/// signature slot after it, before Trussed's filesystem. `LAYOUT` counts from its start.
const VAULT_BASE: u32 = 0x9_7000;
const VAULT_LEN: u32 = 0x3_1000;

/// Trussed's filesystem, the passkeys, right after the vault: 0xC8000..0xF4000, 44
/// sectors, up to the bootloader at 0xF4000 and out of its reach like the vault. It was
/// 20 sectors until 2026-10-16, and fido-authenticator refuses a resident key unless
/// six blocks and the key's size are free after it, which the directories of a few
/// sites had already used up. `passkey_sectors` in board.toml changes with it: the CLI
/// reads it to leave out a backup's passkeys laid out for another size.
const FS_LEN: u32 = 0x2_C000;

/// Where the bootloader begins: the data region ends at it, and an access past the end
/// would erase the one thing on this board no USB tool can put back.
const BOOTLOADER: u32 = 0xF_4000;
const _: () = assert!(
    VAULT_BASE + VAULT_LEN + FS_LEN <= BOOTLOADER,
    "the vault and Trussed's filesystem end before the bootloader"
);

/// One attempt sector and two copies of 96 KiB: the sizes decided in
/// docs/makerdiary.md, smaller than the C6's because this chip has 1 MiB in all.
const LAYOUT: Layout = Layout {
    attempts: 0x0_0000,
    state_a: 0x0_1000,
    state_b: 0x1_9000,
    state_sectors: 24,
};
const _: () = assert!(
    LAYOUT.fits() && LAYOUT.state_b + store::SECTOR * LAYOUT.state_sectors == VAULT_LEN,
    "the attempt sector and the two copies fill the vault region exactly"
);

/// The core runs at 64 MHz on this chip, whatever the clock source.
const CYCLES_PER_MS: u32 = 64_000;

/// Argon2 over all 128 KiB, with as many passes as fit in about a second on this core.
/// 48 passes took 2645 ms through `vkey check` (2026-10-13), about 50 ms each, so 20 is
/// ≈1 s. There is no chip key here, so this cost alone is what a copy of the flash is
/// guessed at.
const KDF_COST: Cost =
    Cost::from_wire(128, 20).expect("128 KiB and 20 passes is a cost Argon2 runs");

/// Where every item sits in the image, ~10 KiB, in RAM for the life of the program:
/// the firmware has no allocator. Argon2's 128 KiB is not here: the core takes it on
/// the stack for each derivation, and passkeys use the same RAM between them.
static VAULT: StaticCell<store::Index> = StaticCell::new();

/// Two item-sized halves, 16 KiB: one to open or build an item in, one for the items
/// carried across while the image is rewritten.
static BUF: ConstStaticCell<[u8; device::BUF_LEN]> = ConstStaticCell::new([0; device::BUF_LEN]);

/// The chip's RNG and its flash controller, each shared by the vault and Trussed.
static ENTROPY: StaticCell<RefCell<Rng>> = StaticCell::new();
static FLASH: StaticCell<RefCell<Flash>> = StaticCell::new();

/// The clock tree outlives everything: USB holds a reference to it.
static CLOCKS: StaticCell<Clocks<ExternalOscillator, Internal, LfOscStopped>> = StaticCell::new();

type Bus = Usbd<UsbPeripheral<'static>>;
static USB_BUS: StaticCell<UsbBusAllocator<Bus>> = StaticCell::new();

/// Milliseconds since boot, counted by the `SysTick` exception.
static MILLIS: Mutex<Cell<u64>> = Mutex::new(Cell::new(0));

#[exception]
fn SysTick() {
    critical_section::with(|cs| {
        let ms = MILLIS.borrow(cs);
        ms.set(ms.get() + 1);
    });
}

/// Milliseconds since boot. A tick that counts itself, not a counter read on demand:
/// the auto-lock compares times only when the next request arrives, so a counter that
/// wraps between two readings would let an idle key stay unlocked. A flash erase
/// stalls the core and swallows ticks, so the clock runs slow by that much - which only
/// ever delays a timeout by a fraction of a second.
#[derive(Clone, Copy)]
struct Uptime;

impl Clock for Uptime {
    fn now_ms(&self) -> u64 {
        critical_section::with(|cs| MILLIS.borrow(cs).get())
    }
}

/// The USB device with its two interfaces - CDC-ACM for vkey's protocol and CTAPHID for
/// FIDO (docs/roadmap.md, phase 6) - polled from the main loop: nothing runs from an
/// interrupt. The bus is served wherever the key waits - for the next request (`Usb`) and
/// for the button (`Panel`), which together cover all but Argon2 and flash writes, when
/// the host's transfers simply wait. Shared by both through one `RefCell`, borrowed only
/// for a poll, a read or a write.
struct UsbStack {
    dev: UsbDevice<'static, Bus>,
    serial: SerialPort<'static, Bus>,
    ctaphid: CtapHid<'static, 'static, 'static, Bus, CTAP_MESSAGE>,
    /// True while a passkey waits for its tap (`fido::Touch`).
    awaiting_touch: bool,
    /// When the last keepalive went out.
    keepalive_ms: u64,
}

impl UsbStack {
    /// CTAP2's keepalive interval: the host gives up on a request it hears nothing about.
    const KEEPALIVE_MS: u64 = 100;

    fn poll(&mut self) {
        // usb-device polls the classes only when the bus has an event, and an answer the
        // FIDO side has just finished is not one: it has to be picked up here.
        self.ctaphid.check_for_app_response();
        self.dev.poll(&mut [&mut self.serial, &mut self.ctaphid]);
        let now = Uptime.now_ms();
        // The pipe times out a request whose packets stop arriving; it compares wrapping
        // millisecond stamps, so the low half of the uptime is all it needs.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a wrapping stamp, on purpose"
        )]
        self.ctaphid.check_timeout(now as u32);
        // A CTAP request the FIDO side holds - waiting for a tap, or for its turn behind a
        // vkey request - is announced as such. With none pending the pipe sends nothing.
        if now - self.keepalive_ms >= Self::KEEPALIVE_MS {
            self.keepalive_ms = now;
            self.ctaphid.send_keepalive(self.awaiting_touch);
        }
    }
}

static USB_STACK: StaticCell<RefCell<UsbStack>> = StaticCell::new();

/// The largest CTAP message either way, announced in getInfo. CTAPHID could carry 7609
/// bytes, but every buffer of this size sits once in RAM and again on the stack, which
/// passkeys need more; CTAP2 asks for 1024, and no request here comes near 3072.
const CTAP_MESSAGE: usize = 3072;

/// CTAPHID requests on their way to the FIDO side, and its answers back: one message each
/// way.
static CTAP_CHANNEL: Channel<CTAP_MESSAGE> = Channel::new();

/// Where the pipe finds the flag of the request being served, to raise it when the host
/// sends `CTAPHID_CANCEL`: the dispatch puts the app's flag here for the length of a call.
static CTAP_CANCEL: OptionRefSwap<'static, InterruptFlag> = OptionRefSwap::new(None);

/// The protocol's side of the stack, and FIDO's: requests that come through CTAPHID are
/// answered while vkey's line is quiet.
struct Usb {
    stack: &'static RefCell<UsbStack>,
    fido: Dispatch<'static, 'static, CTAP_MESSAGE>,
    passkeys: &'static mut fido::Passkeys,
    /// When vkey's last byte arrived.
    last_rx: u64,
}

impl Usb {
    /// How long a write may make no progress before the host counts as gone.
    const STALL_MS: u64 = 1000;
    /// How long vkey's line must be silent before FIDO is served. A frame's bytes come
    /// in back to back, so this never lands in the middle of one, and a CTAP request
    /// that waits for a touch never holds up a frame half read.
    const QUIET_MS: u64 = 50;
}

impl Port for Usb {
    fn read_byte(&mut self) -> Option<u8> {
        let byte = {
            let mut usb = self.stack.borrow_mut();
            usb.poll();
            let mut byte = [0u8];
            matches!(usb.serial.read(&mut byte), Ok(1)).then_some(byte[0])
        };
        let now = Uptime.now_ms();
        if byte.is_some() {
            self.last_rx = now;
        }
        fido::tend(now, self.last_rx);
        // Not while a backup or a restore has the passkeys' flash: CTAP requests wait.
        if byte.is_none() && now - self.last_rx > Self::QUIET_MS && fido::serving() {
            // Outside the stack's borrow: a passkey's tap wait polls the bus itself.
            let passkeys: &mut dyn App<'static> = &mut *self.passkeys;
            self.fido.poll(&mut [passkeys]);
        }
        byte
    }

    // A host that stopped reading has nobody to tell: what it does not take is dropped.
    fn write(&mut self, data: &[u8]) {
        let mut usb = self.stack.borrow_mut();
        let mut rest = data;
        let mut since = Uptime.now_ms();
        while !rest.is_empty() {
            usb.poll();
            match usb.serial.write(rest) {
                Ok(n) if n > 0 => {
                    rest = &rest[n..];
                    since = Uptime.now_ms();
                }
                Ok(_) | Err(UsbError::WouldBlock) => {
                    if Uptime.now_ms() - since > Self::STALL_MS {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    fn flush(&mut self) {
        let mut usb = self.stack.borrow_mut();
        let since = Uptime.now_ms();
        loop {
            usb.poll();
            match usb.serial.flush() {
                Err(UsbError::WouldBlock) if Uptime.now_ms() - since <= Self::STALL_MS => {}
                _ => return,
            }
        }
    }
}

/// The flash the firmware keeps data in - the vault, then Trussed's filesystem - as the
/// slice the flash driver wants. Taken once: two slices over the same flash would be
/// two owners of it.
#[expect(
    unsafe_code,
    reason = "the flash driver takes its region as a &'static mut slice, and memory-mapped flash cannot be named in safe code"
)]
fn data_region() -> &'static mut [u8] {
    static TAKEN: AtomicBool = AtomicBool::new(false);
    assert!(
        !TAKEN.swap(true, Ordering::Relaxed),
        "the data region is taken once"
    );
    let base = core::ptr::with_exposed_provenance_mut::<u8>(VAULT_BASE as usize);
    // SAFETY: 0x97000..0xF4000 is flash outside the image - memory.x ends FLASH at
    // 0x96000, and the bootloader starts at 0xF4000, which a const assert above holds
    // the region to - so nothing the compiler knows of
    // lives there; it is page-aligned, as the driver asserts; and the flag above makes
    // this the only reference to it. The flash controller rewrites these bytes on
    // erase, which is why every access goes through `Flash` and its fences.
    unsafe { core::slice::from_raw_parts_mut(base, (VAULT_LEN + FS_LEN) as usize) }
}

/// The flash controller over the vault region, with a compiler fence after every
/// change. The region is memory the compiler takes for an ordinary slice, and an erase
/// rewrites it behind the compiler's back: the fence keeps a later read from being
/// answered with bytes loaded before the erase.
struct Flash(Nvmc<pac::NVMC>);

impl ErrorType for Flash {
    type Error = NvmcError;
}

impl ReadNorFlash for Flash {
    const READ_SIZE: usize = <Nvmc<pac::NVMC> as ReadNorFlash>::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), NvmcError> {
        compiler_fence(Ordering::SeqCst);
        self.0.read(offset, bytes)
    }

    fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl NorFlash for Flash {
    const WRITE_SIZE: usize = <Nvmc<pac::NVMC> as NorFlash>::WRITE_SIZE;
    const ERASE_SIZE: usize = <Nvmc<pac::NVMC> as NorFlash>::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), NvmcError> {
        let r = self.0.erase(from, to);
        compiler_fence(Ordering::SeqCst);
        r
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), NvmcError> {
        let r = self.0.write(offset, bytes);
        compiler_fence(Ordering::SeqCst);
        r
    }
}

/// One part of the data region - the vault's or Trussed's - over the one flash
/// controller. Each sees its own bytes from offset 0, and an access past its end is
/// refused, so neither can reach into the other.
struct Region {
    flash: &'static RefCell<Flash>,
    base: u32,
    len: u32,
}

impl Region {
    /// Where `len` bytes at `offset` sit in the data region, if they fit in this part.
    fn at(&self, offset: u32, len: u32) -> Result<u32, NvmcError> {
        match offset.checked_add(len) {
            Some(end) if end <= self.len => Ok(self.base + offset),
            _ => Err(NvmcError::OutOfBounds),
        }
    }
}

/// A buffer's length as flash counts it; nothing here is anywhere near 4 GiB.
fn flash_len(bytes: &[u8]) -> Result<u32, NvmcError> {
    u32::try_from(bytes.len()).map_err(|_| NvmcError::OutOfBounds)
}

impl ErrorType for Region {
    type Error = NvmcError;
}

impl ReadNorFlash for Region {
    const READ_SIZE: usize = Flash::READ_SIZE;

    fn read(&mut self, offset: u32, bytes: &mut [u8]) -> Result<(), NvmcError> {
        let at = self.at(offset, flash_len(bytes)?)?;
        self.flash.borrow_mut().read(at, bytes)
    }

    fn capacity(&self) -> usize {
        self.len as usize
    }
}

impl NorFlash for Region {
    const WRITE_SIZE: usize = Flash::WRITE_SIZE;
    const ERASE_SIZE: usize = Flash::ERASE_SIZE;

    fn erase(&mut self, from: u32, to: u32) -> Result<(), NvmcError> {
        let len = to.checked_sub(from).ok_or(NvmcError::OutOfBounds)?;
        let at = self.at(from, len)?;
        self.flash.borrow_mut().erase(at, at + len)
    }

    fn write(&mut self, offset: u32, bytes: &[u8]) -> Result<(), NvmcError> {
        let at = self.at(offset, flash_len(bytes)?)?;
        self.flash.borrow_mut().write(at, bytes)
    }
}

/// The chip's RNG, for the vault and for Trussed alike: two handles on one peripheral,
/// each borrowing it only for a draw. The core speaks `rand_core` 0.9, as the HAL does;
/// Trussed speaks 0.6.
#[derive(Clone, Copy)]
struct Entropy(&'static RefCell<Rng>);

impl rand_core::RngCore for Entropy {
    fn next_u32(&mut self) -> u32 {
        self.0.borrow_mut().random_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.borrow_mut().random_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.borrow_mut().random(dest);
    }
}

impl rand_core::CryptoRng for Entropy {}

impl rand_core_06::RngCore for Entropy {
    fn next_u32(&mut self) -> u32 {
        self.0.borrow_mut().random_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.borrow_mut().random_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.borrow_mut().random(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.0.borrow_mut().random(dest);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for Entropy {}

/// No chip key yet. This chip has no eFuse key, and its replacement - a secret in a
/// flash page locked by the ACL until reset - is not built (docs/makerdiary.md). The
/// vault is protected by the PIN alone, and `vkey info` says so.
struct NoChipKey;

impl DeviceKey for NoChipKey {
    fn bound(&self) -> bool {
        false
    }

    fn mac(&mut self, msg: &[u8; 32], out: &mut [u8; 32]) -> bool {
        *out = *msg;
        true
    }
}

/// USER button on P0.18 and the RGB LED on P0.23 (red), P0.22 (green), P0.24 (blue),
/// all active low, from the Makerdiary wiki. Confirmed on the board: P0.18 is a plain
/// input, not the chip's reset, and the tap (amber) and the double tap (blue) worked
/// under `vkey check`. Red alone, the 5 s hold, has not been watched yet.
struct Controls {
    button: Pin<Input<PullUp>>,
    /// Served on every look at the button: a tap wait lasts seconds, and a host whose
    /// requests go unanswered that long resets the device.
    usb: &'static RefCell<UsbStack>,
    red: Pin<Output<PushPull>>,
    green: Pin<Output<PushPull>>,
    blue: Pin<Output<PushPull>>,
}

static CONTROLS: StaticCell<RefCell<Controls>> = StaticCell::new();

/// The button and the light, for the vault and for passkeys alike: they take turns, as
/// a passkey is only served while the vault waits for its next request.
#[derive(Clone, Copy)]
struct Panel(&'static RefCell<Controls>);

impl Ui for Panel {
    fn set(&mut self, state: State) {
        // Three plain LEDs and no PWM: amber is red and green together.
        let (r, g, b) = match state {
            State::Idle => (false, false, false),
            // amber: a tap approves a code, a password or a passkey
            State::Waiting => (true, true, false),
            State::Export => (false, false, true), // blue: two taps let a backup out
            State::Ok => (false, true, false),
            // Red both ways, told apart by how long it stays: held while a wipe counts
            // down, a blink when nothing was confirmed.
            State::Danger | State::Refused => (true, false, false),
        };
        let mut c = self.0.borrow_mut();
        light(&mut c.red, r);
        light(&mut c.green, g);
        light(&mut c.blue, b);
    }

    fn pressed(&self) -> bool {
        let mut c = self.0.borrow_mut();
        // The protocol never holds the stack while the key waits for the button; if it
        // ever did, this poll is skipped rather than borrowed twice.
        if let Ok(mut usb) = c.usb.try_borrow_mut() {
            usb.poll();
        }
        let Ok(low) = c.button.is_low();
        low
    }
}

/// One active-low LED on or off.
fn light(pin: &mut Pin<Output<PushPull>>, on: bool) {
    let Ok(()) = if on { pin.set_low() } else { pin.set_high() };
}

/// What the chip says about itself, for a maintainer with no probe: the build code from
/// FICR (`AAF0` - the third letter is the revision), the UICR `APPROTECT` word as stored,
/// and why the chip last reset. The first two stay raw, because what an `APPROTECT`
/// value means depends on the revision; docs/makerdiary.md reads them together. The
/// factory bootloader leaves the reset cause for the application, and it is cleared
/// here, so each boot reports only what happened since the last one.
fn chip_report(
    out: &mut impl Write,
    ficr: &pac::FICR,
    uicr: &pac::UICR,
    power: &pac::POWER,
) -> core::fmt::Result {
    let code = ficr.info.variant.read().bits();
    match core::str::from_utf8(&code.to_be_bytes()) {
        Ok(s) if s.bytes().all(|b| b.is_ascii_alphanumeric()) => write!(out, "nRF52840 {s}")?,
        _ => write!(out, "nRF52840 variant {code:#010x}")?,
    }
    write!(
        out,
        ", UICR APPROTECT {:#010x}, last reset: ",
        uicr.approtect.read().bits()
    )?;

    let causes = power.resetreas.read().bits();
    power.resetreas.write(|w| {
        w.resetpin().detected();
        w.dog().detected();
        w.sreq().detected();
        w.lockup().detected();
        w.off().detected();
        w.lpcomp().detected();
        w.dif().detected();
        w.nfc().detected();
        w.vbus().detected()
    });
    if causes == 0 {
        out.write_str("power-on")?;
    }
    let mut sep = "";
    for (bit, name) in RESET_CAUSES {
        if causes & bit != 0 {
            write!(out, "{sep}{name}")?;
            sep = "+";
        }
    }
    let unnamed = causes & !RESET_CAUSES.iter().fold(0, |all, (bit, _)| all | bit);
    if unnamed != 0 {
        write!(out, "{sep}{unnamed:#x}")?;
    }
    Ok(())
}

/// Closes the debug port for good: UICR `APPROTECT` goes from erased to Enabled, the low
/// byte 0x00 and the rest left at 0xFF. On revision 1-2 an erased word leaves SWD open;
/// on revision 3 it is closed unless UICR holds 0x5A, and 0x00 takes that away. It takes
/// effect at the next reset. Irreversible with no probe, and harmless to the owner, who
/// never has one - so the firmware does it itself, the first time it boots.
///
/// One attempt, no retry and no reset: a loop around a write that does not stick is how
/// boards have been reported to hang. A word that did not change shows in `vkey info`.
/// Nothing else writes UICR, and with the port protected nothing can afterwards.
fn protect(nvmc: &pac::NVMC, uicr: &pac::UICR) {
    if uicr.approtect.read().pall().is_enabled() {
        return;
    }
    let ready = || while nvmc.ready.read().ready().is_busy() {};
    ready();
    nvmc.config.write(|w| w.wen().wen());
    ready();
    // `write` starts from the register's reset value, 0xFFFF_FFFF: only PALL changes.
    uicr.approtect.write(|w| w.pall().enabled());
    ready();
    nvmc.config.write(|w| w.wen().ren());
    ready();
}

/// Fail closed: a panic resets the chip. The vault comes back locked, and the statics
/// that held keys are zeroed again at boot.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    SCB::sys_reset()
}

#[entry]
fn main() -> ! {
    let p = pac::Peripherals::take().expect("the peripherals are taken once, here");
    let mut cp = cortex_m::Peripherals::take().expect("the core peripherals are taken once, here");

    // Before INFO is written, so the chip line shows the word as it now stands.
    protect(&p.NVMC, &p.UICR);

    let info = INFO.init(heapless::String::new());
    writeln!(info, "{VERSION}")
        .and_then(|()| chip_report(info, &p.FICR, &p.UICR, &p.POWER))
        .expect("256 bytes hold the version and the longest chip report");
    let info: &'static heapless::String<256> = info;

    cp.SYST.set_clock_source(SystClkSource::Core);
    cp.SYST.set_reload(CYCLES_PER_MS - 1);
    cp.SYST.clear_current();
    cp.SYST.enable_counter();
    cp.SYST.enable_interrupt();

    // USB runs from the crystal, not the internal oscillator. The classes take their
    // endpoints before the device is built.
    let clocks = CLOCKS.init(Clocks::new(p.CLOCK).enable_ext_hfosc());
    let bus = USB_BUS.init(UsbBusAllocator::new(Usbd::new(UsbPeripheral::new(
        p.USBD, clocks,
    ))));
    // The serial class first, so it keeps interface 0 and the port its by-id name.
    let serial = SerialPort::new(bus);
    let (requester, responder) = CTAP_CHANNEL
        .split()
        .expect("the CTAPHID channel is split once, here");
    // CBOR announced in INIT, or hosts never send CTAP2.
    let ctaphid = CtapHid::with_interrupt(bus, requester, Some(&CTAP_CANCEL), 0).implements_ctap2();
    let usb = UsbDeviceBuilder::new(bus, UsbVidPid(USB_VID, USB_PID))
        .strings(&[StringDescriptors::default()
            .manufacturer("vaulttecdev")
            .product("vkey")])
        .expect("one language")
        .max_packet_size_0(64)
        .expect("64 bytes is a valid control packet size")
        // Two functions on one device: the CDC class announces itself with an interface
        // association, which the device class has to say is there.
        .composite_with_iads()
        .build();
    let usb: &'static RefCell<UsbStack> = USB_STACK.init(RefCell::new(UsbStack {
        dev: usb,
        serial,
        ctaphid,
        awaiting_touch: false,
        keepalive_ms: 0,
    }));

    let port0 = p0::Parts::new(p.P0);
    let mut panel = Panel(CONTROLS.init(RefCell::new(Controls {
        button: port0.p0_18.into_pullup_input().degrade(),
        usb,
        red: port0.p0_23.into_push_pull_output(Level::High).degrade(),
        green: port0.p0_22.into_push_pull_output(Level::High).degrade(),
        blue: port0.p0_24.into_push_pull_output(Level::High).degrade(),
    })));
    panel.set(State::Idle);

    let rng = Entropy(ENTROPY.init(RefCell::new(Rng::new(p.RNG))));
    let flash: &'static RefCell<Flash> =
        FLASH.init(RefCell::new(Flash(Nvmc::new(p.NVMC, data_region()))));
    let vault = Region {
        flash,
        base: 0,
        len: VAULT_LEN,
    };
    let passkeys = Region {
        flash,
        base: VAULT_LEN,
        len: FS_LEN,
    };
    // The same flash again, for the backup to carry: never at once with Trussed, which
    // the backup's freeze keeps off it.
    let passkey_backup = Region {
        flash,
        base: VAULT_LEN,
        len: FS_LEN,
    };

    let mut dev = Device::new(
        Store::new(vault, LAYOUT),
        panel,
        rng,
        Uptime,
        NoChipKey,
        fido::Backup(passkey_backup),
        KDF_COST,
        VAULT.init_with(store::Index::empty),
        BUF.take(),
    );

    let port = Usb {
        stack: usb,
        fido: Dispatch::with_interrupt(responder, Some(&CTAP_CANCEL)),
        passkeys: fido::start(passkeys, rng, panel, usb),
        last_rx: 0,
    };
    let mut proto = Proto::new(port, Uptime, info.as_str());
    proto.run(&mut dev)
}
