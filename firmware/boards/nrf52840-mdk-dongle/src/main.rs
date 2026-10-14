//! Makerdiary nRF52840 MDK USB Dongle: the board-specific half of the key. Pins, chip
//! crates, flash layout - and nothing else. The key itself is `vaultkey_core`; this file
//! only hands it the hardware through the traits in `vaultkey_core::hal`.
//!
//! Runs on the board: `vkey check --wipe-everything` passed on 2026-10-13, flashed
//! through the factory UF2 bootloader, which sits at 0xF4000 behind Nordic's MBR at 0x0
//! (docs2/makerdiary.md).

#![no_std]
#![no_main]

use core::cell::{Cell, RefCell};
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering, compiler_fence};

use cortex_m::peripheral::SCB;
use cortex_m::peripheral::syst::SystClkSource;
use cortex_m_rt::{entry, exception};
use critical_section::Mutex;
use embedded_hal::digital::{InputPin, OutputPin};
use embedded_storage::nor_flash::{ErrorType, NorFlash, ReadNorFlash};
use nrf52840_hal::clocks::{Clocks, ExternalOscillator, Internal, LfOscStopped};
use nrf52840_hal::gpio::{Input, Level, Output, Pin, PullUp, PushPull, p0};
use nrf52840_hal::nvmc::{Nvmc, NvmcError};
use nrf52840_hal::pac;
use nrf52840_hal::rng::Rng;
use nrf52840_hal::usbd::{UsbPeripheral, Usbd};
use static_cell::{ConstStaticCell, StaticCell};
use usb_device::UsbError;
use usb_device::bus::UsbBusAllocator;
use usb_device::device::{StringDescriptors, UsbDevice, UsbDeviceBuilder, UsbVidPid};
use usbd_serial::SerialPort;
use vaultkey_core::device::{self, Device};
use vaultkey_core::hal::{Clock, DeviceKey, Port, Ui};
use vaultkey_core::proto::Proto;
use vaultkey_core::store::{self, Layout, Store};
use vaultkey_core::ui::State;
use vaultkey_core::vault::{Block, Cost, KDF_BLOCKS};

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

/// The vault's flash, 0x97000..0xD8000: past the end of FLASH in memory.x and the
/// signature slot after it, before Trussed's filesystem. `LAYOUT` counts from its start.
const VAULT_BASE: u32 = 0x9_7000;
const VAULT_LEN: u32 = 0x4_1000;

/// One attempt sector and two copies of 128 KiB: the sizes decided in
/// docs2/makerdiary.md, smaller than the C6's because this chip has 1 MiB in all.
const LAYOUT: Layout = Layout {
    attempts: 0x0_0000,
    state_a: 0x0_1000,
    state_b: 0x2_1000,
    state_sectors: 32,
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

/// Argon2 working memory, in RAM for the life of the program: the key derivation has
/// no allocator, and 128 KiB does not belong on the stack.
static KDF_MEM: ConstStaticCell<[Block; KDF_BLOCKS]> =
    ConstStaticCell::new([Block::new(); KDF_BLOCKS]);

/// Where every item sits in the image, ~10 KiB: same reason, same place.
static VAULT: StaticCell<store::Index> = StaticCell::new();

/// Two item-sized halves, 16 KiB: one to open or build an item in, one for the items
/// carried across while the image is rewritten.
static BUF: ConstStaticCell<[u8; device::BUF_LEN]> = ConstStaticCell::new([0; device::BUF_LEN]);

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

/// USB CDC-ACM, polled: every read and write services the bus first. Nothing runs from
/// an interrupt, so the bus waits while the key computes - Argon2, a flash write - and
/// the host's bulk transfers simply wait with it.
struct Usb {
    dev: UsbDevice<'static, Bus>,
    serial: SerialPort<'static, Bus>,
}

impl Usb {
    /// How long a write may make no progress before the host counts as gone.
    const STALL_MS: u64 = 1000;

    fn poll(&mut self) {
        self.dev.poll(&mut [&mut self.serial]);
    }
}

impl Port for Usb {
    fn read_byte(&mut self) -> Option<u8> {
        self.poll();
        let mut byte = [0u8];
        matches!(self.serial.read(&mut byte), Ok(1)).then_some(byte[0])
    }

    // A host that stopped reading has nobody to tell: what it does not take is dropped.
    fn write(&mut self, data: &[u8]) {
        let mut rest = data;
        let mut since = Uptime.now_ms();
        while !rest.is_empty() {
            self.poll();
            match self.serial.write(rest) {
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
        let since = Uptime.now_ms();
        loop {
            self.poll();
            match self.serial.flush() {
                Err(UsbError::WouldBlock) if Uptime.now_ms() - since <= Self::STALL_MS => {}
                _ => return,
            }
        }
    }
}

/// The vault region as the slice the flash driver wants. Taken once: two slices over
/// the same flash would be two owners of it.
#[expect(
    unsafe_code,
    reason = "the flash driver takes its region as a &'static mut slice, and memory-mapped flash cannot be named in safe code"
)]
fn vault_region() -> &'static mut [u8] {
    static TAKEN: AtomicBool = AtomicBool::new(false);
    assert!(
        !TAKEN.swap(true, Ordering::Relaxed),
        "the vault region is taken once"
    );
    let base = core::ptr::with_exposed_provenance_mut::<u8>(VAULT_BASE as usize);
    // SAFETY: 0x97000..0xD8000 is flash outside the image - memory.x ends FLASH at
    // 0x96000 - so nothing the compiler knows of lives there; it is page-aligned, as
    // the driver asserts; and the flag above makes this the only reference to it. The
    // flash controller rewrites these bytes on erase, which is why every access goes
    // through `Flash` and its fences.
    unsafe { core::slice::from_raw_parts_mut(base, VAULT_LEN as usize) }
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

/// No chip key yet. This chip has no eFuse key, and its replacement - a secret in a
/// flash page locked by the ACL until reset - is not built (docs2/makerdiary.md). The
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
struct Panel {
    // embedded-hal reads a pin through `&mut`, and `Ui::pressed` takes `&self`.
    button: RefCell<Pin<Input<PullUp>>>,
    red: Pin<Output<PushPull>>,
    green: Pin<Output<PushPull>>,
    blue: Pin<Output<PushPull>>,
}

impl Ui for Panel {
    fn set(&mut self, state: State) {
        // Three plain LEDs and no PWM: amber is red and green together.
        let (r, g, b) = match state {
            State::Idle => (false, false, false),
            State::Waiting => (true, true, false), // amber: a tap approves a code or a password
            State::Export => (false, false, true), // blue: two taps let a backup out
            State::Ok => (false, true, false),
            // Red both ways, told apart by how long it stays: held while a wipe counts
            // down, a blink when nothing was confirmed.
            State::Danger | State::Refused => (true, false, false),
        };
        light(&mut self.red, r);
        light(&mut self.green, g);
        light(&mut self.blue, b);
    }

    fn pressed(&self) -> bool {
        let Ok(low) = self.button.borrow_mut().is_low();
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
/// value means depends on the revision; docs2/makerdiary.md reads them together. The
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

    let port0 = p0::Parts::new(p.P0);
    let mut panel = Panel {
        button: RefCell::new(port0.p0_18.into_pullup_input().degrade()),
        red: port0.p0_23.into_push_pull_output(Level::High).degrade(),
        green: port0.p0_22.into_push_pull_output(Level::High).degrade(),
        blue: port0.p0_24.into_push_pull_output(Level::High).degrade(),
    };
    panel.set(State::Idle);

    // USB runs from the crystal, not the internal oscillator. The classes take their
    // endpoints before the device is built.
    let clocks = CLOCKS.init(Clocks::new(p.CLOCK).enable_ext_hfosc());
    let bus = USB_BUS.init(UsbBusAllocator::new(Usbd::new(UsbPeripheral::new(
        p.USBD, clocks,
    ))));
    let serial = SerialPort::new(bus);
    let usb = UsbDeviceBuilder::new(bus, UsbVidPid(USB_VID, USB_PID))
        .strings(&[StringDescriptors::default()
            .manufacturer("vaulttecdev")
            .product("vkey")])
        .expect("one language")
        .max_packet_size_0(64)
        .expect("64 bytes is a valid control packet size")
        .device_class(usbd_serial::USB_CLASS_CDC)
        .build();

    let store = Store::new(Flash(Nvmc::new(p.NVMC, vault_region())), LAYOUT);
    let mut dev = Device::new(
        store,
        panel,
        Rng::new(p.RNG),
        Uptime,
        NoChipKey,
        KDF_MEM.take(),
        KDF_COST,
        VAULT.init_with(store::Index::empty),
        BUF.take(),
    );

    let mut proto = Proto::new(Usb { dev: usb, serial }, Uptime, info.as_str());
    proto.run(&mut dev)
}
