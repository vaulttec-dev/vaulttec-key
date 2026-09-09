//! Waveshare ESP32-C6-Zero: the board-specific half of the key. Pins, chip crates,
//! flash layout - and nothing else. The key itself is `vaultkey_core`; this file only
//! hands it the hardware through the traits in `vaultkey_core::hal`.
//!
//! Every pin here was measured on the board, not read from a datasheet - see
//! docs/hardware.md. A wrong pin fails silently (a dead button, a dark LED), so a new
//! board starts with a probe, not with a copy of this file.

#![no_std]
#![no_main]

use esp_backtrace as _;
use esp_hal::Blocking;
use esp_hal::clock::CpuClock;
use esp_hal::efuse::{KEY_PURPOSE_0, read_field_le};
use esp_hal::gpio::{Input, InputConfig, Pull};
use esp_hal::hmac::{Hmac, HmacPurpose, KeyId};
use esp_hal::peripherals::HMAC;
use esp_hal::rmt::Rmt;
use esp_hal::rng::{Trng, TrngSource};
use esp_hal::time::{Instant, Rate};
use esp_hal::usb::usb_serial_jtag::UsbSerialJtag;
use esp_hal_smartled::{RmtSmartLeds, WS2812_TIMING, buffer_size, color_order};
use esp_storage::FlashStorage;
use smart_leds::{RGB8, SmartLedsWrite, brightness};
use static_cell::{ConstStaticCell, StaticCell};
use vaultkey_core::device::{self, Device};
use vaultkey_core::hal::{Clock, DeviceKey, Port, Ui};
use vaultkey_core::proto::Proto;
use vaultkey_core::store::{self, Layout, Store};
use vaultkey_core::ui::State;
use vaultkey_core::vault::{Block, KDF_BLOCKS};

// The ESP-IDF second-stage bootloader wants an application descriptor in the image.
esp_bootloader_esp_idf::esp_app_desc!();

/// What INFO reports; the version number lives in the core crate.
const VERSION: &str = vaultkey_core::version!("esp32c6-zero");

/// Where the key keeps its state: raw flash past the `factory` partition of the stock
/// ESP-IDF table (0x110000..0x17B000 of the 4 MiB chip). The table describes nothing
/// there, so neither the bootloader nor a firmware update ever touches it.
const LAYOUT: Layout = Layout {
    attempts: 0x11_0000,
    state_a: 0x11_1000,
    state_b: 0x12_6000,
    env: 0x13_B000,
};

/// Argon2 working memory, in RAM for the life of the program: the key derivation has
/// no allocator, and 128 KiB does not belong on the stack.
static KDF_MEM: ConstStaticCell<[Block; KDF_BLOCKS]> =
    ConstStaticCell::new([Block::new(); KDF_BLOCKS]);

/// The vault as last read from flash, ~80 KiB: same reason, same place. Filled in at
/// boot rather than a `const`: a constant with padding in it is not "all zeros" to the
/// linker, and this one would be copied out of the firmware image byte for byte.
static VAULT: StaticCell<store::State> = StaticCell::new();

/// One env blob or one backup item, sealed or open, 8 KiB: same reason, same place.
static BUF: ConstStaticCell<[u8; device::BUF_LEN]> = ConstStaticCell::new([0; device::BUF_LEN]);

/// The built-in USB-Serial/JTAG port. It also carries esp-println output; frames
/// start with a magic word, so that is harmless.
struct Usb(UsbSerialJtag<'static, Blocking>);

impl Port for Usb {
    fn read_byte(&mut self) -> Option<u8> {
        self.0.read_byte().ok()
    }

    fn write(&mut self, data: &[u8]) {
        let _ = self.0.write(data);
    }

    fn flush(&mut self) {
        let _ = self.0.flush_tx();
    }
}

/// The chip's own key, once it is burned: HMAC-SHA256 under eFuse key block 0, which
/// software can use but never read. Until that block carries a key with the `HMAC_UP`
/// purpose (docs/hardware.md says how to burn one), the vault is protected by the PIN
/// alone - and `vkey info` says so.
struct ChipKey(Option<Hmac<'static>>);

impl ChipKey {
    /// `KEY_PURPOSE_0 == HMAC_UP`: upstream mode, the result readable by software.
    const HMAC_UP: u8 = 8;

    fn detect(hmac: HMAC<'static>) -> Self {
        let burned = read_field_le::<u8>(KEY_PURPOSE_0) == Self::HMAC_UP;
        ChipKey(burned.then(|| Hmac::new(hmac)))
    }
}

impl DeviceKey for ChipKey {
    fn bound(&self) -> bool {
        self.0.is_some()
    }

    fn mac(&mut self, msg: &[u8; 32], out: &mut [u8; 32]) -> bool {
        let Some(h) = self.0.as_mut() else {
            *out = *msg;
            return true;
        };
        h.init();
        if h.configure(HmacPurpose::ToUser, KeyId::Key0).is_err() {
            return false;
        }
        // The driver answers "would block" while the accelerator is busy.
        let mut rest: &[u8] = msg;
        while !rest.is_empty() {
            if let Ok(r) = h.update(rest) {
                rest = r;
            }
        }
        while h.finalize(out).is_err() {}
        true
    }
}

/// Milliseconds since boot, from the system timer.
struct Uptime;

impl Clock for Uptime {
    fn now_ms(&self) -> u64 {
        Instant::now().duration_since_epoch().as_millis()
    }
}

/// BOOT button on GPIO9, active low (not GPIO0 as on older ESP32s), and the single
/// WS2812 on GPIO8, wired RGB - not the GRB most drivers assume.
type Led = RmtSmartLeds<'static, { buffer_size::<RGB8>(1) }, Blocking, RGB8, color_order::Rgb>;

struct Panel {
    button: Input<'static>,
    led: Led,
}

impl Ui for Panel {
    fn set(&mut self, state: State) {
        let color = match state {
            State::Idle => RGB8::new(0, 0, 0),
            State::Waiting => RGB8::new(255, 110, 0), // amber: a tap approves a code or a password
            State::Export => RGB8::new(0, 80, 255),   // blue: two taps let a backup out
            State::Ok => RGB8::new(0, 255, 0),
            // Red both ways, told apart by how long it stays: held while a wipe counts
            // down, a blink when nothing was confirmed.
            State::Danger | State::Refused => RGB8::new(255, 0, 0),
        };
        // Errors here mean the RMT is busy; the next update fixes it, nothing to do.
        let _ = self.led.write(brightness([color].into_iter(), 24));
    }

    fn pressed(&self) -> bool {
        self.button.is_low()
    }
}

#[esp_hal::main]
fn main() -> ! {
    let p = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));

    // Without the SAR-ADC noise source switched on, the RNG register is not random.
    // The handle must stay alive for as long as random numbers are drawn - forever.
    let _entropy = TrngSource::new(p.RNG, p.ADC1);
    let trng = Trng::try_new().expect("entropy source enabled above");

    let button = Input::new(p.GPIO9, InputConfig::default().with_pull(Pull::Up));
    let rmt = Rmt::new(p.RMT, Rate::from_mhz(80)).expect("RMT clock");
    let led =
        Led::new(WS2812_TIMING, rmt.channel0, p.GPIO8, Rate::from_mhz(80)).expect("LED channel");
    let mut panel = Panel { button, led };
    panel.set(State::Idle);

    // GPIO12/13 are USB D-/D+: never configured here, or the board leaves the bus.
    let store = Store::new(FlashStorage::new(p.FLASH), LAYOUT);
    let mut dev = Device::new(
        store,
        panel,
        trng,
        Uptime,
        ChipKey::detect(p.HMAC),
        KDF_MEM.take(),
        VAULT.init_with(store::State::empty),
        BUF.take(),
    );

    esp_println::println!("{VERSION}: listening");
    let mut proto = Proto::new(Usb(UsbSerialJtag::new(p.USB_DEVICE)), Uptime, VERSION);
    proto.run(&mut dev)
}
