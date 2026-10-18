//! The key as a USB keyboard, for one thing only: typing the computer's login password
//! and Enter on the double tap made with nothing asked (`vaultkey_core::ui::IdleDoubleTap`).
//! At the login screen the vault is still locked and the keyring waits for that password,
//! which `pam_u2f` cannot give it. Maintainer's decision, 2026-10-17;
//! docs/threat-model.md says what it costs.
//!
//! A boot-protocol keyboard with one input report (modifiers, a reserved byte, six keys)
//! and one output report, the host's LEDs: Caps Lock would otherwise turn every letter
//! the wrong case. Key codes are a US layout's; the device cannot know the layout the
//! login screen uses.

use core::cell::RefCell;

use usb_device::bus::{InterfaceNumber, UsbBus, UsbBusAllocator};
use usb_device::class::{ControlIn, ControlOut, UsbClass};
use usb_device::control::{Recipient, Request, RequestType};
use usb_device::descriptor::DescriptorWriter;
use usb_device::endpoint::EndpointIn;
use usb_device::{Result as UsbResult, UsbError};
use vaultkey_core::hal::{Clock, Ui};
use vaultkey_core::ui::State;

use crate::{Panel, Uptime, UsbStack};

const HID: u8 = 0x03;
const SUBCLASS_BOOT: u8 = 0x01;
const PROTOCOL_KEYBOARD: u8 = 0x01;
const HID_DESCRIPTOR: u8 = 0x21;
const REPORT_DESCRIPTOR: u8 = 0x22;

// HID 1.11, 7.2: the class requests a boot keyboard answers.
const GET_REPORT: u8 = 0x01;
const GET_IDLE: u8 = 0x02;
const GET_PROTOCOL: u8 = 0x03;
const SET_REPORT: u8 = 0x09;
const SET_IDLE: u8 = 0x0A;
const SET_PROTOCOL: u8 = 0x0B;

/// The boot keyboard's report descriptor, HID 1.11 appendix B.1.
const REPORT: [u8; 63] = [
    0x05, 0x01, // usage page: generic desktop
    0x09, 0x06, // usage: keyboard
    0xA1, 0x01, // collection: application
    0x05, 0x07, //   usage page: keys
    0x19, 0xE0, 0x29, 0xE7, // usages: the eight modifiers
    0x15, 0x00, 0x25, 0x01, // 0..1
    0x75, 0x01, 0x95, 0x08, 0x81, 0x02, // input: 8 bits, data
    0x95, 0x01, 0x75, 0x08, 0x81, 0x01, // input: a reserved byte
    0x95, 0x05, 0x75, 0x01, // 5 bits
    0x05, 0x08, 0x19, 0x01, 0x29, 0x05, // usage page: LEDs, Num Lock..Kana
    0x91, 0x02, // output: data
    0x95, 0x01, 0x75, 0x03, 0x91, 0x01, // output: 3 bits of padding
    0x95, 0x06, 0x75, 0x08, // six bytes
    0x15, 0x00, 0x25, 0x65, // 0..101
    0x05, 0x07, 0x19, 0x00, 0x29, 0x65, // usage page: keys
    0x81, 0x00, // input: array
    0xC0, // end collection
];

/// Bit 1 of the LED report.
const CAPS_LOCK: u8 = 0x02;
const LEFT_SHIFT: u8 = 0x02;
const ENTER: u8 = 0x28;

/// How often the host asks for a report, ms: two per key, so a 20-character password
/// takes under half a second.
const POLL_MS: u8 = 10;
/// How long one report may wait for the host before typing stops.
const REPORT_MS: u64 = 200;

pub(crate) struct Keyboard<'a, B: UsbBus> {
    interface: InterfaceNumber,
    endpoint: EndpointIn<'a, B>,
    /// The host's LEDs, as it last set them.
    leds: u8,
    /// Boot or report protocol, as the host last chose; both carry the same report here.
    protocol: u8,
}

impl<'a, B: UsbBus> Keyboard<'a, B> {
    pub(crate) fn new(bus: &'a UsbBusAllocator<B>) -> Self {
        Keyboard {
            interface: bus.interface(),
            endpoint: bus.interrupt(8, POLL_MS),
            leds: 0,
            protocol: 1,
        }
    }

    /// One report out, if the endpoint is free.
    fn send(&self, modifiers: u8, key: u8) -> UsbResult<usize> {
        self.endpoint.write(&[modifiers, 0, key, 0, 0, 0, 0, 0])
    }
}

impl<B: UsbBus> UsbClass<B> for Keyboard<'_, B> {
    fn get_configuration_descriptors(&self, writer: &mut DescriptorWriter<'_>) -> UsbResult<()> {
        writer.interface(self.interface, HID, SUBCLASS_BOOT, PROTOCOL_KEYBOARD)?;
        #[expect(clippy::cast_possible_truncation, reason = "63 bytes")]
        let len = REPORT.len() as u8;
        // bcdHID 1.11, no country, one report descriptor of `len` bytes.
        writer.write(
            HID_DESCRIPTOR,
            &[0x11, 0x01, 0x00, 0x01, REPORT_DESCRIPTOR, len, 0x00],
        )?;
        writer.endpoint(&self.endpoint)
    }

    fn control_in(&mut self, xfer: ControlIn<'_, '_, '_, B>) {
        let req = *xfer.request();
        if req.index != u16::from(u8::from(self.interface)) || req.recipient != Recipient::Interface
        {
            return;
        }
        let answer = match (req.request_type, req.request) {
            (RequestType::Standard, Request::GET_DESCRIPTOR)
                if req.value >> 8 == u16::from(REPORT_DESCRIPTOR) =>
            {
                xfer.accept_with_static(&REPORT)
            }
            (RequestType::Class, GET_REPORT) => xfer.accept_with(&[0; 8]),
            (RequestType::Class, GET_IDLE) => xfer.accept_with(&[0]),
            (RequestType::Class, GET_PROTOCOL) => xfer.accept_with(&[self.protocol]),
            // Not this class's: usb-device answers what no class takes.
            _ => return,
        };
        // A host that hung up mid-request has nobody to tell.
        answer.ok();
    }

    fn control_out(&mut self, xfer: ControlOut<'_, '_, '_, B>) {
        let req = *xfer.request();
        if req.index != u16::from(u8::from(self.interface))
            || req.recipient != Recipient::Interface
            || req.request_type != RequestType::Class
        {
            return;
        }
        match req.request {
            SET_REPORT => {
                if let Some(&leds) = xfer.data().first() {
                    self.leds = leds;
                }
                xfer.accept().ok();
            }
            SET_IDLE => {
                xfer.accept().ok();
            }
            #[expect(clippy::cast_possible_truncation, reason = "0 or 1 in the low byte")]
            SET_PROTOCOL => {
                self.protocol = req.value as u8;
                xfer.accept().ok();
            }
            _ => {
                xfer.reject().ok();
            }
        }
    }
}

/// A printable ASCII character as a US keyboard's key, and whether it takes Shift.
/// `vaultkey_core::login::Login` lets nothing else in.
const fn key(c: u8) -> Option<(bool, u8)> {
    Some(match c {
        b'a'..=b'z' => (false, 0x04 + (c - b'a')),
        b'A'..=b'Z' => (true, 0x04 + (c - b'A')),
        b'1'..=b'9' => (false, 0x1E + (c - b'1')),
        b'0' => (false, 0x27),
        b'!' => (true, 0x1E),
        b'@' => (true, 0x1F),
        b'#' => (true, 0x20),
        b'$' => (true, 0x21),
        b'%' => (true, 0x22),
        b'^' => (true, 0x23),
        b'&' => (true, 0x24),
        b'*' => (true, 0x25),
        b'(' => (true, 0x26),
        b')' => (true, 0x27),
        b' ' => (false, 0x2C),
        b'-' => (false, 0x2D),
        b'_' => (true, 0x2D),
        b'=' => (false, 0x2E),
        b'+' => (true, 0x2E),
        b'[' => (false, 0x2F),
        b'{' => (true, 0x2F),
        b']' => (false, 0x30),
        b'}' => (true, 0x30),
        b'\\' => (false, 0x31),
        b'|' => (true, 0x31),
        b';' => (false, 0x33),
        b':' => (true, 0x33),
        b'\'' => (false, 0x34),
        b'"' => (true, 0x34),
        b'`' => (false, 0x35),
        b'~' => (true, 0x35),
        b',' => (false, 0x36),
        b'<' => (true, 0x36),
        b'.' => (false, 0x37),
        b'>' => (true, 0x37),
        b'/' => (false, 0x38),
        b'?' => (true, 0x38),
        _ => return None,
    })
}

/// Types `text` and Enter, green while it does and red after if it stopped: each key
/// down, then up, so a letter
/// twice in a row is two letters. With Caps Lock on, Shift is inverted for letters. A
/// report the host does not take in `REPORT_MS`, or a character without a key, stops
/// it before Enter: a half-typed password is never submitted.
pub(crate) fn type_login(usb: &RefCell<UsbStack>, mut panel: Panel, text: &[u8]) {
    panel.set(State::Ok);
    let typed = type_text(usb, text);
    show(usb, panel, if typed { State::Ok } else { State::Refused });
}

/// The outcome for a moment, the bus served meanwhile, then the light off.
pub(crate) fn show(usb: &RefCell<UsbStack>, mut panel: Panel, state: State) {
    panel.set(state);
    let since = Uptime.now_ms();
    while Uptime.now_ms() - since < 300 {
        usb.borrow_mut().poll();
    }
    panel.set(State::Idle);
}

fn type_text(usb: &RefCell<UsbStack>, text: &[u8]) -> bool {
    let caps = usb.borrow().keyboard.leds & CAPS_LOCK != 0;
    let mut typed = true;
    for &c in text {
        let Some((shift, code)) = key(c) else {
            typed = false;
            break;
        };
        let shift = shift ^ (caps && c.is_ascii_alphabetic());
        let modifiers = if shift { LEFT_SHIFT } else { 0 };
        if !(report(usb, modifiers, code) && report(usb, 0, 0)) {
            typed = false;
            break;
        }
    }
    typed = typed && report(usb, 0, ENTER) && report(usb, 0, 0);
    if !typed {
        report(usb, 0, 0);
    }
    typed
}

/// One report, the bus served until the host takes it.
fn report(usb: &RefCell<UsbStack>, modifiers: u8, code: u8) -> bool {
    let since = Uptime.now_ms();
    loop {
        let mut usb = usb.borrow_mut();
        usb.poll();
        match usb.keyboard.send(modifiers, code) {
            Ok(_) => return true,
            Err(UsbError::WouldBlock) if Uptime.now_ms() - since <= REPORT_MS => {}
            Err(_) => return false,
        }
    }
}
