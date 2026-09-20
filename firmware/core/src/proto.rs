//! Host protocol over whatever byte stream the board provides (on the C6-Zero: the
//! built-in USB-Serial/JTAG port). The byte layout is in [`crate::wire`], which the
//! host CLI compiles too.
//!
//! The port may also carry log output, so frames start with a magic word the host
//! scans for. Log lines are plain ASCII and never contain it. USB already guarantees
//! integrity, so there is no checksum. The host is hostile: every field is parsed into
//! a type that can only hold a valid value before the device sees it.

use embedded_storage::nor_flash::NorFlash;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::device::{Device, Reach};
use crate::hal::{Clock, DeviceKey, Port, Ui};
use crate::item::{Category, ITEM_MAX};
use crate::oath::{NAME_MAX, Name, len_u8};
use crate::store::MAX_ENTRIES;
use crate::vault::{Passphrase, Pin};
use crate::wire::{
    AUTH_CHALLENGE_LEN, AUTH_SIGNATURE_LEN, BAD_CMD, BAD_LEN, BackupHead, Cmd, FLAG_REPLACE, Fail,
    MAGIC, MAX_PAYLOAD, OK, PinStatus, REACH_OPEN, REACH_SECRET, REACH_SEED, frame_head,
    scan_magic,
};

/// ~5 s of silence mid-frame resynchronises the framer instead of leaving it stuck.
const FRAME_TIMEOUT_MS: u64 = 5_000;
/// A full `List`: every item as `len | name | category`.
const LIST_MAX: usize = MAX_ENTRIES * (NAME_MAX + 2);

/// A request that never reaches the device: the payload does not have the shape the
/// command needs (`Len`), or it has the shape but not the values (`Arg`).
#[derive(Clone, Copy)]
enum Malformed {
    Len,
    Arg,
}

pub struct Proto<P: Port, C: Clock> {
    port: P,
    clock: C,
    version: &'static str,
}

impl<P: Port, C: Clock> Proto<P, C> {
    /// `version` is what INFO answers - build it with `vaultkey_core::version!`.
    pub fn new(port: P, clock: C, version: &'static str) -> Self {
        Proto {
            port,
            clock,
            version,
        }
    }

    fn read_byte(&mut self, deadline: Option<u64>) -> Option<u8> {
        loop {
            if let Some(b) = self.port.read_byte() {
                return Some(b);
            }
            if deadline.is_some_and(|d| self.clock.now_ms() > d) {
                return None;
            }
        }
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> bool {
        let deadline = self.clock.now_ms() + FRAME_TIMEOUT_MS;
        for b in buf.iter_mut() {
            match self.read_byte(Some(deadline)) {
                Some(v) => *b = v,
                None => return false,
            }
        }
        true
    }

    /// Scans until the magic word appears; log output and partial frames get skipped.
    fn await_magic(&mut self) {
        let mut matched = 0;
        while matched < MAGIC.len() {
            if let Some(b) = self.read_byte(None) {
                matched = scan_magic(matched, b);
            }
        }
    }

    fn respond(&mut self, status: u8, payload: &[u8]) {
        const _: () = assert!(
            LIST_MAX <= u16::MAX as usize,
            "the longest answer, a full list, must fit the u16 length field"
        );
        #[expect(clippy::cast_possible_truncation, reason = "asserted above")]
        let len = payload.len() as u16;
        self.port.write(&frame_head(status, len));
        if !payload.is_empty() {
            self.port.write(payload);
        }
        self.port.flush();
    }

    /// One frame out of two pieces, so a body that is only in the device's buffer is
    /// not copied somewhere else just to put a byte in front of it.
    fn respond_parts(&mut self, status: u8, head: &[u8], body: &[u8]) {
        const _: () = assert!(
            MAX_PAYLOAD <= u16::MAX as usize,
            "an answer's length must fit the u16 length field"
        );
        let total = head.len() + body.len();
        #[expect(clippy::cast_possible_truncation, reason = "asserted above")]
        let len = total as u16;
        self.port.write(&frame_head(status, len));
        self.port.write(head);
        if !body.is_empty() {
            self.port.write(body);
        }
        self.port.flush();
    }

    fn fail(&mut self, f: Fail) {
        match f {
            Fail::WrongPin(left) => self.respond(f.code(), &[left]),
            Fail::Refused
            | Fail::Internal
            | Fail::NotFound
            | Fail::Full
            | Fail::BadArg
            | Fail::Locked
            | Fail::Wiped
            | Fail::NoPin
            | Fail::PinExists
            | Fail::Exists
            | Fail::Incompatible
            | Fail::BadBackup => self.respond(f.code(), &[]),
        }
    }

    fn result(&mut self, r: Result<(), Fail>) {
        match r {
            Ok(()) => self.respond(OK, &[]),
            Err(f) => self.fail(f),
        }
    }

    fn reject(&mut self, m: Malformed) {
        match m {
            Malformed::Len => self.respond(BAD_LEN, &[]),
            Malformed::Arg => self.fail(Fail::BadArg),
        }
    }

    /// Runs forever, one request at a time.
    pub fn run<F, R, U, DC, K>(&mut self, dev: &mut Device<'_, F, R, U, DC, K>) -> !
    where
        F: NorFlash,
        R: RngCore + CryptoRng,
        U: Ui,
        DC: Clock,
        K: DeviceKey,
    {
        loop {
            self.await_magic();
            let mut head = [0u8; 3];
            if !self.read_exact(&mut head) {
                continue;
            }
            let len = usize::from(u16::from_le_bytes([head[1], head[2]]));
            if len > MAX_PAYLOAD {
                self.respond(BAD_LEN, &[]);
                continue;
            }
            // PINs and secrets pass through this buffer; it is scrubbed on every exit,
            // including a frame that stops half-way.
            let mut payload = Zeroizing::new([0u8; MAX_PAYLOAD]);
            if len > 0 && !self.read_exact(&mut payload[..len]) {
                continue;
            }
            dev.tick();
            match Cmd::from_wire(head[0]) {
                Some(cmd) => self.handle(dev, cmd, &payload[..len]),
                None => self.respond(BAD_CMD, &[]),
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one match over every wire command; splitting it would scatter the dispatch that is meant to be read in one place"
    )]
    fn handle<F, R, U, DC, K>(&mut self, dev: &mut Device<'_, F, R, U, DC, K>, cmd: Cmd, p: &[u8])
    where
        F: NorFlash,
        R: RngCore + CryptoRng,
        U: Ui,
        DC: Clock,
        K: DeviceKey,
    {
        match cmd {
            Cmd::Info => self.respond(OK, self.version.as_bytes()),

            Cmd::ItemPut => match parse_item_put(p) {
                Ok((name, category, item, replace)) => {
                    let r = dev.put(name, category, item, replace);
                    self.result(r);
                }
                Err(m) => self.reject(m),
            },

            Cmd::List => {
                let mut out = [0u8; LIST_MAX];
                let mut o = 0;
                let r = dev.list(|name, category| {
                    let n = name.as_bytes();
                    out[o] = len_u8(n.len());
                    out[o + 1..o + 1 + n.len()].copy_from_slice(n);
                    o += 1 + n.len();
                    out[o] = category;
                    o += 1;
                });
                match r {
                    Ok(()) => self.respond(OK, &out[..o]),
                    Err(f) => self.fail(f),
                }
            }

            Cmd::Code => {
                let Some((name, rest)) = take_name(p) else {
                    return self.reject(Malformed::Len);
                };
                let Ok(time) = <[u8; 8]>::try_from(rest) else {
                    return self.reject(Malformed::Len);
                };
                let mut code = Zeroizing::new([0u8; 9]);
                let mut out = Zeroizing::new([0u8; 8]);
                match dev.code(name, u64::from_le_bytes(time), &mut out) {
                    Ok((n, period)) => {
                        code[..n].copy_from_slice(&out[..n]);
                        code[n] = period;
                        self.respond(OK, &code[..=n]);
                    }
                    Err(f) => self.fail(f),
                }
            }

            Cmd::Respond => {
                let Some((name, rest)) = take_name(p) else {
                    return self.reject(Malformed::Len);
                };
                let Ok(challenge) = <&[u8; AUTH_CHALLENGE_LEN]>::try_from(rest) else {
                    return self.reject(Malformed::Len);
                };
                let mut out = [0u8; AUTH_SIGNATURE_LEN];
                match dev.respond(name, challenge, &mut out) {
                    Ok(()) => self.respond(OK, &out),
                    Err(f) => self.fail(f),
                }
            }

            Cmd::ItemGet => {
                let Some((name, rest)) = take_name(p) else {
                    return self.reject(Malformed::Len);
                };
                let Some(&reach_byte) = rest.first() else {
                    return self.reject(Malformed::Len);
                };
                let Some(reach) = reach_of(reach_byte) else {
                    return self.reject(Malformed::Arg);
                };
                // Answered straight out of the device's buffer: the only copy of those
                // fields in RAM, scrubbed as soon as this returns. The category and the
                // classes the item holds come in front, so the host need neither have
                // listed first nor spend a gesture to learn what kind of thing this is.
                let r = dev.get(name, reach, |category, present, item| {
                    self.respond_parts(OK, &[category, present], item);
                });
                if let Err(f) = r {
                    self.fail(f);
                }
            }

            Cmd::Delete => {
                let Some((name, _)) = take_name(p) else {
                    return self.reject(Malformed::Len);
                };
                let r = dev.delete(name);
                self.result(r);
            }

            Cmd::Rename => {
                let Some((from, rest)) = take_name(p) else {
                    return self.reject(Malformed::Len);
                };
                let Some((to, _)) = take_name(rest) else {
                    return self.reject(Malformed::Len);
                };
                let r = dev.rename(from, to);
                self.result(r);
            }

            Cmd::PinStatus => {
                let st: PinStatus = dev.pin_status();
                self.respond(OK, &st.wire());
            }

            Cmd::PinSet => match Pin::new(p) {
                Some(pin) => {
                    let r = dev.pin_set(pin);
                    self.result(r);
                }
                None => self.reject(Malformed::Arg),
            },

            Cmd::PinUnlock => match Pin::new(p) {
                Some(pin) => {
                    let r = dev.pin_unlock(pin);
                    self.result(r);
                }
                None => self.reject(Malformed::Arg),
            },

            Cmd::PinChange => match parse_pin_change(p) {
                Ok((old, new)) => {
                    let r = dev.pin_change(old, new);
                    self.result(r);
                }
                Err(m) => self.reject(m),
            },

            Cmd::Lock => {
                dev.lock();
                self.respond(OK, &[]);
            }

            Cmd::Wipe => {
                let r = dev.wipe();
                self.result(r);
            }

            Cmd::ExportBegin => match Passphrase::new(p) {
                Some(pass) => match dev.export_begin(pass) {
                    Ok(head) => self.respond(OK, &head.wire()),
                    Err(f) => self.fail(f),
                },
                None => self.reject(Malformed::Arg),
            },

            Cmd::ExportNext => {
                // Straight out of the device's buffer, like a blob.
                let r = dev.export_next(|item| self.respond(OK, item));
                if let Err(f) = r {
                    self.fail(f);
                }
            }

            Cmd::ImportBegin => match parse_import_begin(p) {
                Ok((pass, head)) => {
                    let r = dev.import_begin(pass, head);
                    self.result(r);
                }
                Err(m) => self.reject(m),
            },

            Cmd::ImportItem => {
                let r = dev.import_item(p);
                self.result(r);
            }

            Cmd::ImportEnd => {
                let r = dev.import_end();
                self.result(r);
            }
        }
    }
}

/// `head | passphrase` into its parts.
fn parse_import_begin(p: &[u8]) -> Result<(Passphrase<'_>, BackupHead), Malformed> {
    let (head, pass) = p
        .split_first_chunk::<{ BackupHead::WIRE_LEN }>()
        .ok_or(Malformed::Len)?;
    let head = BackupHead::from_wire(*head).ok_or(Malformed::Arg)?;
    let pass = Passphrase::new(pass).ok_or(Malformed::Arg)?;
    Ok((pass, head))
}

/// `name | category | flags | item` into its parts and the replace flag. The item's
/// own bytes are checked by the device, which parses them before storing anything.
fn parse_item_put(p: &[u8]) -> Result<(Name<'_>, Category, &[u8], bool), Malformed> {
    let (name, rest) = take_name(p).ok_or(Malformed::Len)?;
    let (&category, rest) = rest.split_first().ok_or(Malformed::Len)?;
    let (flags, item) = rest.split_first().ok_or(Malformed::Len)?;
    if flags & !FLAG_REPLACE != 0 || item.len() > ITEM_MAX {
        return Err(Malformed::Arg);
    }
    let category = Category::from_wire(category).ok_or(Malformed::Arg)?;
    Ok((name, category, item, flags & FLAG_REPLACE != 0))
}

/// The reach byte of an `ItemGet`. An unknown one is refused rather than rounded down
/// to something safe-looking: a host that asks in a language this firmware does not
/// speak gets no fields at all.
const fn reach_of(b: u8) -> Option<Reach> {
    match b {
        REACH_OPEN => Some(Reach::Open),
        REACH_SECRET => Some(Reach::Secret),
        REACH_SEED => Some(Reach::Seed),
        _ => None,
    }
}

/// `old_len u8 | old | new` into two PINs.
fn parse_pin_change(p: &[u8]) -> Result<(Pin<'_>, Pin<'_>), Malformed> {
    let (old_len, rest) = p.split_first().ok_or(Malformed::Len)?;
    let old_len = usize::from(*old_len);
    if old_len == 0 || old_len >= rest.len() {
        return Err(Malformed::Len);
    }
    let (old, new) = rest.split_at(old_len);
    match (Pin::new(old), Pin::new(new)) {
        (Some(old), Some(new)) => Ok((old, new)),
        _ => Err(Malformed::Arg),
    }
}

/// A u8-length-prefixed name at the start of `p`: (name, rest), or None if malformed.
fn take_name(p: &[u8]) -> Option<(Name<'_>, &[u8])> {
    Name::take(p)
}
