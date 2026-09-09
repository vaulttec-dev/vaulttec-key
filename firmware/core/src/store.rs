//! Persistent state in raw flash, power-cut safe, no filesystem.
//!
//! The board says where (a [`Layout`]: four regions the bootloader will never touch);
//! this module says how:
//!
//!   attempts   one word per failed PIN, cleared 1->0 without an erase
//!   state A  \ salt, KDF cost, verifier, wrapped env key and the whole credential
//!   state B  / table as ONE image, written alternately
//!   env        `ENV_SLOTS` blobs too big for the table, each its own A/B pair
//!
//! One image, because a PIN change re-seals every entry under a new key: with the
//! header and the entries in separate places, a power cut between the two writes
//! would leave entries no PIN can open. Every image carries a magic, a sequence
//! number and a CRC. Readers take the valid copy with the higher sequence; writers
//! overwrite the other one.
//!
//! All access goes through the `NorFlash` traits on purpose: a "convenient" write that
//! does read-erase-rewrite of the sector would turn the attempt counter's "one word,
//! no erase" into "erase first" - and a power cut between that erase and the write
//! would hand every attempt back.
//!
//! An image is ~80 KiB and never sits in RAM whole: the CRC is streamed a slot at a
//! time, and reads and writes go slot by slot. The state itself (`State`) is the only
//! image-sized thing in memory, and the chip has no room for two more copies of it.

use crc::{CRC_32_ISO_HDLC, Crc};
use embedded_storage::nor_flash::NorFlash;
use zeroize::Zeroize;

use crate::oath::{ENV_MAX, Kind, NAME_MAX, Name, SECRET_MAX, len_u8, len_u16};
use crate::vault::{Cost, KEY_LEN, OVERHEAD, SALT_LEN};

pub const MAX_ENTRIES: usize = 256;
pub const MAX_ATTEMPTS: u8 = 8;
/// Every region below is this many bytes; flash erases in these units.
pub const SECTOR: u32 = 4096;
pub const STATE_SECTORS: u32 = 21;

/// Env blobs: how many, and how much flash they take - two copies of two sectors each.
pub const ENV_SLOTS: usize = 16;
const ENV_COPY_SECTORS: u32 = 2;
const ENV_COPY: u32 = SECTOR * ENV_COPY_SECTORS;
pub const ENV_SECTORS: u32 = 64;
const _: () = assert!(
    ENV_SECTORS as usize == ENV_SLOTS * 2 * ENV_COPY_SECTORS as usize,
    "the env region is every slot's two copies"
);
/// A sealed blob with room for the AEAD overhead: what the board's buffer holds.
pub const ENV_BUF_LEN: usize = ENV_MAX + OVERHEAD;
const _: () = assert!(
    ENV_BUF_LEN.is_multiple_of(4),
    "blob bodies are written in words"
);

/// Where the four regions live. Each must start on a sector boundary; `state_a` and
/// `state_b` are `STATE_SECTORS` long, `attempts` one sector, `env` `ENV_SECTORS`.
#[derive(Clone, Copy, Debug)]
pub struct Layout {
    pub attempts: u32,
    pub state_a: u32,
    pub state_b: u32,
    pub env: u32,
}

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
/// How much of an image or a blob a CRC pass reads per driver call.
const CRC_CHUNK: usize = 1024;
/// Bump the digit whenever the image layout changes, so an old image is refused
/// instead of misread. The size assert below is the tripwire.
const MAGIC: [u8; 4] = *b"VKS6";

/// Why the store could not do what was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error<E> {
    /// Flash holds something, but neither copy is an image this firmware understands.
    /// Nothing may be written over it without an explicit wipe.
    Corrupt,
    /// The flash driver refused a read, write or erase.
    Flash(E),
}

/// Salt, KDF cost, key binding and verifier: everything needed to check a PIN. Plus
/// the env key, sealed under the dek: it changes with the PIN inside this one image,
/// so the blobs it protects never have to.
#[derive(Clone, Copy)]
pub struct Header {
    pub salt: [u8; SALT_LEN],
    pub cost: Cost,
    /// Whether the keys were derived with a chip-only key mixed in.
    pub bound: bool,
    pub verifier: [u8; KEY_LEN],
    pub env_key: [u8; KEY_LEN + OVERHEAD],
}

/// A name copied out of a slot head, for a caller who asked by slot and not by name:
/// the head it came from is gone by the time the caller looks.
#[derive(Clone, Copy)]
pub struct StoredName {
    bytes: [u8; NAME_MAX],
    len: u8,
}

impl StoredName {
    pub(crate) fn of(name: Name<'_>) -> Self {
        let name = name.as_bytes();
        let mut s = StoredName {
            bytes: [0; NAME_MAX],
            len: len_u8(name.len()),
        };
        s.bytes[..name.len()].copy_from_slice(name);
        s
    }

    #[must_use]
    pub fn get(&self) -> Name<'_> {
        Name::trusted(&self.bytes[..usize::from(self.len)])
    }
}

/// One stored credential: plaintext metadata, sealed secret.
#[derive(Clone, Copy)]
pub struct Record {
    name: [u8; NAME_MAX],
    name_len: u8,
    pub kind: Kind,
    sealed_len: u16,
    sealed: [u8; SECRET_MAX + OVERHEAD],
}

impl Record {
    /// The slot layout: name, its length, kind, sealed length, then the sealed bytes.
    /// `put` and `get` both index by these, so they are each other's inverse.
    const OFF_NAME_LEN: usize = NAME_MAX;
    const OFF_KIND: usize = Self::OFF_NAME_LEN + 1;
    const OFF_SEALED_LEN: usize = Self::OFF_KIND + Kind::WIRE_LEN;
    const META: usize = Self::OFF_SEALED_LEN + 2;
    /// A slot in flash: the record padded up to a word, so every slot starts on a
    /// word boundary and can be written on its own.
    const SIZE: usize = (Self::META + Self::SEALED_MAX).next_multiple_of(4); // 324
    const SEALED_MAX: usize = SECRET_MAX + OVERHEAD;

    /// An empty slot. A name is never empty, so `name_len == 0` is the whole test.
    pub const EMPTY: Record = Record {
        name: [0; NAME_MAX],
        name_len: 0,
        kind: Kind::Password,
        sealed_len: 0,
        sealed: [0; Self::SEALED_MAX],
    };

    /// None if `sealed` is not something [`crate::vault::seal`] could have produced.
    #[must_use]
    pub fn new(name: Name<'_>, kind: Kind, sealed: &[u8]) -> Option<Record> {
        if !(OVERHEAD + 1..=Self::SEALED_MAX).contains(&sealed.len()) {
            return None;
        }
        let name = name.as_bytes();
        let mut r = Record {
            name: [0; NAME_MAX],
            name_len: len_u8(name.len()),
            kind,
            sealed_len: len_u16(sealed.len()),
            sealed: [0; Self::SEALED_MAX],
        };
        r.name[..name.len()].copy_from_slice(name);
        r.sealed[..sealed.len()].copy_from_slice(sealed);
        Some(r)
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.name_len == 0
    }

    #[must_use]
    pub fn name(&self) -> Name<'_> {
        Name::trusted(&self.name[..usize::from(self.name_len)])
    }

    #[must_use]
    pub fn sealed(&self) -> &[u8] {
        &self.sealed[..usize::from(self.sealed_len)]
    }

    /// An empty slot is all zeros; a used one is `name | name_len | kind | sealed_len
    /// u16le | sealed | pad`.
    fn put(r: &Record, out: &mut [u8; Record::SIZE]) {
        out.fill(0);
        if r.is_empty() {
            return;
        }
        out[..NAME_MAX].copy_from_slice(&r.name);
        out[Self::OFF_NAME_LEN] = r.name_len;
        out[Self::OFF_KIND..Self::OFF_SEALED_LEN].copy_from_slice(&r.kind.wire());
        out[Self::OFF_SEALED_LEN..Self::META].copy_from_slice(&r.sealed_len.to_le_bytes());
        out[Self::META..Self::META + Self::SEALED_MAX].copy_from_slice(&r.sealed);
    }

    /// A slot from flash. The metadata is plaintext under a CRC, not under the AEAD,
    /// so anyone with flash access can edit it: anything a code would choke on is
    /// treated as an empty slot rather than trusted.
    fn get(bytes: &[u8]) -> Option<Record> {
        let name_len = usize::from(bytes[Self::OFF_NAME_LEN]);
        if name_len == 0 {
            return None;
        }
        let name = Name::new(&bytes[..name_len.min(NAME_MAX)])?;
        let kind = Kind::from_wire(word(&bytes[Self::OFF_KIND..Self::OFF_SEALED_LEN]))?;
        let sealed_len = usize::from(u16::from_le_bytes([
            bytes[Self::OFF_SEALED_LEN],
            bytes[Self::OFF_SEALED_LEN + 1],
        ]));
        let sealed = &bytes[Self::META..Self::META + sealed_len.min(Self::SEALED_MAX)];
        Record::new(name, kind, sealed)
    }
}

/// The device's whole persistent state. None header = no PIN has been set.
/// Zeroized when dropped: the sealed blobs are ciphertext, but the verifier is not.
pub struct State {
    pub header: Option<Header>,
    /// Every slot of the table, empty ones as [`Record::EMPTY`].
    pub slots: [Record; MAX_ENTRIES],
}

impl State {
    #[must_use]
    #[expect(
        clippy::large_stack_arrays,
        reason = "evaluated at compile time into the board's static; the host test boxes it"
    )]
    pub const fn empty() -> State {
        State {
            header: None,
            slots: [Record::EMPTY; MAX_ENTRIES],
        }
    }

    #[must_use]
    pub fn find(&self, name: Name<'_>) -> Option<usize> {
        self.slots
            .iter()
            .position(|r| !r.is_empty() && r.name() == name)
    }

    #[must_use]
    pub fn free_slot(&self) -> Option<usize> {
        self.slots.iter().position(Record::is_empty)
    }

    /// The slots that hold something.
    pub fn used(&self) -> impl Iterator<Item = &Record> {
        self.slots.iter().filter(|r| !r.is_empty())
    }
}

/// Back to `State::empty()`, in place: no header, no slots, nothing left behind.
impl Zeroize for State {
    fn zeroize(&mut self) {
        for slot in &mut self.slots {
            *slot = Record::EMPTY; // a store the table is read after: never elided
        }
        if let Some(h) = self.header.as_mut() {
            h.salt.zeroize();
            h.verifier.zeroize();
            h.env_key.zeroize();
        }
        self.header = None;
    }
}

impl Drop for State {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// Image: magic | seq u32 | flags u8 + pad(3) | salt | m_kib u32 | t u32 | verifier |
// env_key | records | crc. Flags: bit 0 = a PIN is set, bit 1 = derived with the
// chip key. The header offsets below are the one description of that layout: the
// writer and the reader both index by them.
const FLAG_PIN: u8 = 0x01;
const FLAG_BOUND: u8 = 0x02;
const H_FLAGS: usize = 0;
const H_SALT: usize = 4;
const H_M_KIB: usize = H_SALT + SALT_LEN;
const H_T: usize = H_M_KIB + 4;
const H_VERIFIER: usize = H_T + 4;
const H_ENV_KEY: usize = H_VERIFIER + KEY_LEN;
const HDR_BYTES: usize = H_ENV_KEY + KEY_LEN + OVERHEAD;
/// Magic, sequence and header: what `save` writes before the first slot.
const HEAD: usize = 8 + HDR_BYTES;
const IMAGE: usize = HEAD + Record::SIZE * MAX_ENTRIES + 4;
const _: () = assert!(
    HEAD.is_multiple_of(4) && Record::SIZE.is_multiple_of(4),
    "images are written in whole words, one piece at a time"
);
const _: () = assert!(
    IMAGE <= (SECTOR * STATE_SECTORS) as usize,
    "an image must fit its region"
);
const _: () = assert!(
    IMAGE == 83_076,
    "layout changed: bump MAGIC, then update this number"
);

// Env slot copy: magic | seq u32 | name_len u8 + pad(3) | name[NAME_MAX] | len u16 +
// pad(2) | sealed[len] | pad to a word | crc. The CRC covers the head and the sealed
// bytes. A blank copy is all 0xFF; a copy that fails any check is as good as blank.
const ENV_MAGIC: [u8; 4] = *b"VKE1";
const ENV_HEAD: usize = 12 + NAME_MAX + 4;
const _: () = assert!(
    ENV_HEAD + ENV_BUF_LEN + 3 + 4 <= ENV_COPY as usize,
    "a sealed blob, padded, plus its CRC must fit one copy"
);

/// The address of an env copy and the head read from it.
type SlotHead = (u32, [u8; ENV_HEAD]);
/// A valid env copy: its sequence number and head.
type CopySeq = (u32, [u8; ENV_HEAD]);
/// The newest env copy of a slot: sequence number, address, head.
type Picked = (u32, u32, [u8; ENV_HEAD]);

/// A flash address `off` bytes into a region.
fn at(base: u32, off: usize) -> u32 {
    const _: () = assert!(
        IMAGE <= u32::MAX as usize && ENV_SECTORS as usize * SECTOR as usize <= u32::MAX as usize,
        "every offset into a region is cast to a flash address"
    );
    #[expect(clippy::cast_possible_truncation, reason = "asserted above")]
    {
        base + off as u32
    }
}

/// `magic | seq | name_len + pad | name | len + pad` back into (seq, name, sealed
/// length), or None if the bytes are not a head this firmware wrote.
fn env_head(h: &[u8; ENV_HEAD]) -> Option<(u32, Name<'_>, usize)> {
    if h[..4] != ENV_MAGIC {
        return None;
    }
    let seq = u32::from_le_bytes(word(&h[4..8]));
    let name_len = usize::from(h[8]);
    if name_len > NAME_MAX {
        return None;
    }
    let name = Name::new(&h[12..12 + name_len])?;
    let len = usize::from(u16::from_le_bytes([h[12 + NAME_MAX], h[13 + NAME_MAX]]));
    if !(OVERHEAD + 1..=ENV_BUF_LEN).contains(&len) {
        return None;
    }
    Some((seq, name, len))
}

pub struct Store<F: NorFlash> {
    flash: F,
    at: Layout,
    /// The newest image copy - (sequence, address) - as of the last `load` or
    /// `save`, so a write need not re-check both copies' CRCs to find its target.
    /// Only *which* copy is newer is remembered, never what it holds; `wipe` forgets.
    current: Option<(u32, u32)>,
}

impl<F: NorFlash> Store<F> {
    /// Panics at boot on a flash whose geometry this layout does not fit: a wrong
    /// board definition must fail loudly, not corrupt silently.
    pub fn new(flash: F, at: Layout) -> Self {
        assert!(
            F::ERASE_SIZE == SECTOR as usize,
            "store expects 4 KiB sectors"
        );
        assert!(
            4_usize.is_multiple_of(F::WRITE_SIZE) && 4_usize.is_multiple_of(F::READ_SIZE),
            "store reads and writes in 4-byte words"
        );
        for region in [at.attempts, at.state_a, at.state_b, at.env] {
            assert!(
                region.is_multiple_of(SECTOR),
                "regions start on sector boundaries"
            );
        }
        Store {
            flash,
            at,
            current: None,
        }
    }

    fn read(&mut self, addr: u32, buf: &mut [u8]) -> Result<(), Error<F::Error>> {
        self.flash.read(addr, buf).map_err(Error::Flash)
    }

    fn erase(&mut self, from: u32, sectors: u32) -> Result<(), Error<F::Error>> {
        self.flash
            .erase(from, from + SECTOR * sectors)
            .map_err(Error::Flash)
    }

    /// Plain write: only clears bits, never erases. Callers erase first when they
    /// need to, and never when they must not.
    fn write(&mut self, addr: u32, buf: &[u8]) -> Result<(), Error<F::Error>> {
        self.flash.write(addr, buf).map_err(Error::Flash)
    }

    // --- A/B image -------------------------------------------------------------

    /// Checks one copy. Ok(Some(seq)) if its magic and CRC check out, Ok(None) if the
    /// copy is blank, Err(Corrupt) if there is something else there.
    fn image_seq(&mut self, addr: u32) -> Result<Option<u32>, Error<F::Error>> {
        let mut head = [0u8; 8];
        self.read(addr, &mut head)?;
        if head == [0xFF; 8] {
            return Ok(None);
        }
        if head[..4] != MAGIC {
            return Err(Error::Corrupt);
        }
        let mut digest = CRC.digest();
        digest.update(&head);
        let mut chunk = [0u8; CRC_CHUNK];
        let mut off = head.len();
        while off < IMAGE - 4 {
            let n = (IMAGE - 4 - off).min(chunk.len());
            self.read(at(addr, off), &mut chunk[..n])?;
            digest.update(&chunk[..n]);
            off += n;
        }
        chunk.zeroize(); // the first chunk held the verifier
        let mut stored = [0u8; 4];
        self.read(at(addr, IMAGE - 4), &mut stored)?;
        if digest.finalize() != u32::from_le_bytes(stored) {
            return Err(Error::Corrupt);
        }
        Ok(Some(u32::from_le_bytes(word(&head[4..8]))))
    }

    /// The newest valid copy: Ok(Some((seq, address))), Ok(None) when the flash is
    /// blank, Err when it holds something this firmware cannot read.
    fn newest(&mut self) -> Result<Option<(u32, u32)>, Error<F::Error>> {
        let (a, b) = (self.at.state_a, self.at.state_b);
        let sa = self.image_seq(a);
        let sb = self.image_seq(b);
        // One damaged copy next to one good one is the expected aftermath of a power
        // cut mid-write; the good one wins. Two damaged copies are not.
        match (sa, sb) {
            (Ok(Some(x)), Ok(Some(y))) if y > x => Ok(Some((y, b))),
            (Ok(Some(x)), _) => Ok(Some((x, a))),
            (_, Ok(Some(y))) => Ok(Some((y, b))),
            (Ok(None), Ok(None)) => Ok(None),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }

    /// Whether the newer-looking copy says a PIN is set - from its first twelve bytes,
    /// no CRC. For the status line, which is asked every second: a torn image answers
    /// wrong here for exactly as long as it takes the next real operation to `load`
    /// and refuse it properly. `Ok(false)` on a blank flash.
    pub fn has_pin(&mut self) -> Result<bool, Error<F::Error>> {
        let mut best: Option<(u32, bool)> = None;
        for addr in [self.at.state_a, self.at.state_b] {
            let mut head = [0u8; 12];
            self.read(addr, &mut head)?;
            if head[..4] != MAGIC {
                continue;
            }
            let seq = u32::from_le_bytes(word(&head[4..8]));
            if best.is_none_or(|(s, _)| seq > s) {
                best = Some((seq, head[8 + H_FLAGS] & FLAG_PIN != 0));
            }
        }
        Ok(best.is_some_and(|(_, pin)| pin))
    }

    /// A header with a cost this firmware will not run is as unusable as a bad CRC:
    /// refused, not rounded down.
    fn header_of(h: &[u8; HDR_BYTES]) -> Result<Option<Header>, Error<F::Error>> {
        if h[H_FLAGS] & FLAG_PIN == 0 {
            return Ok(None);
        }
        let mut hdr = Header {
            salt: [0; SALT_LEN],
            cost: Cost::from_wire(
                u32::from_le_bytes(word(&h[H_M_KIB..H_T])),
                u32::from_le_bytes(word(&h[H_T..H_VERIFIER])),
            )
            .ok_or(Error::Corrupt)?,
            bound: h[H_FLAGS] & FLAG_BOUND != 0,
            verifier: [0; KEY_LEN],
            env_key: [0; KEY_LEN + OVERHEAD],
        };
        hdr.salt.copy_from_slice(&h[H_SALT..H_M_KIB]);
        hdr.verifier.copy_from_slice(&h[H_VERIFIER..H_ENV_KEY]);
        hdr.env_key.copy_from_slice(&h[H_ENV_KEY..]);
        Ok(Some(hdr))
    }

    /// Loads the newest copy into `out`, or leaves it empty on a blank flash. On any
    /// error `out` is empty too: half a state is not a state. Emptied in place with
    /// `zeroize`: a fresh `State` would be a 50 KiB temporary on the stack.
    pub fn load(&mut self, out: &mut State) -> Result<(), Error<F::Error>> {
        out.zeroize();
        let r = self.load_into(out);
        if r.is_err() {
            out.zeroize();
        }
        r
    }

    fn load_into(&mut self, out: &mut State) -> Result<(), Error<F::Error>> {
        self.current = self.newest()?;
        let Some((_, addr)) = self.current else {
            return Ok(());
        };
        let mut hdr = [0u8; HDR_BYTES];
        self.read(addr + 8, &mut hdr)?;
        let header = Self::header_of(&hdr);
        hdr.zeroize();
        out.header = header?;
        let mut slot_buf = [0u8; Record::SIZE];
        let r = out.slots.iter_mut().enumerate().try_for_each(|(i, slot)| {
            self.read(at(addr, HEAD + i * Record::SIZE), &mut slot_buf)?;
            *slot = Record::get(&slot_buf).unwrap_or(Record::EMPTY);
            Ok(())
        });
        slot_buf.zeroize();
        r
    }

    /// Writes the whole state to the copy that is not current. The old copy stays
    /// valid until this one is complete, so a power cut costs at most this write.
    /// Refuses to write over flash it cannot read: that needs an explicit wipe.
    pub fn save(&mut self, s: &State) -> Result<(), Error<F::Error>> {
        let current = match self.current {
            Some(c) => Some(c),
            None => self.newest()?,
        };
        let (seq, current) = current.unwrap_or((0, self.at.state_b));
        let target = if current == self.at.state_a {
            self.at.state_b
        } else {
            self.at.state_a
        };
        self.current = None; // nothing is newest until this write is whole
        self.erase(target, STATE_SECTORS)?;

        let mut head = [0u8; HEAD];
        head[..4].copy_from_slice(&MAGIC);
        head[4..8].copy_from_slice(&(seq.wrapping_add(1)).to_le_bytes());
        if let Some(hdr) = &s.header {
            let h = &mut head[8..];
            h[H_FLAGS] = FLAG_PIN | if hdr.bound { FLAG_BOUND } else { 0 };
            h[H_SALT..H_M_KIB].copy_from_slice(&hdr.salt);
            h[H_M_KIB..H_T].copy_from_slice(&hdr.cost.m_kib.to_le_bytes());
            h[H_T..H_VERIFIER].copy_from_slice(&hdr.cost.t.to_le_bytes());
            h[H_VERIFIER..H_ENV_KEY].copy_from_slice(&hdr.verifier);
            h[H_ENV_KEY..].copy_from_slice(&hdr.env_key);
        }
        let mut digest = CRC.digest();
        digest.update(&head);
        let r = self.write(target, &head);
        head.zeroize();
        r?;

        let mut slot_buf = [0u8; Record::SIZE];
        let r = s.slots.iter().enumerate().try_for_each(|(i, slot)| {
            Record::put(slot, &mut slot_buf);
            digest.update(&slot_buf);
            self.write(at(target, HEAD + i * Record::SIZE), &slot_buf)
        });
        slot_buf.zeroize();
        r?;
        self.write(at(target, IMAGE - 4), &digest.finalize().to_le_bytes())?;
        self.current = Some((seq.wrapping_add(1), target));
        Ok(())
    }

    // --- failed-attempt counter -------------------------------------------------

    /// Failed attempts since the last success: zeroed words at the start of the
    /// sector. A read error is an error, not zero attempts.
    pub fn attempts_used(&mut self) -> Result<u8, Error<F::Error>> {
        let mut words = [0u8; 4 * MAX_ATTEMPTS as usize];
        self.read(self.at.attempts, &mut words)?;
        let used = words.chunks(4).take_while(|w| *w != [0xFF; 4]).count();
        Ok(u8::try_from(used).unwrap_or(MAX_ATTEMPTS))
    }

    /// Spends one attempt: a single word goes 0xFFFFFFFF -> 0, no erase involved, so
    /// a power cut at any point cannot give the attempt back. Returns attempts used.
    pub fn spend_attempt(&mut self) -> Result<u8, Error<F::Error>> {
        let used = self.attempts_used()?;
        if used >= MAX_ATTEMPTS {
            return Ok(used);
        }
        self.write(self.at.attempts + u32::from(used) * 4, &[0, 0, 0, 0])?;
        Ok(used + 1)
    }

    pub fn reset_attempts(&mut self) -> Result<(), Error<F::Error>> {
        self.erase(self.at.attempts, 1)
    }

    /// Everything gone: both state copies, the attempt counter and every env blob.
    /// Every region is tried even if one fails; the first failure is what comes back.
    pub fn wipe(&mut self) -> Result<(), Error<F::Error>> {
        self.current = None;
        let mut first = Ok(());
        for (from, sectors) in [
            (self.at.state_a, STATE_SECTORS),
            (self.at.state_b, STATE_SECTORS),
            (self.at.attempts, 1),
            (self.at.env, ENV_SECTORS),
        ] {
            if let Err(e) = self.erase(from, sectors) {
                first = first.and(Err(e));
            }
        }
        first
    }

    // --- env blobs -----------------------------------------------------------------

    fn env_copy(&self, slot: usize, copy: usize) -> u32 {
        at(self.at.env, (slot * 2 + copy) * ENV_COPY as usize)
    }

    /// One copy of a slot: Ok(Some(seq)) when its head and CRC check out, Ok(None)
    /// when it is blank or damaged - a torn write of a new blob has no older copy to
    /// fall back to and must read as a free slot, not lock the key the way a torn
    /// image does - and Err only when the flash driver fails. The CRC is checked here,
    /// while choosing, so a torn newer copy loses to an intact older one.
    fn env_copy_seq(&mut self, addr: u32) -> Result<Option<CopySeq>, Error<F::Error>> {
        let mut head = [0u8; ENV_HEAD];
        self.read(addr, &mut head)?;
        let Some((seq, _, len)) = env_head(&head) else {
            return Ok(None);
        };
        // Reads are whole words (the flash driver insists), the CRC covers the
        // exact sealed length: the last chunk is read padded and digested short.
        let padded = len.next_multiple_of(4);
        let mut digest = CRC.digest();
        digest.update(&head);
        let mut chunk = [0u8; CRC_CHUNK];
        let mut off = 0;
        while off < padded {
            let n = (padded - off).min(chunk.len());
            self.read(at(addr, ENV_HEAD + off), &mut chunk[..n])?;
            digest.update(&chunk[..n.min(len - off)]);
            off += n;
        }
        let mut stored = [0u8; 4];
        self.read(at(addr, ENV_HEAD + padded), &mut stored)?;
        Ok((digest.finalize() == u32::from_le_bytes(stored)).then_some((seq, head)))
    }

    /// The newest valid copy of a slot: (seq, address, head), or None for a free slot.
    fn env_pick(&mut self, slot: usize) -> Result<Option<Picked>, Error<F::Error>> {
        let (a, b) = (self.env_copy(slot, 0), self.env_copy(slot, 1));
        let sa = self.env_copy_seq(a)?;
        let sb = self.env_copy_seq(b)?;
        Ok(match (sa, sb) {
            (Some((x, _)), Some((y, hb))) if y > x => Some((y, b, hb)),
            (Some((x, ha)), _) => Some((x, a, ha)),
            (None, Some((y, hb))) => Some((y, b, hb)),
            (None, None) => None,
        })
    }

    fn env_newest(&mut self, slot: usize) -> Result<Option<(u32, u32)>, Error<F::Error>> {
        Ok(self.env_pick(slot)?.map(|(seq, addr, _)| (seq, addr)))
    }

    /// The newest copy's address and head, or None for a free slot.
    fn env_slot(&mut self, slot: usize) -> Result<Option<SlotHead>, Error<F::Error>> {
        Ok(self.env_pick(slot)?.map(|(_, addr, head)| (addr, head)))
    }

    /// The slot holding the blob called `name`.
    pub fn env_find(&mut self, name: Name<'_>) -> Result<Option<usize>, Error<F::Error>> {
        for slot in 0..ENV_SLOTS {
            if let Some((_, head)) = self.env_slot(slot)?
                && env_head(&head).is_some_and(|(_, n, _)| n == name)
            {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// A slot with no blob in it.
    pub fn env_free(&mut self) -> Result<Option<usize>, Error<F::Error>> {
        for slot in 0..ENV_SLOTS {
            if self.env_newest(slot)?.is_none() {
                return Ok(Some(slot));
            }
        }
        Ok(None)
    }

    /// The name of every stored blob.
    pub fn env_names(&mut self, mut each: impl FnMut(Name<'_>)) -> Result<(), Error<F::Error>> {
        for slot in 0..ENV_SLOTS {
            if let Some((_, head)) = self.env_slot(slot)?
                && let Some((_, name, _)) = env_head(&head)
            {
                each(name);
            }
        }
        Ok(())
    }

    /// The sealed blob in `slot` into `buf`; its length and name, or None for a free
    /// slot.
    pub fn env_read(
        &mut self,
        slot: usize,
        buf: &mut [u8; ENV_BUF_LEN],
    ) -> Result<Option<(usize, StoredName)>, Error<F::Error>> {
        let Some((addr, head)) = self.env_slot(slot)? else {
            return Ok(None);
        };
        let Some((_, name, len)) = env_head(&head) else {
            return Ok(None);
        };
        // Whole words, as the driver insists; the padding is zero and fits `buf`.
        self.read(at(addr, ENV_HEAD), &mut buf[..len.next_multiple_of(4)])?;
        Ok(Some((len, StoredName::of(name))))
    }

    /// Writes `buf[..len]` - a sealed blob, `OVERHEAD + 1..=ENV_BUF_LEN` bytes, the
    /// rest of `buf` zero - as `name` into the copy of `slot` that is not current.
    /// The old copy stays valid until this one's CRC lands.
    pub fn env_write(
        &mut self,
        slot: usize,
        name: Name<'_>,
        buf: &[u8; ENV_BUF_LEN],
        len: usize,
    ) -> Result<(), Error<F::Error>> {
        let (seq, target) = match self.env_newest(slot)? {
            Some((seq, addr)) if addr == self.env_copy(slot, 0) => (seq, self.env_copy(slot, 1)),
            Some((seq, _)) => (seq, self.env_copy(slot, 0)),
            None => (0, self.env_copy(slot, 0)),
        };
        self.erase(target, ENV_COPY_SECTORS)?;

        let mut head = [0u8; ENV_HEAD];
        head[..4].copy_from_slice(&ENV_MAGIC);
        head[4..8].copy_from_slice(&seq.wrapping_add(1).to_le_bytes());
        head[8] = len_u8(name.as_bytes().len());
        head[12..12 + name.as_bytes().len()].copy_from_slice(name.as_bytes());
        head[12 + NAME_MAX..14 + NAME_MAX].copy_from_slice(&len_u16(len).to_le_bytes());
        let mut digest = CRC.digest();
        digest.update(&head);
        digest.update(&buf[..len]);

        self.write(target, &head)?;
        let padded = len.next_multiple_of(4);
        self.write(at(target, ENV_HEAD), &buf[..padded])?;
        self.write(
            at(target, ENV_HEAD + padded),
            &digest.finalize().to_le_bytes(),
        )
    }

    /// Both copies of a slot gone, the newest first: the other way round, a power cut
    /// between the two erases would leave the older version as the newest valid copy.
    /// This way it comes back at most once, and the next delete finishes the job.
    pub fn env_delete(&mut self, slot: usize) -> Result<(), Error<F::Error>> {
        let (a, b) = (self.env_copy(slot, 0), self.env_copy(slot, 1));
        let order = match self.env_newest(slot)? {
            Some((_, addr)) if addr == b => [b, a],
            _ => [a, b],
        };
        for copy in order {
            self.erase(copy, ENV_COPY_SECTORS)?;
        }
        Ok(())
    }
}

/// Four bytes out of a slice that is known to hold them.
fn word(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}
